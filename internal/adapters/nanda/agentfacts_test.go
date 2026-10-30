package nanda

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalizeMatchesECMAScriptJSON(t *testing.T) {
	document, err := decodeGeneric([]byte(`{
		"b": [3, 1.5, -0, 1e21, 1e20, 0.000001, 1e-7, 1.2345e-7, 255, 12345678901234567890],
		"a": {"z": true, "y": null, "x": "q\"<>& \u0001\n\\"},
		"A": "upper sorts first"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Canonicalize(document)
	if err != nil {
		t.Fatal(err)
	}
	// Expected bytes are what JSON.stringify-based canonicalize() in
	// nanda-index-v2 produces for the same input.
	want := `{"A":"upper sorts first","a":{"x":"q\"<>&` + " " + `\u0001\n\\","y":null,"z":true},` +
		`"b":[3,1.5,0,1e+21,100000000000000000000,0.000001,1e-7,1.2345e-7,255,12345678901234567000]}`
	if string(got) != want {
		t.Fatalf("canonical JSON mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestCanonicalizeRejectsNonJSONValues(t *testing.T) {
	if _, err := Canonicalize(map[string]any{"bad": 1.5}); err == nil {
		t.Fatal("expected an error for a raw float64 (values must be json.Number)")
	}
	if _, err := Canonicalize(map[string]any{"bad": string([]byte{0xff})}); err == nil {
		t.Fatal("expected an error for invalid UTF-8")
	}
}

func TestDIDKeyRoundTrip(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	did := DIDKey(public)
	// Every Ed25519 did:key starts with z6Mk because of the 0xed01 prefix.
	if !strings.HasPrefix(did, "did:key:z6Mk") {
		t.Fatalf("unexpected did:key prefix: %s", did)
	}
	parsed, err := ParseDIDKey(did)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed, public) {
		t.Fatal("did:key did not round-trip")
	}
	for _, bad := range []string{"did:key:", "did:web:example.org", "did:key:z0OIl", "did:key:z" + strings.Repeat("1", 40)} {
		if _, err := ParseDIDKey(bad); err == nil {
			t.Fatalf("ParseDIDKey(%q) succeeded", bad)
		}
	}
}

func testFacts() Facts {
	modes := []string{"application/json"}
	return Facts{
		ID: "urn:air:aegis.test:agent:investigator", AgentName: "AegisSRE Investigator", Label: "AegisSRE Investigator",
		Description: "Builds evidence-driven diagnoses", Version: "0.1.0",
		Provider:     Provider{Name: "AegisSRE", URL: "https://github.com/shanurwan/AegisSRE"},
		Endpoints:    Endpoints{Static: []string{"http://investigator.aegis.test/a2a"}},
		Capabilities: Capabilities{Modalities: modes, Authentication: Authentication{Methods: []string{"none"}}},
		Skills:       []Skill{{ID: "investigate-incident", Description: "Diagnose", InputModes: modes, OutputModes: modes}},
	}
}

func TestSignedAgentFactsVerifyOnlyAgainstThePinnedKey(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	attackerPublic, attackerPrivate, _ := ed25519.GenerateKey(rand.Reader)
	signed, err := Sign(testFacts(), private)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := Verify(signed, public)
	if err != nil {
		t.Fatalf("valid AgentFacts rejected: %v", err)
	}
	if facts.Provider.DID != DIDKey(public) || !facts.HasSkill("investigate-incident") {
		t.Fatalf("unexpected verified document: %+v", facts)
	}

	// A self-consistent document from another key proves nothing.
	forged, err := Sign(testFacts(), attackerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(forged, public); err == nil {
		t.Fatal("AgentFacts signed by an unpinned key was accepted")
	}
	if _, err := Verify(signed, attackerPublic); err == nil {
		t.Fatal("AgentFacts verified against the wrong pinned key")
	}
}

func TestTamperedAgentFactsAreRejected(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	signed, err := Sign(testFacts(), private)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(map[string]any){
		"endpoint redirected": func(d map[string]any) {
			d["endpoints"] = map[string]any{"static": []any{"https://attacker.example/a2a"}}
		},
		"skill added": func(d map[string]any) {
			skills := d["skills"].([]any)
			d["skills"] = append(skills, map[string]any{"id": "operate-remediation", "description": "x", "inputModes": []any{"a"}, "outputModes": []any{"a"}})
		},
		"signature removed":    func(d map[string]any) { delete(d, "signature_value") },
		"algorithm changed":    func(d map[string]any) { d["signature_algorithm"] = "none" },
		"unsigned field added": func(d map[string]any) { d["jurisdiction"] = "XX" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			document, err := decodeGeneric(signed)
			if err != nil {
				t.Fatal(err)
			}
			mutate(document)
			tampered, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(tampered, public); err == nil {
				t.Fatal("tampered AgentFacts verified")
			}
		})
	}
}

func TestSignRejectsIncompleteAgentFacts(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	facts := testFacts()
	facts.Skills = nil
	if _, err := Sign(facts, private); err == nil {
		t.Fatal("AgentFacts without skills was signed")
	}
}

func TestPublisherDomain(t *testing.T) {
	domain, err := PublisherDomain("urn:air:aegis.example.org:agent:investigator")
	if err != nil || domain != "aegis.example.org" {
		t.Fatalf("got %q, %v", domain, err)
	}
	for _, bad := range []string{"urn:air:localhost:agent:x", "urn:ai:aegis.test:agent:x", "urn:air:aegis.test:x", "urn:air:AEGIS.test:agent:x"} {
		if _, err := PublisherDomain(bad); err == nil {
			t.Fatalf("PublisherDomain(%q) succeeded", bad)
		}
	}
}
