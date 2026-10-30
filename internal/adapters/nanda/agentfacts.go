package nanda

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// FactsPath is where every AegisSRE agent serves its AgentFacts, beside the
// A2A Agent Card. The NANDA concierge demo reads the same path.
const FactsPath = "/agentfacts.json"

// SignatureAlgorithm names the only accepted AgentFacts signature scheme.
const SignatureAlgorithm = "ed25519"

// Facts is an AgentFacts document in the agentfacts-format v1 layout
// (https://agentfacts.org/schema/v1). The schema has no signature, so AegisSRE
// adds two top-level fields following the NANDA Index signing recipe: the
// signature covers the canonical JSON of every field except signature_value,
// and the signing key is the did:key in provider.did.
type Facts struct {
	ID                 string       `json:"id"`
	AgentName          string       `json:"agent_name"`
	Label              string       `json:"label"`
	Description        string       `json:"description"`
	Version            string       `json:"version"`
	DocumentationURL   string       `json:"documentationUrl,omitempty"`
	Provider           Provider     `json:"provider"`
	Endpoints          Endpoints    `json:"endpoints"`
	Capabilities       Capabilities `json:"capabilities"`
	Skills             []Skill      `json:"skills"`
	SignatureAlgorithm string       `json:"signature_algorithm"`
	SignatureValue     string       `json:"signature_value,omitempty"`
}

type Provider struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	DID  string `json:"did,omitempty"`
}

type Endpoints struct {
	Static []string `json:"static"`
}

type Capabilities struct {
	Modalities     []string       `json:"modalities"`
	Streaming      bool           `json:"streaming"`
	Authentication Authentication `json:"authentication"`
}

type Authentication struct {
	Methods []string `json:"methods"`
}

type Skill struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	InputModes  []string `json:"inputModes"`
	OutputModes []string `json:"outputModes"`
}

// Validate checks the agentfacts-format v1 required fields.
func (f Facts) Validate() error {
	required := map[string]string{
		"id": f.ID, "agent_name": f.AgentName, "label": f.Label, "description": f.Description,
		"version": f.Version, "provider.name": f.Provider.Name, "provider.url": f.Provider.URL,
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("AgentFacts %s is required", name)
		}
	}
	if len(f.Endpoints.Static) == 0 || len(f.Capabilities.Modalities) == 0 || len(f.Capabilities.Authentication.Methods) == 0 {
		return errors.New("AgentFacts endpoints, modalities and authentication methods are required")
	}
	if len(f.Skills) == 0 {
		return errors.New("AgentFacts needs at least one skill")
	}
	for _, skill := range f.Skills {
		if skill.ID == "" || skill.Description == "" || len(skill.InputModes) == 0 || len(skill.OutputModes) == 0 {
			return fmt.Errorf("AgentFacts skill %q is incomplete", skill.ID)
		}
	}
	return nil
}

// HasSkill reports whether the document advertises the skill ID.
func (f Facts) HasSkill(id string) bool {
	for _, skill := range f.Skills {
		if skill.ID == id {
			return true
		}
	}
	return false
}

// Sign binds the document to key: it sets provider.did to the key's did:key,
// signs the canonical form and returns the canonical signed document.
func Sign(facts Facts, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("AgentFacts signing key must be an Ed25519 private key")
	}
	facts.Provider.DID = DIDKey(key.Public().(ed25519.PublicKey))
	facts.SignatureAlgorithm = SignatureAlgorithm
	facts.SignatureValue = ""
	if err := facts.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(facts)
	if err != nil {
		return nil, fmt.Errorf("encode AgentFacts: %w", err)
	}
	document, err := decodeGeneric(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode AgentFacts: %w", err)
	}
	payload, err := Canonicalize(document)
	if err != nil {
		return nil, err
	}
	document["signature_value"] = base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))
	return Canonicalize(document)
}

// Verify checks that data is AgentFacts signed by exactly the pinned key and
// returns the decoded document. A did:key that verifies its own signature
// proves nothing by itself; trust comes from pinning the expected key.
func Verify(data []byte, pinned ed25519.PublicKey) (Facts, error) {
	if len(pinned) != ed25519.PublicKeySize {
		return Facts{}, errors.New("a pinned Ed25519 AgentFacts key is required")
	}
	document, err := decodeGeneric(data)
	if err != nil {
		return Facts{}, fmt.Errorf("decode AgentFacts: %w", err)
	}
	signature, _ := document["signature_value"].(string)
	if signature == "" {
		return Facts{}, errors.New("AgentFacts is not signed")
	}
	delete(document, "signature_value")
	if algorithm, _ := document["signature_algorithm"].(string); algorithm != SignatureAlgorithm {
		return Facts{}, fmt.Errorf("AgentFacts signature algorithm %q is not %s", algorithm, SignatureAlgorithm)
	}
	var facts Facts
	if err := json.Unmarshal(data, &facts); err != nil {
		return Facts{}, fmt.Errorf("decode AgentFacts: %w", err)
	}
	signer, err := ParseDIDKey(facts.Provider.DID)
	if err != nil {
		return Facts{}, fmt.Errorf("AgentFacts provider.did: %w", err)
	}
	if !bytes.Equal(signer, pinned) {
		return Facts{}, errors.New("AgentFacts is signed by a key other than the pinned key")
	}
	rawSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(rawSignature) != ed25519.SignatureSize {
		return Facts{}, errors.New("AgentFacts signature_value is not a base64 Ed25519 signature")
	}
	payload, err := Canonicalize(document)
	if err != nil {
		return Facts{}, err
	}
	if !ed25519.Verify(pinned, payload, rawSignature) {
		return Facts{}, errors.New("AgentFacts signature does not verify")
	}
	if err := facts.Validate(); err != nil {
		return Facts{}, err
	}
	return facts, nil
}
