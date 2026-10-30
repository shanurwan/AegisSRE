package nanda

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
)

const (
	testURN     = "urn:air:aegis.test:agent:investigator"
	testSkill   = "investigate-incident"
	testBase    = "http://investigator.aegis.test"
	testCardURL = testBase + "/.well-known/agent-card.json"
)

// world is a fake NANDA Index plus one peer agent. Every hostname dials the
// same test server, which routes on the Host header.
type world struct {
	t          *testing.T
	server     *httptest.Server
	indexHits  atomic.Int32
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey

	entry      map[string]any
	card       map[string]any
	facts      []byte
	cardStatus int
	redirect   bool
}

func newWorld(t *testing.T) *world {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, publicKey: public, privateKey: private, cardStatus: http.StatusOK}
	w.entry = map[string]any{
		"locator": testURN, "identifier": "investigator", "match": "exact",
		"entry": map[string]any{
			"identifier": testURN, "type": A2ACardMediaType, "url": testCardURL,
			"extensions": map[string]any{nandaExtension: map[string]any{
				"status": "active", "domain": "aegis.test", "domainVerified": true,
			}},
		},
	}
	w.card = map[string]any{
		"name": "AegisSRE Investigator", "description": "Diagnoses", "version": "0.1.0",
		"supportedInterfaces": []any{map[string]any{"url": testBase + "/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}},
		"capabilities":        map[string]any{},
		"defaultInputModes":   []any{"application/json"}, "defaultOutputModes": []any{"application/json"},
		"skills": []any{map[string]any{"id": testSkill, "name": "Investigate", "description": "Diagnose", "tags": []any{"sre"}}},
	}
	w.signFacts(testFacts(), private)
	w.server = httptest.NewServer(http.HandlerFunc(w.serve))
	t.Cleanup(w.server.Close)
	return w
}

func (w *world) signFacts(facts Facts, key ed25519.PrivateKey) {
	signed, err := Sign(facts, key)
	if err != nil {
		w.t.Fatal(err)
	}
	w.facts = signed
}

func (w *world) serve(writer http.ResponseWriter, request *http.Request) {
	host := request.Host
	switch {
	case host == "index.nanda.test" && request.URL.Path == "/api/v1/resolve":
		w.indexHits.Add(1)
		if request.URL.Query().Get("locator") != testURN {
			http.NotFound(writer, request)
			return
		}
		_ = json.NewEncoder(writer).Encode(w.entry)
	case host == "investigator.aegis.test" && request.URL.Path == "/.well-known/agent-card.json":
		if w.redirect {
			http.Redirect(writer, request, "http://attacker.example/card.json", http.StatusFound)
			return
		}
		writer.WriteHeader(w.cardStatus)
		_ = json.NewEncoder(writer).Encode(w.card)
	case host == "investigator.aegis.test" && request.URL.Path == FactsPath:
		_, _ = writer.Write(w.facts)
	default:
		http.NotFound(writer, request)
	}
}

func (w *world) client() *http.Client {
	address := w.server.Listener.Addr().String()
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func (w *world) resolver() *Resolver {
	client := w.client()
	return &Resolver{
		Index:      IndexClient{BaseURL: "http://index.nanda.test", HTTPClient: client},
		Peers:      map[model.AgentID]Peer{model.AgentInvestigator: {ID: testURN, Key: w.publicKey, Skill: testSkill}},
		PeerClient: func(model.AgentID) *http.Client { return client },
		AllowHTTP:  true,
		TTL:        time.Minute,
	}
}

func entryField(w *world, key string, value any) {
	w.entry["entry"].(map[string]any)[key] = value
}

func extensionField(w *world, key string, value any) {
	entry := w.entry["entry"].(map[string]any)
	entry["extensions"].(map[string]any)[nandaExtension].(map[string]any)[key] = value
}

func TestResolverReturnsVerifiedEndpoint(t *testing.T) {
	w := newWorld(t)
	endpoint, err := w.resolver().Resolve(context.Background(), model.AgentInvestigator)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != testBase {
		t.Fatalf("endpoint = %q, want %q", endpoint, testBase)
	}
}

func TestResolverRejectsUntrustworthyPeers(t *testing.T) {
	cases := map[string]func(*world){
		"publisher-level match": func(w *world) { w.entry["match"] = "publisher" },
		"entry is not an agent card": func(w *world) {
			entryField(w, "type", "application/ai-catalog+json")
		},
		"entry suspended":     func(w *world) { extensionField(w, "status", "suspended") },
		"domain not verified": func(w *world) { extensionField(w, "domainVerified", false) },
		"card outside domain": func(w *world) { entryField(w, "url", "http://aegis.test.attacker.example/.well-known/agent-card.json") },
		"card URL not a card": func(w *world) { entryField(w, "url", testBase+"/card.json") },
		"card redirects":      func(w *world) { w.redirect = true },
		"card unavailable":    func(w *world) { w.cardStatus = http.StatusServiceUnavailable },
		"card lacks the skill": func(w *world) {
			w.card["skills"] = []any{map[string]any{"id": "something-else", "name": "x", "description": "x", "tags": []any{"x"}}}
		},
		"card points elsewhere": func(w *world) {
			w.card["supportedInterfaces"] = []any{map[string]any{"url": "https://attacker.example/a2a", "protocolBinding": "JSONRPC"}}
		},
		"facts signed by another key": func(w *world) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			w.signFacts(testFacts(), other)
		},
		"facts for another identity": func(w *world) {
			facts := testFacts()
			facts.ID = "urn:air:aegis.test:agent:someone-else"
			w.signFacts(facts, w.privateKey)
		},
		"facts lack the skill": func(w *world) {
			facts := testFacts()
			facts.Skills[0].ID = "something-else"
			w.signFacts(facts, w.privateKey)
		},
		"facts name another endpoint": func(w *world) {
			facts := testFacts()
			facts.Endpoints.Static = []string{"https://attacker.example/a2a"}
			w.signFacts(facts, w.privateKey)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			mutate(w)
			if endpoint, err := w.resolver().Resolve(context.Background(), model.AgentInvestigator); err == nil {
				t.Fatalf("untrustworthy peer resolved to %q", endpoint)
			}
		})
	}
}

func TestResolverRefusesPlaintextUnlessAllowed(t *testing.T) {
	w := newWorld(t)
	resolver := w.resolver()
	resolver.AllowHTTP = false
	if _, err := resolver.Resolve(context.Background(), model.AgentInvestigator); err == nil ||
		!strings.Contains(err.Error(), "scheme") {
		t.Fatalf("plaintext Agent Card accepted: %v", err)
	}
}

func TestResolverRejectsUnconfiguredPeer(t *testing.T) {
	w := newWorld(t)
	if _, err := w.resolver().Resolve(context.Background(), model.AgentOperator); err == nil {
		t.Fatal("peer without a pinned NANDA identity resolved")
	}
}

func TestResolverCachesUntilTTLAndForget(t *testing.T) {
	w := newWorld(t)
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	resolver := w.resolver()
	resolver.Now = func() time.Time { return now }
	ctx := context.Background()
	for range 3 {
		if _, err := resolver.Resolve(ctx, model.AgentInvestigator); err != nil {
			t.Fatal(err)
		}
	}
	if hits := w.indexHits.Load(); hits != 1 {
		t.Fatalf("index queried %d times within the TTL, want 1", hits)
	}
	now = now.Add(2 * time.Minute)
	if _, err := resolver.Resolve(ctx, model.AgentInvestigator); err != nil {
		t.Fatal(err)
	}
	resolver.Forget(model.AgentInvestigator)
	if _, err := resolver.Resolve(ctx, model.AgentInvestigator); err != nil {
		t.Fatal(err)
	}
	if hits := w.indexHits.Load(); hits != 3 {
		t.Fatalf("index queried %d times, want 3 after expiry and Forget", hits)
	}
}

func TestResolverStopsTrustingAPeerThatChanges(t *testing.T) {
	w := newWorld(t)
	resolver := w.resolver()
	ctx := context.Background()
	if _, err := resolver.Resolve(ctx, model.AgentInvestigator); err != nil {
		t.Fatal(err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	w.signFacts(testFacts(), other)
	resolver.Forget(model.AgentInvestigator)
	if _, err := resolver.Resolve(ctx, model.AgentInvestigator); err == nil {
		t.Fatal("peer that rotated to an unpinned key was still trusted")
	}
}
