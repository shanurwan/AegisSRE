package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shanurwan/AegisSRE/internal/adapters/discovery"
	"github.com/shanurwan/AegisSRE/internal/adapters/fixture"
	"github.com/shanurwan/AegisSRE/internal/adapters/nanda"
	"github.com/shanurwan/AegisSRE/internal/app/investigator"
	"github.com/shanurwan/AegisSRE/internal/app/monitor"
	"github.com/shanurwan/AegisSRE/internal/app/operator"
	"github.com/shanurwan/AegisSRE/internal/core/model"
	runtimeadapter "github.com/shanurwan/AegisSRE/internal/platform/runtime"
	"github.com/shanurwan/AegisSRE/internal/security"
	a2atransport "github.com/shanurwan/AegisSRE/internal/transport/a2a"
	mcptransport "github.com/shanurwan/AegisSRE/internal/transport/mcp"
)

const (
	nandaDomain          = "aegis.test"
	investigatorURN      = "urn:air:aegis.test:agent:investigator"
	operatorURN          = "urn:air:aegis.test:agent:operator"
	investigatorSkillID  = "investigate-incident"
	operatorSkillID      = "operate-remediation"
	investigatorHostname = "investigator.aegis.test"
	operatorHostname     = "operator.aegis.test"
	indexHostname        = "index.nanda.test"
)

// nandaNetwork routes virtual hostnames to in-process test servers, so the
// agents keep the public URLs they publish in their Agent Cards and AgentFacts.
type nandaNetwork struct {
	routes map[string]string
}

func (n *nandaNetwork) client() *http.Client {
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		target, ok := n.routes[host]
		if !ok {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

// startNANDAIndex serves GET /api/v1/resolve in the response shape of
// nanda-index-v2 (routes/resolve.ts and toIndexEntry in
// db/queries/organizations.ts) for verified, active A2A Agent Card entries.
func startNANDAIndex(t *testing.T, cards map[string]string, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/resolve" {
			http.NotFound(writer, request)
			return
		}
		hits.Add(1)
		locator := request.URL.Query().Get("locator")
		cardURL, ok := cards[locator]
		if !ok {
			writer.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(writer).Encode(map[string]string{"error": "not_found"})
			return
		}
		short := locator[strings.LastIndex(locator, ":")+1:]
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"locator": locator, "identifier": short, "match": "exact",
			"entry": map[string]any{
				"identifier": locator, "displayName": "AegisSRE " + short, "type": nanda.A2ACardMediaType,
				"url": cardURL, "tags": []string{"sre"}, "updatedAt": "2026-10-30T00:00:00.000Z",
				"extensions": map[string]any{"org.projectnanda": map[string]any{
					"orgId": "aegissre-" + short, "status": "active", "ttlSeconds": 86400,
					"emailVerified": true, "domainVerified": true, "domain": nandaDomain,
				}},
			},
		})
	}))
	t.Cleanup(server.Close)
	return server
}

// startPublishedAgent serves an A2A agent at a virtual public URL with a
// signed AgentFacts document, the way `aegissre investigator|operator` does
// when AEGIS_AGENTFACTS_ID is configured.
func startPublishedAgent(t *testing.T, hostname, urn, skill string, key ed25519.PrivateKey, handler a2atransport.Handler) *httptest.Server {
	t.Helper()
	publicURL := "http://" + hostname
	modes := []string{"application/json"}
	facts, err := nanda.Sign(nanda.Facts{
		ID: urn, AgentName: hostname, Label: hostname, Description: hostname + " integration service", Version: "0.1.0",
		Provider:     nanda.Provider{Name: "AegisSRE", URL: "https://github.com/shanurwan/AegisSRE"},
		Endpoints:    nanda.Endpoints{Static: []string{publicURL + "/a2a"}},
		Capabilities: nanda.Capabilities{Modalities: modes, Authentication: nanda.Authentication{Methods: []string{"none"}}},
		Skills:       []nanda.Skill{{ID: skill, Description: skill, InputModes: modes, OutputModes: modes}},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	application, _, err := a2atransport.NewHandler(a2atransport.CardConfig{
		Name: hostname, Description: hostname + " integration service", PublicURL: publicURL,
		SkillID: skill, SkillName: skill, AgentFacts: facts,
	}, handler)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(application)
	t.Cleanup(server.Close)
	return server
}

type nandaTopology struct {
	monitor          *monitor.Service
	indexHits        *atomic.Int32
	investigatorHits *atomic.Int32
	operatorHits     *atomic.Int32
}

// newNANDATopology wires the fixture incident flow with Monitor discovering
// both peers through the NANDA Index. operatorSigner lets a test publish the
// Operator's AgentFacts under a key other than the one Monitor pins.
func newNANDATopology(t *testing.T, ctx context.Context, operatorSigner func(pinned ed25519.PrivateKey) ed25519.PrivateKey) nandaTopology {
	t.Helper()
	fixturePath := filepath.Join("..", "..", "testdata", "fixtures", "unavailable-deployment.json")
	clock, ids := runtimeadapter.Clock{}, runtimeadapter.IDs{}
	observeFixture, err := fixture.Load(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	readClient := startMCPClient(t, ctx, "nanda-read-client", mcptransport.HTTPHandler(mcptransport.NewReadServer(observeFixture)))

	grantPublic, grantPrivate, _ := ed25519.GenerateKey(rand.Reader)
	const keyID = "nanda-integration-key"
	signer, err := security.NewSigner(grantPrivate, keyID)
	if err != nil {
		t.Fatal(err)
	}
	operatorVerifier, err := security.NewVerifier(grantPublic, keyID, model.AgentOperator)
	if err != nil {
		t.Fatal(err)
	}
	actionVerifier, err := security.NewVerifier(grantPublic, keyID, model.AgentMCPAction)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := security.NewPolicy(security.PolicyConfig{
		AllowedNamespaces: []string{"outage-arena"},
		AllowedActions:    []model.ActionKind{model.ActionRestartDeployment, model.ActionScaleDeployment},
		MinimumConfidence: 0.8, MinimumEvidence: 1, MaximumGrantTTL: 2 * time.Minute, RequireDryRun: true,
		MaximumReplicas: 20, MaximumReplicaIncrease: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	actionFixture, err := fixture.Load(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	actionFixture.Verifier, actionFixture.Policy = actionVerifier, policy
	actionFixture.Replay, actionFixture.Clock, actionFixture.IDs = security.NewMemoryReplayGuard(), clock, ids
	actionClient := startMCPClient(t, ctx, "nanda-action-client", mcptransport.HTTPHandler(mcptransport.NewActionServer(actionFixture)))

	investigatorPublic, investigatorPrivate, _ := ed25519.GenerateKey(rand.Reader)
	operatorPublic, operatorPrivate, _ := ed25519.GenerateKey(rand.Reader)
	topology := nandaTopology{indexHits: &atomic.Int32{}, investigatorHits: &atomic.Int32{}, operatorHits: &atomic.Int32{}}

	investigatorService := &investigator.Service{
		Tools: readClient, Reasoner: investigator.HeuristicReasoner{Clock: clock, IDs: ids},
		Clock: clock, IDs: ids, MaxLogBytes: 32768,
	}
	investigatorServer := startPublishedAgent(t, investigatorHostname, investigatorURN, investigatorSkillID, investigatorPrivate,
		func(ctx context.Context, envelope model.Envelope) (model.Envelope, error) {
			topology.investigatorHits.Add(1)
			return investigatorService.Handle(ctx, envelope)
		})
	operatorService := &operator.Service{
		Tools: actionClient, Verifier: operatorVerifier, ReportVerifier: operatorVerifier, Policy: policy,
		Replay: security.NewMemoryReplayGuard(), Clock: clock, IDs: ids,
	}
	operatorServer := startPublishedAgent(t, operatorHostname, operatorURN, operatorSkillID, operatorSigner(operatorPrivate),
		func(ctx context.Context, envelope model.Envelope) (model.Envelope, error) {
			topology.operatorHits.Add(1)
			return operatorService.Handle(ctx, envelope)
		})
	index := startNANDAIndex(t, map[string]string{
		investigatorURN: "http://" + investigatorHostname + "/.well-known/agent-card.json",
		operatorURN:     "http://" + operatorHostname + "/.well-known/agent-card.json",
	}, topology.indexHits)

	network := &nandaNetwork{routes: map[string]string{
		investigatorHostname: investigatorServer.Listener.Addr().String(),
		operatorHostname:     operatorServer.Listener.Addr().String(),
		indexHostname:        index.Listener.Addr().String(),
	}}
	client := network.client()
	a2aClient := a2atransport.NewClient(5 * time.Second)
	a2aClient.HTTPClient = client
	resolver := &nanda.Resolver{
		Index: nanda.IndexClient{BaseURL: "http://" + indexHostname, HTTPClient: client},
		Peers: map[model.AgentID]nanda.Peer{
			model.AgentInvestigator: {ID: investigatorURN, Key: investigatorPublic, Skill: investigatorSkillID},
			model.AgentOperator:     {ID: operatorURN, Key: operatorPublic, Skill: operatorSkillID},
		},
		PeerClient: func(model.AgentID) *http.Client { return client },
		AllowHTTP:  true,
		TTL:        time.Minute,
	}
	topology.monitor = &monitor.Service{
		Tools: readClient, Peers: discovery.Messenger{Resolver: resolver, Next: a2aClient},
		Signer: signer, ReportSigner: signer, Policy: policy, Clock: clock, IDs: ids,
		// Static addresses are deliberately unusable: every hop must come
		// from the NANDA Index.
		Namespace: "outage-arena", InvestigatorURL: "http://static.invalid", OperatorURL: "http://static.invalid",
		Rules: monitor.DefaultRules(), VerificationCount: 2, Cooldown: time.Minute,
		DelegationTTL: 2 * time.Minute, RequestTimeout: 5 * time.Second, EvidenceBudget: 6, DryRun: true,
	}
	return topology
}

func TestE2EMonitorDiscoversVerifiedPeersThroughNANDAIndex(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	topology := newNANDATopology(t, ctx, func(pinned ed25519.PrivateKey) ed25519.PrivateKey { return pinned })

	if _, err := topology.monitor.Scan(ctx, monitor.ScanRequest{}); err != nil {
		t.Fatal(err)
	}
	second, err := topology.monitor.Scan(ctx, monitor.ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Outcomes) != 1 {
		t.Fatalf("verified incident did not produce one outcome: %#v", second)
	}
	outcome := second.Outcomes[0]
	if outcome.Diagnosis == nil || outcome.Grant == nil || outcome.Receipt == nil || !outcome.Receipt.DryRun {
		t.Fatalf("discovered peers did not complete diagnosis, delegation and dry-run action: %#v", outcome)
	}
	if outcome.Report == nil || outcome.Report.Report.Reason != model.ReportReasonDryRunCompleted {
		t.Fatalf("Operator found through NANDA did not produce the terminal report: %#v", outcome.Report)
	}
	if topology.investigatorHits.Load() == 0 || topology.operatorHits.Load() == 0 {
		t.Fatal("a peer was never reached through its discovered endpoint")
	}
	// One resolution per peer; later messages reuse the verified endpoint.
	if hits := topology.indexHits.Load(); hits != 2 {
		t.Fatalf("NANDA Index queried %d times, want 2", hits)
	}
}

func TestE2EPeerWithUnpinnedAgentFactsKeyNeverReceivesAGrant(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// The Index entry and Agent Card look right, but the Operator's AgentFacts
	// are signed by a key Monitor never pinned, as an impersonator's would be.
	topology := newNANDATopology(t, ctx, func(ed25519.PrivateKey) ed25519.PrivateKey {
		_, impostor, _ := ed25519.GenerateKey(rand.Reader)
		return impostor
	})

	_, _ = topology.monitor.Scan(ctx, monitor.ScanRequest{})
	second, _ := topology.monitor.Scan(ctx, monitor.ScanRequest{})
	if topology.investigatorHits.Load() == 0 {
		t.Fatal("the correctly signed Investigator should still be reached")
	}
	if hits := topology.operatorHits.Load(); hits != 0 {
		t.Fatalf("an Operator that failed AgentFacts verification received %d messages", hits)
	}
	for _, outcome := range second.Outcomes {
		if outcome.Receipt != nil {
			t.Fatalf("an action ran through an unverified Operator: %#v", outcome.Receipt)
		}
	}
}
