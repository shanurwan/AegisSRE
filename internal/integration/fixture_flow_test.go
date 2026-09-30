package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/shanurwan/AegisSRE/internal/adapters/fixture"
	"github.com/shanurwan/AegisSRE/internal/app/investigator"
	"github.com/shanurwan/AegisSRE/internal/app/monitor"
	"github.com/shanurwan/AegisSRE/internal/app/operator"
	"github.com/shanurwan/AegisSRE/internal/core/model"
	runtimeadapter "github.com/shanurwan/AegisSRE/internal/platform/runtime"
	"github.com/shanurwan/AegisSRE/internal/security"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
	a2atransport "github.com/shanurwan/AegisSRE/internal/transport/a2a"
	mcptransport "github.com/shanurwan/AegisSRE/internal/transport/mcp"
)

func TestFixtureIncidentFlowsAcrossMCPAndA2A(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	fixturePath := filepath.Join("..", "..", "testdata", "fixtures", "unavailable-deployment.json")
	clock, ids := runtimeadapter.Clock{}, runtimeadapter.IDs{}

	observeFixture, err := fixture.Load(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	readMux := http.NewServeMux()
	readMux.Handle("/mcp", mcptransport.HTTPHandler(mcptransport.NewReadServer(observeFixture)))
	readServer := httptest.NewServer(readMux)
	t.Cleanup(readServer.Close)
	readClient, err := mcptransport.Connect(ctx, readServer.URL+"/mcp", "integration-read-client", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = readClient.Close() })

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "integration-key"
	signer, err := security.NewSigner(privateKey, keyID)
	if err != nil {
		t.Fatal(err)
	}
	operatorVerifier, err := security.NewVerifier(publicKey, keyID, model.AgentOperator)
	if err != nil {
		t.Fatal(err)
	}
	actionVerifier, err := security.NewVerifier(publicKey, keyID, model.AgentMCPAction)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := security.NewPolicy(security.PolicyConfig{
		AllowedNamespaces: []string{"outage-arena"},
		AllowedActions: []model.ActionKind{
			model.ActionRestartDeployment, model.ActionScaleDeployment,
		},
		MinimumConfidence: 0.8, MinimumEvidence: 1,
		MaximumGrantTTL: 2 * time.Minute, RequireDryRun: true,
		MaximumReplicas: 20, MaximumReplicaIncrease: 5,
	})
	if err != nil {
		t.Fatal(err)
	}

	actionFixture, err := fixture.Load(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	actionFixture.Verifier = actionVerifier
	actionFixture.Policy = policy
	actionFixture.Replay = security.NewMemoryReplayGuard()
	actionFixture.Clock = clock
	actionFixture.IDs = ids
	actionFixture.AllowMutations = false
	actionMux := http.NewServeMux()
	actionMux.Handle("/mcp", mcptransport.HTTPHandler(mcptransport.NewActionServer(actionFixture)))
	actionServer := httptest.NewServer(actionMux)
	t.Cleanup(actionServer.Close)
	actionClient, err := mcptransport.Connect(ctx, actionServer.URL+"/mcp", "integration-action-client", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = actionClient.Close() })

	investigatorService := &investigator.Service{
		Tools: readClient, Reasoner: investigator.HeuristicReasoner{Clock: clock, IDs: ids},
		Clock: clock, IDs: ids, MaxLogBytes: 32768,
	}
	investigatorServer := startA2AServer(t, "Investigator", "investigate", investigatorService.Handle)

	operatorService := &operator.Service{
		Tools: actionClient, Verifier: operatorVerifier, Policy: policy,
		Replay: security.NewMemoryReplayGuard(), Clock: clock, IDs: ids,
	}
	operatorServer := startA2AServer(t, "Operator", "operate", operatorService.Handle)

	monitorService := &monitor.Service{
		Tools: readClient, Peers: a2atransport.NewClient(5 * time.Second),
		Signer: signer, Policy: policy, Clock: clock, IDs: ids,
		Namespace: "outage-arena", InvestigatorURL: investigatorServer.URL, OperatorURL: operatorServer.URL,
		Rules: monitor.DefaultRules(), VerificationCount: 2, Cooldown: time.Minute,
		DelegationTTL: 2 * time.Minute, RequestTimeout: 5 * time.Second,
		EvidenceBudget: 6, DryRun: true,
	}

	first, err := monitorService.Scan(ctx, monitor.ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Candidates != 1 || len(first.Outcomes) != 0 {
		t.Fatalf("first observation must verify, not delegate: %#v", first)
	}
	second, err := monitorService.Scan(ctx, monitor.ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Outcomes) != 1 {
		t.Fatalf("verified incident did not produce one outcome: %#v", second)
	}
	outcome := second.Outcomes[0]
	if outcome.Diagnosis == nil || outcome.Grant == nil || outcome.Receipt == nil {
		t.Fatalf("flow did not cross diagnosis, delegation, and action boundaries: %#v", outcome)
	}
	if outcome.Status != string(model.ActionDryRun) || !outcome.Receipt.DryRun || outcome.Incident.State != model.IncidentEscalated {
		t.Fatalf("unexpected safe dry-run outcome: %#v", outcome)
	}
	if err := outcome.Diagnosis.VerifyDigest(); err != nil {
		t.Fatalf("diagnosis digest failed: %v", err)
	}
	if err := security.VerifyGrant(publicKey, keyID, model.AgentMCPAction, *outcome.Grant, time.Now().UTC()); err != nil {
		t.Fatalf("grant was not independently verifiable: %v", err)
	}

	var after toolapi.GetWorkloadSnapshotOutput
	if err := readClient.Call(ctx, toolapi.ToolGetWorkloadSnapshot, toolapi.GetWorkloadSnapshotInput{
		Namespace: "outage-arena", Kind: "Deployment", Name: "demo-api",
	}, &after); err != nil {
		t.Fatal(err)
	}
	if after.Snapshot.ResourceVersion != "fixture-rv-before" || after.Snapshot.AvailableReplicas != 0 {
		t.Fatalf("dry-run changed fixture state: %#v", after.Snapshot)
	}
}

func startA2AServer(t *testing.T, name, skill string, handler a2atransport.Handler) *httptest.Server {
	t.Helper()
	var application http.Handler
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		application.ServeHTTP(writer, request)
	}))
	t.Cleanup(server.Close)
	var err error
	application, _, err = a2atransport.NewHandler(a2atransport.CardConfig{
		Name: name, Description: name + " integration service", PublicURL: server.URL,
		SkillID: skill, SkillName: skill,
	}, handler)
	if err != nil {
		t.Fatal(err)
	}
	return server
}
