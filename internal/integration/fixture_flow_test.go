package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shanurwan/AegisSRE/internal/adapters/fixture"
	"github.com/shanurwan/AegisSRE/internal/adapters/notification"
	"github.com/shanurwan/AegisSRE/internal/app/investigator"
	"github.com/shanurwan/AegisSRE/internal/app/monitor"
	"github.com/shanurwan/AegisSRE/internal/app/operator"
	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
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
		Tools: actionClient, Verifier: operatorVerifier, ReportVerifier: operatorVerifier, Policy: policy,
		Replay: security.NewMemoryReplayGuard(), Clock: clock, IDs: ids,
	}
	operatorServer := startA2AServer(t, "Operator", "operate", operatorService.Handle)

	monitorService := &monitor.Service{
		Tools: readClient, Peers: a2atransport.NewClient(5 * time.Second),
		Signer: signer, ReportSigner: signer, Policy: policy, Clock: clock, IDs: ids,
		Namespace: "outage-arena", InvestigatorURL: investigatorServer.URL, OperatorURL: operatorServer.URL,
		Rules: monitor.DefaultRules(), VerificationCount: 2, Cooldown: time.Minute,
		DelegationTTL: 2 * time.Minute, RequestTimeout: 5 * time.Second,
		EvidenceBudget: 6, DryRun: true,
	}

	first, err := monitorService.Scan(ctx, monitor.ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Candidates != 3 || len(first.Outcomes) != 0 {
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
	if outcome.Report == nil || outcome.Report.Report.Reason != model.ReportReasonDryRunCompleted ||
		outcome.Report.Notification.Status != model.NotificationFailed {
		t.Fatalf("terminal result did not return an independent report/notification receipt: %#v", outcome.Report)
	}
	if err := outcome.Report.Validate(); err != nil {
		t.Fatalf("terminal incident report failed validation: %v", err)
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

// TestE2EFixtureLiveRecoveryAndWhatsAppDelivery is the executable acceptance
// test for the complete autonomous loop. It crosses the production MCP and A2A
// HTTP transports, mutates a shared fixture through the action plane, verifies
// recovery through the independent observe plane, then delivers Operator's
// sealed terminal report through the WhatsApp adapter to a loopback API double.
func TestE2EFixtureLiveRecoveryAndWhatsAppDelivery(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	fixturePath := filepath.Join("..", "..", "testdata", "fixtures", "unavailable-deployment.json")
	clock, ids := runtimeadapter.Clock{}, runtimeadapter.IDs{}

	sharedFixture, err := fixture.Load(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "e2e-live-key"
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
		AllowedActions:    []model.ActionKind{model.ActionRestartDeployment},
		MinimumConfidence: 0.8, MinimumEvidence: 1,
		MaximumGrantTTL: 2 * time.Minute, RequireDryRun: false,
		MaximumReplicas: 20, MaximumReplicaIncrease: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	sharedFixture.Verifier = actionVerifier
	sharedFixture.Policy = policy
	sharedFixture.Replay = security.NewMemoryReplayGuard()
	sharedFixture.Clock = clock
	sharedFixture.IDs = ids
	sharedFixture.AllowMutations = true
	actionBackend := &countingOperateBackend{OperateBackend: sharedFixture}

	readClient := startMCPClient(t, ctx, "e2e-read-client", mcptransport.HTTPHandler(mcptransport.NewReadServer(sharedFixture)))
	actionClient := startMCPClient(t, ctx, "e2e-action-client", mcptransport.HTTPHandler(mcptransport.NewActionServer(actionBackend)))
	notifier, captures := startWhatsAppDouble(t)

	investigatorService := &investigator.Service{
		Tools: readClient, Reasoner: investigator.HeuristicReasoner{Clock: clock, IDs: ids},
		Clock: clock, IDs: ids, MaxLogBytes: 32768,
	}
	investigatorServer := startA2AServer(t, "Investigator", "investigate", investigatorService.Handle)
	operatorService := &operator.Service{
		Tools: actionClient, Verifier: operatorVerifier, ReportVerifier: operatorVerifier, Policy: policy,
		Replay: security.NewMemoryReplayGuard(), Clock: clock, IDs: ids, Notifier: notifier,
	}
	operatorServer := startA2AServer(t, "Operator", "operate", operatorService.Handle)
	monitorService := &monitor.Service{
		Tools: readClient, Peers: a2atransport.NewClient(5 * time.Second),
		Signer: signer, ReportSigner: signer, Policy: policy, Clock: clock, IDs: ids,
		Namespace: "outage-arena", InvestigatorURL: investigatorServer.URL, OperatorURL: operatorServer.URL,
		Rules: monitor.DefaultRules(), VerificationCount: 2, Cooldown: time.Minute,
		DelegationTTL: 2 * time.Minute, RequestTimeout: 5 * time.Second,
		EvidenceBudget: 6, DryRun: false,
	}

	first, err := monitorService.Scan(ctx, monitor.ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Candidates != 3 || len(first.Outcomes) != 0 {
		t.Fatalf("first multi-signal observation must verify without delegating: %#v", first)
	}
	second, err := monitorService.Scan(ctx, monitor.ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if second.Candidates != 3 || len(second.Outcomes) != 1 {
		t.Fatalf("three signals must deduplicate into one incident workflow: %#v", second)
	}
	outcome := second.Outcomes[0]
	if outcome.Status != "resolved" || outcome.Incident.State != model.IncidentResolved {
		t.Fatalf("Monitor did not independently verify recovery: %#v", outcome)
	}
	if outcome.Diagnosis == nil || outcome.Grant == nil || outcome.Receipt == nil || outcome.Report == nil {
		t.Fatalf("full E2E chain is incomplete: %#v", outcome)
	}
	if outcome.Receipt.Outcome != model.ActionSucceeded || outcome.Receipt.DryRun {
		t.Fatalf("action plane did not execute the live fixture remediation: %#v", outcome.Receipt)
	}
	if outcome.Report.Report.Reason != model.ReportReasonRecoveryVerified ||
		outcome.Report.Notification.Status != model.NotificationDelivered ||
		outcome.Report.Notification.ProviderMessageID != "wamid.e2e-recovery" {
		t.Fatalf("terminal recovery report was not delivered: %#v", outcome.Report)
	}
	execution := outcome.Report.Report.Execution
	if execution == nil || execution.GrantID != outcome.Grant.GrantID ||
		execution.ReceiptID != outcome.Receipt.ReceiptID || !execution.Action.Equal(outcome.Grant.Action) ||
		execution.Outcome != outcome.Receipt.Outcome {
		t.Fatalf("terminal report is not bound to the exact grant and receipt: %#v", execution)
	}
	if err := outcome.Report.Validate(); err != nil {
		t.Fatalf("terminal report failed validation: %v", err)
	}
	if calls := actionBackend.executeCalls.Load(); calls != 1 {
		t.Fatalf("live workflow executed the action MCP %d times, want exactly one", calls)
	}

	var after toolapi.GetWorkloadSnapshotOutput
	if err := readClient.Call(ctx, toolapi.ToolGetWorkloadSnapshot, toolapi.GetWorkloadSnapshotInput{
		Namespace: "outage-arena", Kind: "Deployment", Name: "demo-api",
	}, &after); err != nil {
		t.Fatal(err)
	}
	if after.Snapshot.ResourceVersion != "fixture-rv-after" || after.Snapshot.AvailableReplicas != after.Snapshot.DesiredReplicas {
		t.Fatalf("live fixture action did not produce an observable recovery: %#v", after.Snapshot)
	}
	assertWhatsAppCapture(t, captures, "wamid.e2e-recovery")
}

// TestE2EOutsideAuthorityEscalatesWithoutMutation proves that an Operator
// policy rejection is preserved over A2A, converted into a terminal escalation,
// and notified without allowing the action MCP plane to mutate the workload.
func TestE2EOutsideAuthorityEscalatesWithoutMutation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	fixturePath := filepath.Join("..", "..", "testdata", "fixtures", "unavailable-deployment.json")
	clock, ids := runtimeadapter.Clock{}, runtimeadapter.IDs{}
	sharedFixture, err := fixture.Load(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "e2e-authority-key"
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
	monitorPolicy, err := security.NewPolicy(security.PolicyConfig{
		AllowedNamespaces: []string{"outage-arena"},
		AllowedActions:    []model.ActionKind{model.ActionRestartDeployment},
		MinimumConfidence: 0.8, MinimumEvidence: 1,
		MaximumGrantTTL: 2 * time.Minute, RequireDryRun: false,
		MaximumReplicas: 20, MaximumReplicaIncrease: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	operatorPolicy, err := security.NewPolicy(security.PolicyConfig{
		AllowedNamespaces: []string{"outage-arena"},
		AllowedActions:    []model.ActionKind{model.ActionScaleDeployment},
		MinimumConfidence: 0.8, MinimumEvidence: 1,
		MaximumGrantTTL: 2 * time.Minute, RequireDryRun: false,
		MaximumReplicas: 20, MaximumReplicaIncrease: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	sharedFixture.Verifier = actionVerifier
	sharedFixture.Policy = monitorPolicy
	sharedFixture.Replay = security.NewMemoryReplayGuard()
	sharedFixture.Clock = clock
	sharedFixture.IDs = ids
	sharedFixture.AllowMutations = true
	actionBackend := &countingOperateBackend{OperateBackend: sharedFixture}

	readClient := startMCPClient(t, ctx, "e2e-authority-read-client", mcptransport.HTTPHandler(mcptransport.NewReadServer(sharedFixture)))
	actionClient := startMCPClient(t, ctx, "e2e-authority-action-client", mcptransport.HTTPHandler(mcptransport.NewActionServer(actionBackend)))
	notifier, captures := startWhatsAppDoubleWithID(t, "wamid.e2e-authority")
	investigatorService := &investigator.Service{
		Tools: readClient, Reasoner: investigator.HeuristicReasoner{Clock: clock, IDs: ids},
		Clock: clock, IDs: ids, MaxLogBytes: 32768,
	}
	investigatorServer := startA2AServer(t, "Investigator", "investigate", investigatorService.Handle)
	operatorService := &operator.Service{
		Tools: actionClient, Verifier: operatorVerifier, ReportVerifier: operatorVerifier, Policy: operatorPolicy,
		Replay: security.NewMemoryReplayGuard(), Clock: clock, IDs: ids, Notifier: notifier,
	}
	operatorServer := startA2AServer(t, "Operator", "operate", operatorService.Handle)
	monitorService := &monitor.Service{
		Tools: readClient, Peers: a2atransport.NewClient(5 * time.Second),
		Signer: signer, ReportSigner: signer, Policy: monitorPolicy, Clock: clock, IDs: ids,
		Namespace: "outage-arena", InvestigatorURL: investigatorServer.URL, OperatorURL: operatorServer.URL,
		Rules: monitor.DefaultRules(), VerificationCount: 2, Cooldown: time.Minute,
		DelegationTTL: 2 * time.Minute, RequestTimeout: 5 * time.Second,
		EvidenceBudget: 6, DryRun: false,
	}

	if _, err := monitorService.Scan(ctx, monitor.ScanRequest{}); err != nil {
		t.Fatal(err)
	}
	result, err := monitorService.Scan(ctx, monitor.ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outcomes) != 1 {
		t.Fatalf("expected one deduplicated authority escalation: %#v", result)
	}
	outcome := result.Outcomes[0]
	if outcome.Status != string(model.IncidentEscalated) || outcome.Incident.State != model.IncidentEscalated {
		t.Fatalf("outside-authority action was not escalated: %#v", outcome)
	}
	if outcome.Grant == nil || outcome.Receipt != nil || outcome.Report == nil {
		t.Fatalf("authority rejection crossed an unexpected boundary: %#v", outcome)
	}
	if outcome.Report.Report.Reason != model.ReportReasonAuthorityExceeded ||
		outcome.Report.Notification.Status != model.NotificationDelivered ||
		outcome.Report.Notification.ProviderMessageID != "wamid.e2e-authority" {
		t.Fatalf("authority escalation report was not delivered: %#v", outcome.Report)
	}
	if outcome.Report.Report.Execution != nil {
		t.Fatalf("authority escalation report must not claim an execution: %#v", outcome.Report.Report.Execution)
	}
	if calls := actionBackend.executeCalls.Load(); calls != 0 {
		t.Fatalf("outside-authority workflow called the action MCP %d times, want zero", calls)
	}

	var after toolapi.GetWorkloadSnapshotOutput
	if err := readClient.Call(ctx, toolapi.ToolGetWorkloadSnapshot, toolapi.GetWorkloadSnapshotInput{
		Namespace: "outage-arena", Kind: "Deployment", Name: "demo-api",
	}, &after); err != nil {
		t.Fatal(err)
	}
	if after.Snapshot.ResourceVersion != "fixture-rv-before" || after.Snapshot.AvailableReplicas != 0 {
		t.Fatalf("outside-authority path mutated the fixture: %#v", after.Snapshot)
	}
	assertWhatsAppCapture(t, captures, "wamid.e2e-authority")
}

type whatsAppCapture struct {
	method        string
	path          string
	contentType   string
	authorization string
	body          []byte
}

type countingOperateBackend struct {
	ports.OperateBackend
	executeCalls atomic.Int64
}

func (b *countingOperateBackend) ExecuteRemediation(ctx context.Context, input toolapi.ExecuteRemediationInput) (toolapi.ExecuteRemediationOutput, error) {
	b.executeCalls.Add(1)
	return b.OperateBackend.ExecuteRemediation(ctx, input)
}

func startMCPClient(t *testing.T, ctx context.Context, name string, handler http.Handler) *mcptransport.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	httpServer := httptest.NewServer(mux)
	t.Cleanup(httpServer.Close)
	client, err := mcptransport.Connect(ctx, httpServer.URL+"/mcp", name, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func startWhatsAppDouble(t *testing.T) (*notification.WhatsApp, <-chan whatsAppCapture) {
	t.Helper()
	return startWhatsAppDoubleWithID(t, "wamid.e2e-recovery")
}

func startWhatsAppDoubleWithID(t *testing.T, messageID string) (*notification.WhatsApp, <-chan whatsAppCapture) {
	t.Helper()
	captures := make(chan whatsAppCapture, 4)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(io.LimitReader(request.Body, 16<<10))
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		captures <- whatsAppCapture{
			method: request.Method, path: request.URL.Path,
			contentType:   request.Header.Get("Content-Type"),
			authorization: request.Header.Get("Authorization"), body: body,
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"messaging_product": "whatsapp",
			"messages":          []map[string]string{{"id": messageID}},
		})
	}))
	t.Cleanup(server.Close)
	notifier, err := notification.NewWhatsApp(notification.Config{
		GraphVersion: "v23.0", PhoneNumberID: "123456789", AccessToken: "e2e-test-token",
		Recipient: "60123456789", Template: "aegissre_incident_update", Language: "en_US",
		MaxRetries: 0, Client: server.Client(), BaseURL: server.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	return notifier, captures
}

func assertWhatsAppCapture(t *testing.T, captures <-chan whatsAppCapture, messageID string) {
	t.Helper()
	select {
	case capture := <-captures:
		if capture.method != http.MethodPost {
			t.Fatalf("unexpected WhatsApp method: %s", capture.method)
		}
		if capture.path != "/v23.0/123456789/messages" {
			t.Fatalf("unexpected WhatsApp route: %s", capture.path)
		}
		if capture.contentType != "application/json" {
			t.Fatalf("unexpected WhatsApp content type: %s", capture.contentType)
		}
		if capture.authorization != "Bearer e2e-test-token" {
			t.Fatalf("WhatsApp authorization header was not routed correctly")
		}
		body := string(capture.body)
		for _, forbidden := range []string{"e2e-test-token", "dependency health check timed out", "readiness probe"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("WhatsApp payload leaked forbidden evidence or credentials: %q", forbidden)
			}
		}
		if !strings.Contains(body, `"name":"aegissre_incident_update"`) ||
			!strings.Contains(body, `"reason":`) && !strings.Contains(body, "reason=") {
			t.Fatalf("WhatsApp payload did not contain the approved terminal-report template: %s", body)
		}
		if !strings.Contains(body, `"to":"60123456789"`) {
			t.Fatalf("WhatsApp payload was not routed to the configured recipient: %s", body)
		}
		if messageID == "" {
			t.Fatal("test message ID is empty")
		}
		select {
		case extra := <-captures:
			t.Fatalf("WhatsApp API double received more than one request: %#v", extra)
		default:
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WhatsApp API double did not receive a terminal report")
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
