package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/shanurwan/AegisSRE/internal/adapters/fixture"
	kubeadapter "github.com/shanurwan/AegisSRE/internal/adapters/kubernetes"
	"github.com/shanurwan/AegisSRE/internal/app/operator"
	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
	runtimeadapter "github.com/shanurwan/AegisSRE/internal/platform/runtime"
	"github.com/shanurwan/AegisSRE/internal/security"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
	mcptransport "github.com/shanurwan/AegisSRE/internal/transport/mcp"
)

func TestE2EOperatorRecoversCommittedActionReceiptAfterCrashAndGrantExpiry(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	issuedAt := time.Date(2026, 10, 2, 4, 0, 0, 0, time.UTC)
	clock := &recoveryClock{now: issuedAt}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "e2e-recovery-key"
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
		MinimumConfidence: 0.8, MinimumEvidence: 1, MaximumGrantTTL: 2 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	fixturePath := "../../testdata/fixtures/unavailable-deployment.json"
	actionFixture, err := fixture.Load(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	actionFixture.Verifier = actionVerifier
	actionFixture.Policy = policy
	actionFixture.Replay = security.NewMemoryReplayGuard()
	actionFixture.Clock = clock
	actionFixture.IDs = runtimeadapter.IDs{}
	actionFixture.AllowMutations = true
	countingBackend := &countingOperateBackend{OperateBackend: actionFixture}
	actionClient := startMCPClient(
		t, ctx, "durable-recovery-e2e",
		mcptransport.HTTPHandler(mcptransport.NewActionServer(countingBackend)),
	)

	expectedReplicas := int32(1)
	grant, err := security.SignGrant(privateKey, keyID, model.DelegationGrant{
		SchemaVersion:       model.SchemaVersionV1,
		GrantID:             "grant-e2e-crash-recovery",
		Issuer:              model.AgentMonitor,
		Audiences:           []model.AgentID{model.AgentOperator, model.AgentMCPAction},
		IncidentID:          "incident-e2e-crash-recovery",
		DiagnosisReportID:   "diagnosis-e2e-crash-recovery",
		DiagnosisDigest:     strings.Repeat("a", 64),
		DiagnosisConfidence: 0.99,
		EvidenceIDs:         []string{"evidence-e2e-crash-recovery"},
		ProposalID:          "proposal-e2e-crash-recovery",
		Action: model.ActionSpec{
			Kind: model.ActionRestartDeployment,
			Target: model.ResourceTarget{
				APIVersion: "apps/v1", Kind: "Deployment", Namespace: "outage-arena", Name: "demo-api",
			},
		},
		Preconditions:  model.ActionPreconditions{ResourceVersion: "fixture-rv-before", ExpectedReplicas: &expectedReplicas},
		IdempotencyKey: "incident-e2e-crash-recovery:proposal-e2e-crash-recovery",
		IssuedAt:       issuedAt, NotBefore: issuedAt, ExpiresAt: issuedAt.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	operatorStore := &recoveryExecutionStore{clock: clock}
	lostResponse := &lostExecuteResponse{next: actionClient}
	beforeCrash := &operator.Service{
		Tools: lostResponse, Verifier: operatorVerifier, Policy: policy, Clock: clock,
		Audit: recoveryAuditor{}, ExecutionStore: operatorStore,
		InstanceID: "operator-before-crash", ExecutionLease: 30 * time.Second,
	}
	if _, err := beforeCrash.Execute(ctx, grant); err == nil {
		t.Fatal("initial execution unexpectedly received the committed downstream response")
	}
	beforeRecord, found, err := operatorStore.GetExecution(ctx, ports.ExecutionScopeOperator, grant)
	if err != nil || !found || beforeRecord.Status != ports.ExecutionReserved {
		t.Fatalf("lost response Operator state = (%#v, %t, %v), want reserved", beforeRecord, found, err)
	}
	if lostResponse.receipt == nil {
		t.Fatal("action MCP did not commit a receipt before the simulated response loss")
	}

	// Simulate loss of the Operator response/commit and restart only after both
	// its lease and the grant validity interval have elapsed.
	clock.Set(issuedAt.Add(4 * time.Minute))
	service := &operator.Service{
		Tools: actionClient, Verifier: operatorVerifier, Policy: policy, Clock: clock,
		Audit: recoveryAuditor{}, ExecutionStore: operatorStore,
		InstanceID: "operator-after-crash", ExecutionLease: 30 * time.Second,
	}
	recovered, err := service.Execute(ctx, grant)
	if err != nil {
		t.Fatalf("recover committed receipt after expiry: %v", err)
	}
	if !reflect.DeepEqual(recovered, *lostResponse.receipt) {
		t.Fatalf("recovered receipt = %#v, want exact downstream receipt %#v", recovered, *lostResponse.receipt)
	}
	if calls := countingBackend.executeCalls.Load(); calls != 1 {
		t.Fatalf("crash recovery executed remediation %d times, want exactly once", calls)
	}
	record, found, err := operatorStore.GetExecution(ctx, ports.ExecutionScopeOperator, grant)
	if err != nil || !found || record.Status != ports.ExecutionCompleted || record.Receipt == nil {
		t.Fatalf("Operator durable result = (%#v, %t, %v), want completed", record, found, err)
	}
}

func TestE2EExpiredDownstreamReservationConvergesThroughActionMCPReconciliation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	issuedAt := time.Date(2026, 10, 2, 5, 0, 0, 0, time.UTC)
	clock := &recoveryClock{now: issuedAt}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "e2e-reserved-recovery-key"
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
		MinimumConfidence: 0.8, MinimumEvidence: 1, MaximumGrantTTL: 2 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	replicas := int32(1)
	grant, err := security.SignGrant(privateKey, keyID, model.DelegationGrant{
		SchemaVersion:       model.SchemaVersionV1,
		GrantID:             "grant-e2e-reserved-recovery",
		Issuer:              model.AgentMonitor,
		Audiences:           []model.AgentID{model.AgentOperator, model.AgentMCPAction},
		IncidentID:          "incident-e2e-reserved-recovery",
		DiagnosisReportID:   "diagnosis-e2e-reserved-recovery",
		DiagnosisDigest:     strings.Repeat("b", 64),
		DiagnosisConfidence: 0.99,
		EvidenceIDs:         []string{"evidence-e2e-reserved-recovery"},
		ProposalID:          "proposal-e2e-reserved-recovery",
		Action: model.ActionSpec{
			Kind: model.ActionRestartDeployment,
			Target: model.ResourceTarget{
				APIVersion: "apps/v1", Kind: "Deployment", Namespace: "outage-arena", Name: "demo-api",
			},
		},
		Preconditions:  model.ActionPreconditions{ResourceVersion: "rv-before", ExpectedReplicas: &replicas},
		IdempotencyKey: "incident-e2e-reserved-recovery:proposal-e2e-reserved-recovery",
		IssuedAt:       issuedAt, NotBefore: issuedAt, ExpiresAt: issuedAt.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Kubernetes already carries the exact grant marker: action MCP committed
	// the mutation but crashed before it could persist its receipt.
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "demo-api", Namespace: "outage-arena", ResourceVersion: "rv-after",
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
				"aegissre.io/grant-id":     grant.GrantID,
				"aegissre.io/restarted-at": issuedAt.Add(time.Second).Format(time.RFC3339Nano),
			}}},
		},
	}
	kube := fake.NewSimpleClientset(deployment)
	actionStore := &recoveryExecutionStore{clock: clock}
	if _, err := actionStore.ReserveExecution(
		ctx, ports.ExecutionScopeMCPAction, grant, "action-mcp-before-crash", 10*time.Second,
	); err != nil {
		t.Fatal(err)
	}
	operatorStore := &recoveryExecutionStore{clock: clock}
	if _, err := operatorStore.ReserveExecution(
		ctx, ports.ExecutionScopeOperator, grant, "operator-before-crash", 10*time.Second,
	); err != nil {
		t.Fatal(err)
	}
	actionBackend := &kubeadapter.Client{
		Kube: kube, Namespace: "outage-arena", Verifier: actionVerifier, Policy: policy,
		Clock: clock, Audit: recoveryAuditor{}, AllowMutations: true,
		ExecutionStore: actionStore, InstanceID: "action-mcp-after-crash", ExecutionLease: 30 * time.Second,
	}
	actionClient := startMCPClient(
		t, ctx, "reserved-recovery-e2e",
		mcptransport.HTTPHandler(mcptransport.NewActionServer(actionBackend)),
	)

	clock.Set(issuedAt.Add(4 * time.Minute))
	service := &operator.Service{
		Tools: actionClient, Verifier: operatorVerifier, Policy: policy, Clock: clock,
		Audit: recoveryAuditor{}, ExecutionStore: operatorStore,
		InstanceID: "operator-after-crash", ExecutionLease: 30 * time.Second,
	}
	receipt, err := service.Execute(ctx, grant)
	if err != nil {
		t.Fatalf("recover expired downstream reservation: %v", err)
	}
	if receipt.Outcome != model.ActionSucceeded {
		t.Fatalf("reconciled receipt = %#v, want succeeded", receipt)
	}
	for _, action := range kube.Actions() {
		if action.GetVerb() == "patch" {
			t.Fatalf("marker reconciliation repeated a Kubernetes mutation: %#v", action)
		}
	}
	for name, store := range map[string]*recoveryExecutionStore{"operator": operatorStore, "action MCP": actionStore} {
		record, found, err := store.GetExecution(ctx, map[string]ports.ExecutionScope{
			"operator": ports.ExecutionScopeOperator, "action MCP": ports.ExecutionScopeMCPAction,
		}[name], grant)
		if err != nil || !found || record.Status != ports.ExecutionCompleted || record.Receipt == nil {
			t.Fatalf("%s recovery record = (%#v, %t, %v), want completed", name, record, found, err)
		}
	}
}

func TestE2ERecoveredOperatorNotFoundDenialBecomesUncertain(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	issuedAt := time.Date(2026, 10, 2, 6, 0, 0, 0, time.UTC)
	clock := &recoveryClock{now: issuedAt}
	operatorVerifier, actionVerifier, policy, grant := newRecoveryGrant(
		t, issuedAt, "grant-e2e-not-found-ambiguity",
	)

	actionFixture, err := fixture.Load("../../testdata/fixtures/unavailable-deployment.json")
	if err != nil {
		t.Fatal(err)
	}
	actionFixture.Verifier = actionVerifier
	actionFixture.Policy = policy
	actionFixture.Replay = security.NewMemoryReplayGuard()
	actionFixture.Clock = clock
	actionFixture.IDs = runtimeadapter.IDs{}
	actionFixture.AllowMutations = true
	countingBackend := &countingOperateBackend{OperateBackend: actionFixture}
	actionClient := startMCPClient(
		t, ctx, "not-found-ambiguity-e2e",
		mcptransport.HTTPHandler(mcptransport.NewActionServer(countingBackend)),
	)

	operatorStore := &recoveryExecutionStore{clock: clock}
	if _, err := operatorStore.ReserveExecution(
		ctx, ports.ExecutionScopeOperator, grant, "operator-before-crash", 30*time.Second,
	); err != nil {
		t.Fatal(err)
	}
	clock.Set(issuedAt.Add(4 * time.Minute))
	service := &operator.Service{
		Tools: actionClient, Verifier: operatorVerifier, Policy: policy, Clock: clock,
		Audit: recoveryAuditor{}, ExecutionStore: operatorStore,
		InstanceID: "operator-after-crash", ExecutionLease: 30 * time.Second,
	}

	if _, err := service.Execute(ctx, grant); err == nil {
		t.Fatal("recovered not-found execution error = nil")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeExecutionFailed {
		t.Fatalf("recovered not-found execution error = %v, want uncertain %s classification", err, model.CodeExecutionFailed)
	}
	if calls := countingBackend.executeCalls.Load(); calls != 0 {
		t.Fatalf("authorization-denied not-found recovery executed remediation %d times", calls)
	}
	record, found, err := operatorStore.GetExecution(ctx, ports.ExecutionScopeOperator, grant)
	if err != nil || !found || record.Status != ports.ExecutionUncertain || record.Receipt != nil || record.ErrorCode != model.CodeExecutionFailed {
		t.Fatalf("not-found ambiguity record = (%#v, %t, %v), want uncertain without receipt", record, found, err)
	}
}

func TestE2ERecoveredActionAuthorizationDenialConvergesToUncertain(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	issuedAt := time.Date(2026, 10, 2, 7, 0, 0, 0, time.UTC)
	clock := &recoveryClock{now: issuedAt}
	operatorVerifier, actionVerifier, policy, grant := newRecoveryGrant(
		t, issuedAt, "grant-e2e-action-denial-ambiguity",
	)
	replicas := int32(1)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "demo-api", Namespace: "outage-arena", ResourceVersion: "rv-before",
		},
		Spec: appsv1.DeploymentSpec{Replicas: &replicas},
	}
	kube := fake.NewSimpleClientset(deployment)
	actionStore := &recoveryExecutionStore{clock: clock}
	operatorStore := &recoveryExecutionStore{clock: clock}
	if _, err := actionStore.ReserveExecution(
		ctx, ports.ExecutionScopeMCPAction, grant, "action-mcp-before-crash", 30*time.Second,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := operatorStore.ReserveExecution(
		ctx, ports.ExecutionScopeOperator, grant, "operator-before-crash", 30*time.Second,
	); err != nil {
		t.Fatal(err)
	}
	actionBackend := &countingOperateBackend{OperateBackend: &kubeadapter.Client{
		Kube: kube, Namespace: "outage-arena", Verifier: actionVerifier, Policy: policy,
		Clock: clock, Audit: recoveryAuditor{}, AllowMutations: true,
		ExecutionStore: actionStore, InstanceID: "action-mcp-after-crash", ExecutionLease: 30 * time.Second,
	}}
	actionClient := startMCPClient(
		t, ctx, "action-denial-ambiguity-e2e",
		mcptransport.HTTPHandler(mcptransport.NewActionServer(actionBackend)),
	)

	clock.Set(issuedAt.Add(4 * time.Minute))
	first := &operator.Service{
		Tools: actionClient, Verifier: operatorVerifier, Policy: policy, Clock: clock,
		Audit: recoveryAuditor{}, ExecutionStore: operatorStore,
		InstanceID: "operator-first-recovery", ExecutionLease: 30 * time.Second,
	}
	if _, err := first.Execute(ctx, grant); err == nil {
		t.Fatal("first recovered action denial error = nil")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeExecutionFailed {
		t.Fatalf("first recovered action denial error = %v, want %s", err, model.CodeExecutionFailed)
	}
	actionRecord, found, err := actionStore.GetExecution(ctx, ports.ExecutionScopeMCPAction, grant)
	if err != nil || !found || actionRecord.Status != ports.ExecutionUncertain || actionRecord.Receipt != nil {
		t.Fatalf("action-MCP ambiguity record = (%#v, %t, %v), want uncertain", actionRecord, found, err)
	}
	operatorRecord, found, err := operatorStore.GetExecution(ctx, ports.ExecutionScopeOperator, grant)
	if err != nil || !found || operatorRecord.Status != ports.ExecutionUncertain ||
		operatorRecord.LeaseToken != "" || operatorRecord.LeaseOwner != "" || !operatorRecord.LeaseUntil.IsZero() {
		t.Fatalf("Operator first-pass record = (%#v, %t, %v), want terminal uncertainty without a live lease", operatorRecord, found, err)
	}

	// A later replay returns the already terminal Operator truth without another
	// execute or a renewable reservation.
	clock.Set(issuedAt.Add(5 * time.Minute))
	second := &operator.Service{
		Tools: actionClient, Verifier: operatorVerifier, Policy: policy, Clock: clock,
		Audit: recoveryAuditor{}, ExecutionStore: operatorStore,
		InstanceID: "operator-second-recovery", ExecutionLease: 30 * time.Second,
	}
	if _, err := second.Execute(ctx, grant); err == nil {
		t.Fatal("second recovered action denial error = nil")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeExecutionFailed {
		t.Fatalf("second recovered action denial error = %v, want %s", err, model.CodeExecutionFailed)
	}
	operatorRecord, found, err = operatorStore.GetExecution(ctx, ports.ExecutionScopeOperator, grant)
	if err != nil || !found || operatorRecord.Status != ports.ExecutionUncertain || operatorRecord.Receipt != nil {
		t.Fatalf("Operator converged ambiguity record = (%#v, %t, %v), want uncertain", operatorRecord, found, err)
	}
	if calls := actionBackend.executeCalls.Load(); calls != 1 {
		t.Fatalf("uncertain convergence called action execution %d times, want once", calls)
	}
	for _, action := range kube.Actions() {
		if action.GetVerb() == "patch" {
			t.Fatalf("authorization-denied recovered action issued a Kubernetes patch: %#v", action)
		}
	}
}

func newRecoveryGrant(
	t *testing.T,
	issuedAt time.Time,
	grantID string,
) (*security.Verifier, *security.Verifier, *security.Policy, model.DelegationGrant) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "e2e-ambiguity-key"
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
		MinimumConfidence: 0.8, MinimumEvidence: 1, MaximumGrantTTL: 2 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	expectedReplicas := int32(1)
	grant, err := security.SignGrant(privateKey, keyID, model.DelegationGrant{
		SchemaVersion:       model.SchemaVersionV1,
		GrantID:             grantID,
		Issuer:              model.AgentMonitor,
		Audiences:           []model.AgentID{model.AgentOperator, model.AgentMCPAction},
		IncidentID:          "incident-" + grantID,
		DiagnosisReportID:   "diagnosis-" + grantID,
		DiagnosisDigest:     strings.Repeat("c", 64),
		DiagnosisConfidence: 0.99,
		EvidenceIDs:         []string{"evidence-" + grantID},
		ProposalID:          "proposal-" + grantID,
		Action: model.ActionSpec{
			Kind: model.ActionRestartDeployment,
			Target: model.ResourceTarget{
				APIVersion: "apps/v1", Kind: "Deployment", Namespace: "outage-arena", Name: "demo-api",
			},
		},
		Preconditions:  model.ActionPreconditions{ResourceVersion: "rv-before", ExpectedReplicas: &expectedReplicas},
		IdempotencyKey: "idempotency-" + grantID,
		IssuedAt:       issuedAt, NotBefore: issuedAt, ExpiresAt: issuedAt.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	return operatorVerifier, actionVerifier, policy, grant
}

type lostExecuteResponse struct {
	mu      sync.Mutex
	next    ports.ToolCaller
	lost    bool
	receipt *model.ActionReceipt
}

func (c *lostExecuteResponse) Discover(ctx context.Context) ([]string, error) {
	return c.next.Discover(ctx)
}

func (c *lostExecuteResponse) Call(ctx context.Context, name string, input, output any) error {
	if err := c.next.Call(ctx, name, input, output); err != nil {
		return err
	}
	if name != toolapi.ToolExecuteRemediation {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lost {
		return nil
	}
	c.lost = true
	result, ok := output.(*toolapi.ExecuteRemediationOutput)
	if !ok {
		return errors.New("unexpected execute-remediation output type")
	}
	receipt := result.Receipt
	c.receipt = &receipt
	return errors.New("simulated connection loss after action MCP commit")
}

func (c *lostExecuteResponse) Close() error { return nil }

type recoveryClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *recoveryClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *recoveryClock) Set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

type recoveryAuditor struct{}

func (recoveryAuditor) Record(_ context.Context, event model.AuditEvent) error {
	return event.Validate()
}

type recoveryExecutionStore struct {
	mu     sync.Mutex
	clock  ports.Clock
	record *ports.ExecutionRecord
}

func (s *recoveryExecutionStore) GetExecution(
	_ context.Context,
	scope ports.ExecutionScope,
	grant model.DelegationGrant,
) (ports.ExecutionRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.record == nil {
		return ports.ExecutionRecord{}, false, nil
	}
	if s.record.Scope != scope || !reflect.DeepEqual(s.record.Grant, grant) {
		return ports.ExecutionRecord{}, false, model.NewError(model.CodeInvalidInput, "test signed grant fingerprint mismatch")
	}
	return cloneRecoveryRecord(*s.record), true, nil
}

func (s *recoveryExecutionStore) GetExecutionByID(
	_ context.Context,
	scope ports.ExecutionScope,
	grantID string,
) (ports.ExecutionRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.record == nil || s.record.Scope != scope || s.record.Grant.GrantID != grantID {
		return ports.ExecutionRecord{}, false, nil
	}
	return cloneRecoveryRecord(*s.record), true, nil
}

func (s *recoveryExecutionStore) ReserveExecution(
	_ context.Context,
	scope ports.ExecutionScope,
	grant model.DelegationGrant,
	owner string,
	lease time.Duration,
) (ports.ExecutionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now().UTC()
	if s.record == nil {
		s.record = &ports.ExecutionRecord{
			Scope: scope, Grant: grant, Status: ports.ExecutionReserved,
			LeaseOwner: owner, LeaseToken: "lease-before-crash", LeaseUntil: now.Add(lease),
			StartedAt: now, RetentionUntil: grant.ExpiresAt.Add(24 * time.Hour), Version: 1,
		}
		result := cloneRecoveryRecord(*s.record)
		result.Owner = true
		return result, nil
	}
	if s.record.Scope != scope || !reflect.DeepEqual(s.record.Grant, grant) {
		return ports.ExecutionRecord{}, model.NewError(model.CodeInvalidInput, "test signed grant fingerprint mismatch")
	}
	result := cloneRecoveryRecord(*s.record)
	if result.Status != ports.ExecutionReserved || now.Before(result.LeaseUntil) {
		return result, nil
	}
	s.record.LeaseOwner = owner
	s.record.LeaseToken = "lease-after-crash"
	s.record.LeaseUntil = now.Add(lease)
	s.record.Version++
	result = cloneRecoveryRecord(*s.record)
	result.Owner = true
	result.RecoveredLease = true
	return result, nil
}

func (s *recoveryExecutionStore) CompleteExecution(
	_ context.Context,
	scope ports.ExecutionScope,
	grantID, leaseToken string,
	receipt model.ActionReceipt,
) (ports.ExecutionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.record == nil || s.record.Scope != scope || s.record.Grant.GrantID != grantID ||
		s.record.Status != ports.ExecutionReserved || s.record.LeaseToken != leaseToken {
		return ports.ExecutionRecord{}, model.NewError(model.CodeReplayedGrant, "test execution lease changed")
	}
	copy := receipt
	s.record.Status = ports.ExecutionCompleted
	s.record.Receipt = &copy
	s.record.LeaseOwner, s.record.LeaseToken = "", ""
	s.record.LeaseUntil = time.Time{}
	return cloneRecoveryRecord(*s.record), nil
}

func (s *recoveryExecutionStore) MarkExecutionUncertain(
	_ context.Context,
	scope ports.ExecutionScope,
	grantID, leaseToken string,
	code model.ErrorCode,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.record == nil || s.record.Scope != scope || s.record.Grant.GrantID != grantID ||
		s.record.Status != ports.ExecutionReserved || s.record.LeaseToken != leaseToken {
		return model.NewError(model.CodeReplayedGrant, "test execution lease changed")
	}
	s.record.Status = ports.ExecutionUncertain
	s.record.ErrorCode = code
	s.record.Owner = false
	s.record.RecoveredLease = false
	s.record.LeaseOwner = ""
	s.record.LeaseToken = ""
	s.record.LeaseUntil = time.Time{}
	completedAt := s.clock.Now().UTC()
	s.record.CompletedAt = &completedAt
	s.record.RetentionUntil = completedAt.Add(24 * time.Hour)
	s.record.Version++
	return nil
}

func (*recoveryExecutionStore) PurgeExecutions(context.Context, time.Time, int) (int64, error) {
	return 0, nil
}

func cloneRecoveryRecord(record ports.ExecutionRecord) ports.ExecutionRecord {
	if record.Receipt != nil {
		copy := *record.Receipt
		record.Receipt = &copy
	}
	return record
}
