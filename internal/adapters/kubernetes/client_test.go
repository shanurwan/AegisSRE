package kubernetes

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
	"github.com/shanurwan/AegisSRE/internal/security"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

type adapterClock struct{ value time.Time }

func (c adapterClock) Now() time.Time { return c.value }

type adapterIDs struct{}

func (adapterIDs) NewID() string { return "test-id" }

type memoryExecutionStore struct {
	mu     sync.Mutex
	now    time.Time
	record *ports.ExecutionRecord
}

func (s *memoryExecutionStore) GetExecution(
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
		return ports.ExecutionRecord{}, false, model.NewError(model.CodeInvalidInput, "test execution fingerprint collision")
	}
	return cloneExecutionRecord(*s.record), true, nil
}

func (s *memoryExecutionStore) GetExecutionByID(
	_ context.Context,
	scope ports.ExecutionScope,
	grantID string,
) (ports.ExecutionRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.record == nil || s.record.Scope != scope || s.record.Grant.GrantID != grantID {
		return ports.ExecutionRecord{}, false, nil
	}
	return cloneExecutionRecord(*s.record), true, nil
}

func (s *memoryExecutionStore) ReserveExecution(
	_ context.Context,
	scope ports.ExecutionScope,
	grant model.DelegationGrant,
	owner string,
	lease time.Duration,
) (ports.ExecutionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.record == nil {
		s.record = &ports.ExecutionRecord{
			Scope: scope, Grant: grant, Status: ports.ExecutionReserved,
			LeaseOwner: owner, LeaseToken: "lease-1", LeaseUntil: s.now.Add(lease),
			StartedAt: s.now, RetentionUntil: grant.ExpiresAt.Add(24 * time.Hour), Version: 1,
		}
		result := cloneExecutionRecord(*s.record)
		result.Owner = true
		return result, nil
	}
	if s.record.Scope != scope || !reflect.DeepEqual(s.record.Grant, grant) {
		return ports.ExecutionRecord{}, model.NewError(model.CodeInvalidInput, "test execution fingerprint collision")
	}
	if s.record.Status != ports.ExecutionReserved || s.now.Before(s.record.LeaseUntil) {
		result := cloneExecutionRecord(*s.record)
		result.Owner = false
		return result, nil
	}
	s.record.LeaseOwner = owner
	s.record.Version++
	s.record.LeaseToken = "lease-recovered-" + time.Unix(s.record.Version, 0).UTC().Format("150405")
	s.record.LeaseUntil = s.now.Add(lease)
	result := cloneExecutionRecord(*s.record)
	result.Owner = true
	result.RecoveredLease = true
	return result, nil
}

func (s *memoryExecutionStore) CompleteExecution(
	_ context.Context,
	scope ports.ExecutionScope,
	grantID string,
	leaseToken string,
	receipt model.ActionReceipt,
) (ports.ExecutionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.record == nil || s.record.Scope != scope || s.record.Grant.GrantID != grantID ||
		s.record.Status != ports.ExecutionReserved || s.record.LeaseToken != leaseToken {
		return ports.ExecutionRecord{}, model.NewError(model.CodeReplayedGrant, "test execution lease changed")
	}
	copy := cloneActionReceipt(receipt)
	s.record.Status = ports.ExecutionCompleted
	s.record.Receipt = &copy
	completedAt := receipt.CompletedAt
	s.record.CompletedAt = &completedAt
	s.record.LeaseOwner = ""
	s.record.LeaseToken = ""
	s.record.LeaseUntil = time.Time{}
	s.record.Version++
	return cloneExecutionRecord(*s.record), nil
}

func (s *memoryExecutionStore) MarkExecutionUncertain(
	_ context.Context,
	scope ports.ExecutionScope,
	grantID string,
	leaseToken string,
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
	completedAt := s.now
	s.record.CompletedAt = &completedAt
	s.record.LeaseOwner = ""
	s.record.LeaseToken = ""
	s.record.LeaseUntil = time.Time{}
	s.record.Version++
	return nil
}

func (*memoryExecutionStore) PurgeExecutions(context.Context, time.Time, int) (int64, error) {
	return 0, nil
}

func (s *memoryExecutionStore) snapshot() ports.ExecutionRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.record == nil {
		return ports.ExecutionRecord{}
	}
	return cloneExecutionRecord(*s.record)
}

func cloneExecutionRecord(record ports.ExecutionRecord) ports.ExecutionRecord {
	clone := record
	if record.Receipt != nil {
		receipt := cloneActionReceipt(*record.Receipt)
		clone.Receipt = &receipt
	}
	return clone
}

type recordingAuditor struct {
	mu     sync.Mutex
	events []model.AuditEvent
}

func TestGetRemediationResultIsExactReadOnlyAndIgnoresGrantFreshness(t *testing.T) {
	t.Parallel()
	issuedAt := time.Date(2026, 9, 30, 13, 0, 0, 0, time.UTC)
	grant := signedRestartGrant(t, issuedAt, false)
	receipt := model.ActionReceipt{
		SchemaVersion: model.SchemaVersionV1, ReceiptID: "receipt-lookup",
		GrantID: grant.GrantID, IncidentID: grant.IncidentID, Action: grant.Action,
		Outcome: model.ActionSucceeded, StartedAt: issuedAt, CompletedAt: issuedAt.Add(time.Second),
		AuditRef: "audit-lookup",
	}
	completedAt := receipt.CompletedAt
	store := &memoryExecutionStore{now: grant.ExpiresAt.Add(time.Hour), record: &ports.ExecutionRecord{
		Scope: ports.ExecutionScopeMCPAction, Grant: grant, Status: ports.ExecutionCompleted,
		Receipt: &receipt, StartedAt: issuedAt, CompletedAt: &completedAt,
		RetentionUntil: grant.ExpiresAt.Add(24 * time.Hour), Version: 2,
	}}
	client := &Client{ExecutionStore: store}

	result, err := client.GetRemediationResult(context.Background(), toolapi.GetRemediationResultInput{Grant: grant})
	if err != nil {
		t.Fatalf("GetRemediationResult() expired exact lookup error = %v", err)
	}
	if result.State != toolapi.RemediationCompleted || result.Receipt == nil || !reflect.DeepEqual(*result.Receipt, receipt) {
		t.Fatalf("GetRemediationResult() = %#v, want exact completed receipt", result)
	}
	before := store.snapshot()
	tampered := grant
	replacement := "A"
	if strings.HasPrefix(tampered.Signature.Value, replacement) {
		replacement = "B"
	}
	tampered.Signature.Value = replacement + tampered.Signature.Value[1:]
	if _, err := client.GetRemediationResult(context.Background(), toolapi.GetRemediationResultInput{Grant: tampered}); err == nil {
		t.Fatal("GetRemediationResult() accepted a different signed fingerprint")
	}
	after := store.snapshot()
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("read-only lookup mutated execution store: before=%#v after=%#v", before, after)
	}
}

func TestGetRemediationResultReturnsOnlyBoundedStateForNonCompletedRows(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 13, 30, 0, 0, time.UTC)
	grant := signedRestartGrant(t, now, false)
	for _, test := range []struct {
		name       string
		status     ports.ExecutionStatus
		want       toolapi.RemediationExecutionState
		withRecord bool
	}{
		{name: "not found", want: toolapi.RemediationNotFound},
		{name: "reserved", status: ports.ExecutionReserved, want: toolapi.RemediationReserved, withRecord: true},
		{name: "uncertain", status: ports.ExecutionUncertain, want: toolapi.RemediationUncertain, withRecord: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			store := &memoryExecutionStore{now: now}
			if test.withRecord {
				store.record = &ports.ExecutionRecord{
					Scope: ports.ExecutionScopeMCPAction, Grant: grant, Status: test.status,
					StartedAt: now, RetentionUntil: grant.ExpiresAt.Add(24 * time.Hour), Version: 1,
				}
			}
			client := &Client{ExecutionStore: store}
			result, err := client.GetRemediationResult(context.Background(), toolapi.GetRemediationResultInput{Grant: grant})
			if err != nil {
				t.Fatal(err)
			}
			if result.State != test.want || result.Receipt != nil {
				t.Fatalf("GetRemediationResult() = %#v, want state %q without receipt", result, test.want)
			}
			if snapshot := store.snapshot(); test.withRecord && snapshot.Version != 1 {
				t.Fatalf("lookup mutated durable record: %#v", snapshot)
			}
		})
	}
}

func (a *recordingAuditor) Record(_ context.Context, event model.AuditEvent) error {
	if err := event.Validate(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
	return nil
}

func (a *recordingAuditor) hasDecision(decision string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, event := range a.events {
		if event.Decision == decision {
			return true
		}
	}
	return false
}

func TestRestartDryRunCarriesResourceVersionAndIsIdempotent(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	replicas := int32(1)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "demo-api", Namespace: "outage-arena", ResourceVersion: "rv-7"},
		Spec:       appsv1.DeploymentSpec{Replicas: &replicas},
		Status: appsv1.DeploymentStatus{
			ReadyReplicas: 0, AvailableReplicas: 0, UnavailableReplicas: 1,
		},
	}
	kube := fake.NewSimpleClientset(deployment)
	patchCalls := 0
	kube.PrependReactor("patch", "deployments", func(action ktesting.Action) (bool, runtime.Object, error) {
		patchCalls++
		patchAction, ok := action.(ktesting.PatchActionImpl)
		if !ok {
			t.Fatalf("unexpected patch action type %T", action)
		}
		if len(patchAction.GetPatchOptions().DryRun) != 1 || patchAction.GetPatchOptions().DryRun[0] != metav1.DryRunAll {
			t.Fatalf("Kubernetes dry-run option missing: %#v", patchAction.GetPatchOptions())
		}
		var patch struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
			} `json:"metadata"`
			Spec struct {
				Template struct {
					Metadata struct {
						Annotations map[string]string `json:"annotations"`
					} `json:"metadata"`
				} `json:"template"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(patchAction.GetPatch(), &patch); err != nil {
			t.Fatal(err)
		}
		if patch.Metadata.ResourceVersion != "rv-7" {
			t.Fatalf("restart patch omitted resourceVersion precondition: %#v", patch)
		}
		if patch.Spec.Template.Metadata.Annotations["aegissre.io/grant-id"] != "grant-1" {
			t.Fatalf("restart patch omitted grant audit annotation: %#v", patch)
		}
		return true, deployment.DeepCopy(), nil
	})

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := security.NewVerifier(publicKey, "key-1", model.AgentMCPAction)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := security.NewPolicy(security.PolicyConfig{
		AllowedNamespaces: []string{"outage-arena"},
		AllowedActions:    []model.ActionKind{model.ActionRestartDeployment},
		MinimumConfidence: 0.8, MinimumEvidence: 1,
		MaximumGrantTTL: 2 * time.Minute, RequireDryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	grant := model.DelegationGrant{
		SchemaVersion: model.SchemaVersionV1, GrantID: "grant-1", Issuer: model.AgentMonitor,
		Audiences:  []model.AgentID{model.AgentOperator, model.AgentMCPAction},
		IncidentID: "incident-1", DiagnosisReportID: "diagnosis-1",
		DiagnosisDigest:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		DiagnosisConfidence: 0.9, EvidenceIDs: []string{"evidence-1"}, ProposalID: "proposal-1",
		Action: model.ActionSpec{
			Kind: model.ActionRestartDeployment,
			Target: model.ResourceTarget{
				APIVersion: "apps/v1", Kind: "Deployment", Namespace: "outage-arena", Name: "demo-api",
			},
		},
		Preconditions: model.ActionPreconditions{ResourceVersion: "rv-7", ExpectedReplicas: &replicas},
		DryRun:        true, IdempotencyKey: "incident-1:proposal-1",
		IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(2 * time.Minute),
	}
	grant, err = security.SignGrant(privateKey, "key-1", grant)
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{
		Kube: kube, Namespace: "outage-arena", Verifier: verifier, Policy: policy,
		Replay: security.NewMemoryReplayGuard(), Clock: adapterClock{now.Add(time.Second)}, IDs: adapterIDs{},
		receipts: make(map[string]model.ActionReceipt),
	}
	input := toolapi.ExecuteRemediationInput{Grant: grant, DryRun: true}
	first, err := client.ExecuteRemediation(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.ExecuteRemediation(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if patchCalls != 1 {
		t.Fatalf("idempotent retry executed %d patches", patchCalls)
	}
	if first.Receipt.Outcome != model.ActionDryRun || second.Receipt.ReceiptID != first.Receipt.ReceiptID {
		t.Fatalf("unexpected receipts: first=%#v second=%#v", first.Receipt, second.Receipt)
	}
}

func TestScalePatchCarriesGrantProvenance(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 13, 0, 0, 0, time.UTC)
	beforeReplicas := int32(1)
	requestedReplicas := int32(2)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "demo-api", Namespace: "outage-arena", ResourceVersion: "rv-8",
		},
		Spec: appsv1.DeploymentSpec{Replicas: &beforeReplicas},
		Status: appsv1.DeploymentStatus{
			ObservedGeneration: 1, AvailableReplicas: 0, UnavailableReplicas: 1,
		},
	}
	kube := fake.NewSimpleClientset(deployment)
	patchCalls := 0
	kube.PrependReactor("patch", "deployments", func(action ktesting.Action) (bool, runtime.Object, error) {
		patchCalls++
		patchAction, ok := action.(ktesting.PatchActionImpl)
		if !ok {
			t.Fatalf("unexpected patch action type %T", action)
		}
		var patch struct {
			Metadata struct {
				ResourceVersion string            `json:"resourceVersion"`
				Annotations     map[string]string `json:"annotations"`
			} `json:"metadata"`
			Spec struct {
				Replicas int32 `json:"replicas"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(patchAction.GetPatch(), &patch); err != nil {
			t.Fatal(err)
		}
		if patch.Metadata.ResourceVersion != "rv-8" ||
			patch.Metadata.Annotations["aegissre.io/grant-id"] != "grant-scale" ||
			patch.Spec.Replicas != requestedReplicas {
			t.Fatalf("scale patch omitted an exact precondition or provenance marker: %#v", patch)
		}
		updated := deployment.DeepCopy()
		updated.ResourceVersion = "rv-9"
		updated.Spec.Replicas = &requestedReplicas
		updated.Annotations = map[string]string{"aegissre.io/grant-id": "grant-scale"}
		return true, updated, nil
	})

	grant, verifier, policy := signedScaleGrant(t, now)
	client := &Client{
		Kube: kube, Namespace: "outage-arena", Verifier: verifier, Policy: policy,
		Replay: security.NewMemoryReplayGuard(), Clock: adapterClock{now.Add(time.Second)}, IDs: adapterIDs{},
		AllowMutations: true, receipts: make(map[string]model.ActionReceipt),
	}
	output, err := client.ExecuteRemediation(context.Background(), toolapi.ExecuteRemediationInput{Grant: grant})
	if err != nil {
		t.Fatal(err)
	}
	if patchCalls != 1 || output.Receipt.Outcome != model.ActionSucceeded {
		t.Fatalf("unexpected scale execution: calls=%d receipt=%#v", patchCalls, output.Receipt)
	}
}

func TestDurableExecutionReturnsExactReceiptAfterExpiryAndRestart(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 14, 0, 0, 0, time.UTC)
	beforeReplicas := int32(1)
	requestedReplicas := int32(2)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "demo-api", Namespace: "outage-arena", ResourceVersion: "rv-8"},
		Spec:       appsv1.DeploymentSpec{Replicas: &beforeReplicas},
	}
	kube := fake.NewSimpleClientset(deployment)
	store := &memoryExecutionStore{now: now.Add(time.Second)}
	audit := &recordingAuditor{}
	patchCalls := 0
	kube.PrependReactor("patch", "deployments", func(action ktesting.Action) (bool, runtime.Object, error) {
		patchCalls++
		if record := store.snapshot(); record.Status != ports.ExecutionReserved || record.Scope != ports.ExecutionScopeMCPAction {
			t.Fatalf("Kubernetes patch ran before the durable intent reservation: %#v", record)
		}
		if !audit.hasDecision("execution_reserved") {
			t.Fatal("Kubernetes patch ran before the durable audit intent")
		}
		updated := deployment.DeepCopy()
		updated.ResourceVersion = "rv-9"
		updated.Spec.Replicas = &requestedReplicas
		updated.Annotations = map[string]string{actionGrantAnnotation: "grant-scale"}
		return true, updated, nil
	})

	grant, verifier, policy := signedScaleGrant(t, now)
	client := &Client{
		Kube: kube, Namespace: "outage-arena", Verifier: verifier, Policy: policy,
		Clock: adapterClock{now.Add(time.Second)}, Audit: audit, AllowMutations: true,
		ExecutionStore: store, InstanceID: "action-mcp-1", ExecutionLease: 30 * time.Second,
	}
	first, err := client.ExecuteRemediation(context.Background(), toolapi.ExecuteRemediationInput{Grant: grant})
	if err != nil {
		t.Fatal(err)
	}
	if patchCalls != 1 || store.snapshot().Status != ports.ExecutionCompleted {
		t.Fatalf("durable execution was not completed exactly once: calls=%d record=%#v", patchCalls, store.snapshot())
	}

	// Simulate a new process after expiry. A completed exact fingerprint is a
	// receipt lookup and therefore needs neither a live verifier nor Kubernetes.
	store.now = grant.ExpiresAt.Add(time.Minute)
	restarted := &Client{
		Namespace: "outage-arena", Clock: adapterClock{store.now},
		ExecutionStore: store, ExecutionLease: 20 * time.Second, RequestTimeout: 10 * time.Second,
	}
	second, err := restarted.ExecuteRemediation(context.Background(), toolapi.ExecuteRemediationInput{Grant: grant})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Receipt, second.Receipt) {
		t.Fatalf("expired retry did not return the exact durable receipt:\nfirst=%#v\nsecond=%#v", first.Receipt, second.Receipt)
	}
	if patchCalls != 1 {
		t.Fatalf("expired completed retry issued another patch: %d", patchCalls)
	}
}

func TestDurableExecutionRejectsUnsafeLeaseWindowBeforeReservation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 14, 30, 0, 0, time.UTC)
	grant, verifier, policy := signedScaleGrant(t, now)
	store := &memoryExecutionStore{now: now.Add(time.Second)}
	client := &Client{
		Kube: fake.NewSimpleClientset(), Namespace: "outage-arena", Verifier: verifier, Policy: policy,
		Clock: adapterClock{now.Add(time.Second)}, Audit: &recordingAuditor{}, AllowMutations: true,
		ExecutionStore: store, InstanceID: "action-mcp-unsafe-window",
		ExecutionLease: 20 * time.Second, RequestTimeout: 10 * time.Second,
	}

	if _, err := client.ExecuteRemediation(context.Background(), toolapi.ExecuteRemediationInput{Grant: grant}); err == nil {
		t.Fatal("ExecuteRemediation() unsafe lease error = nil")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeInvalidInput {
		t.Fatalf("ExecuteRemediation() unsafe lease error = %v, want %s", err, model.CodeInvalidInput)
	}
	if record := store.snapshot(); record.Status != "" {
		t.Fatalf("unsafe lease created durable reservation: %#v", record)
	}
}

func TestRecoveredRestartLeaseReconcilesMarkerWithoutRepeatingTimestamp(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 15, 0, 0, 0, time.UTC)
	grant := signedRestartGrant(t, now, false)
	replicas := int32(1)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "demo-api", Namespace: "outage-arena", ResourceVersion: "rv-12"},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
				actionGrantAnnotation: grant.GrantID,
				restartTimeAnnotation: "2026-09-30T15:00:02Z",
			}}},
		},
	}
	kube := fake.NewSimpleClientset(deployment)
	patchCalls := 0
	kube.PrependReactor("patch", "deployments", func(ktesting.Action) (bool, runtime.Object, error) {
		patchCalls++
		return true, nil, nil
	})
	recoveryTime := grant.ExpiresAt.Add(time.Minute)
	store := &memoryExecutionStore{
		now: recoveryTime,
		record: &ports.ExecutionRecord{
			Scope: ports.ExecutionScopeMCPAction, Grant: grant, Status: ports.ExecutionReserved,
			LeaseOwner: "dead-instance", LeaseToken: "dead-lease", LeaseUntil: now.Add(2 * time.Second),
			StartedAt: now.Add(time.Second), RetentionUntil: grant.ExpiresAt.Add(24 * time.Hour), Version: 1,
		},
	}
	client := &Client{
		Kube: kube, Namespace: "outage-arena", Clock: adapterClock{recoveryTime},
		Audit: &recordingAuditor{}, AllowMutations: true,
		ExecutionStore: store, InstanceID: "action-mcp-restarted", ExecutionLease: 30 * time.Second,
	}
	output, err := client.ExecuteRemediation(context.Background(), toolapi.ExecuteRemediationInput{Grant: grant})
	if err != nil {
		t.Fatal(err)
	}
	if patchCalls != 0 {
		t.Fatalf("recovered restart lease repeated a timestamp patch %d times", patchCalls)
	}
	if output.Receipt.Outcome != model.ActionSucceeded || store.snapshot().Status != ports.ExecutionCompleted {
		t.Fatalf("applied restart marker was not completed durably: %#v", output.Receipt)
	}
}

func TestRecoveredLeaseRetriesOnceWhenCurrentlyAuthorizedWithPriorMarkerAndUnchangedPrecondition(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 16, 0, 0, 0, time.UTC)
	grant, verifier, policy := signedScaleGrant(t, now)
	beforeReplicas := int32(1)
	requestedReplicas := int32(2)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "demo-api", Namespace: "outage-arena", ResourceVersion: "rv-8",
			Annotations: map[string]string{actionGrantAnnotation: "older-unrelated-grant"},
		},
		Spec: appsv1.DeploymentSpec{Replicas: &beforeReplicas},
	}
	kube := fake.NewSimpleClientset(deployment)
	patchCalls := 0
	kube.PrependReactor("patch", "deployments", func(ktesting.Action) (bool, runtime.Object, error) {
		patchCalls++
		updated := deployment.DeepCopy()
		updated.ResourceVersion = "rv-9"
		updated.Spec.Replicas = &requestedReplicas
		updated.Annotations = map[string]string{actionGrantAnnotation: grant.GrantID}
		return true, updated, nil
	})
	// The dead owner reserved the grant but crashed before issuing its patch.
	// The older marker was part of the exact resourceVersion the Monitor signed.
	recoveryTime := now.Add(time.Minute)
	store := expiredReservation(grant, recoveryTime, 1)
	client := &Client{
		Kube: kube, Namespace: "outage-arena", Verifier: verifier, Policy: policy,
		Clock: adapterClock{recoveryTime},
		Audit: &recordingAuditor{}, AllowMutations: true,
		ExecutionStore: store, InstanceID: "action-mcp-retry", ExecutionLease: 30 * time.Second,
	}
	output, err := client.ExecuteRemediation(context.Background(), toolapi.ExecuteRemediationInput{Grant: grant})
	if err != nil {
		t.Fatal(err)
	}
	if patchCalls != 1 || output.Receipt.Outcome != model.ActionSucceeded || store.snapshot().Status != ports.ExecutionCompleted {
		t.Fatalf("safe recovered retry did not complete exactly once: calls=%d receipt=%#v record=%#v", patchCalls, output.Receipt, store.snapshot())
	}
}

func TestRecoveredLeaseMarksLateAcceptanceAmbiguityWithoutCurrentAuthorization(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 16, 30, 0, 0, time.UTC)
	grant, verifier, policy := signedScaleGrant(t, now)
	deniedPolicy, err := security.NewPolicy(security.PolicyConfig{
		AllowedNamespaces: []string{"outage-arena"},
		AllowedActions:    []model.ActionKind{model.ActionScaleDeployment},
		MinimumConfidence: 0.8, MinimumEvidence: 1,
		MaximumGrantTTL: 2 * time.Minute, RequireDryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		recoveryTime   time.Time
		policy         ports.GrantAuthorizer
		allowMutations bool
		wantCode       model.ErrorCode
	}{
		{
			name: "expired grant", recoveryTime: grant.ExpiresAt.Add(time.Minute),
			policy: policy, allowMutations: true, wantCode: model.CodeGrantExpired,
		},
		{
			name: "currently denied by policy", recoveryTime: now.Add(time.Minute),
			policy: deniedPolicy, allowMutations: true, wantCode: model.CodePolicyDenied,
		},
		{
			name: "mutation switch disabled", recoveryTime: now.Add(time.Minute),
			policy: policy, allowMutations: false, wantCode: model.CodePolicyDenied,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			beforeReplicas := int32(1)
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name: "demo-api", Namespace: "outage-arena", ResourceVersion: "rv-8",
					Annotations: map[string]string{actionGrantAnnotation: "older-unrelated-grant"},
				},
				Spec: appsv1.DeploymentSpec{Replicas: &beforeReplicas},
			}
			kube := fake.NewSimpleClientset(deployment)
			patchCalls := 0
			kube.PrependReactor("patch", "deployments", func(ktesting.Action) (bool, runtime.Object, error) {
				patchCalls++
				return true, nil, nil
			})
			store := expiredReservation(grant, test.recoveryTime, 1)
			client := &Client{
				Kube: kube, Namespace: "outage-arena", Verifier: verifier, Policy: test.policy,
				Clock: adapterClock{test.recoveryTime}, Audit: &recordingAuditor{}, AllowMutations: test.allowMutations,
				ExecutionStore: store, InstanceID: "action-mcp-unauthorized-retry", ExecutionLease: 30 * time.Second,
			}

			_, err := client.ExecuteRemediation(context.Background(), toolapi.ExecuteRemediationInput{Grant: grant})
			if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeExecutionFailed {
				t.Fatalf("recovered unauthorized retry error = %v, want %s", err, model.CodeExecutionFailed)
			}
			if patchCalls != 0 {
				t.Fatalf("recovered unauthorized retry issued %d Kubernetes patches", patchCalls)
			}
			if record := store.snapshot(); record.Status != ports.ExecutionUncertain || record.Receipt != nil || record.ErrorCode != model.CodeExecutionFailed {
				t.Fatalf("recovered unauthorized retry did not preserve late-acceptance ambiguity (denial %s): %#v", test.wantCode, record)
			}
		})
	}
}

func TestRecoveredLeaseFailsClosedOnDivergenceOrExhaustedRetry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 17, 0, 0, 0, time.UTC)
	grant, verifier, policy := signedScaleGrant(t, now)
	replicas := int32(1)
	tests := []struct {
		name            string
		resourceVersion string
		storedVersion   int64
	}{
		{name: "resource version diverged", resourceVersion: "rv-9", storedVersion: 1},
		{name: "bounded retry exhausted", resourceVersion: "rv-8", storedVersion: 2},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "demo-api", Namespace: "outage-arena", ResourceVersion: test.resourceVersion},
				Spec:       appsv1.DeploymentSpec{Replicas: &replicas},
			}
			kube := fake.NewSimpleClientset(deployment)
			patchCalls := 0
			kube.PrependReactor("patch", "deployments", func(ktesting.Action) (bool, runtime.Object, error) {
				patchCalls++
				return true, nil, nil
			})
			recoveryTime := now.Add(time.Minute)
			store := expiredReservation(grant, recoveryTime, test.storedVersion)
			client := &Client{
				Kube: kube, Namespace: "outage-arena", Verifier: verifier, Policy: policy,
				Clock: adapterClock{recoveryTime},
				Audit: &recordingAuditor{}, AllowMutations: true,
				ExecutionStore: store, InstanceID: "action-mcp-uncertain", ExecutionLease: 30 * time.Second,
			}
			_, err := client.ExecuteRemediation(context.Background(), toolapi.ExecuteRemediationInput{Grant: grant})
			if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeExecutionFailed {
				t.Fatalf("unsafe recovery returned %v, want %s", err, model.CodeExecutionFailed)
			}
			if patchCalls != 0 {
				t.Fatalf("unsafe recovery issued %d patches", patchCalls)
			}
			if record := store.snapshot(); record.Status != ports.ExecutionUncertain || record.ErrorCode != model.CodeExecutionFailed {
				t.Fatalf("unsafe recovery was not made durably uncertain: %#v", record)
			}
		})
	}
}

func TestAmbiguousPatchResponseReconcilesMarkerOrMarksUncertain(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 17, 30, 0, 0, time.UTC)
	grant, verifier, policy := signedScaleGrant(t, now)
	beforeReplicas := int32(1)
	requestedReplicas := int32(2)
	tests := []struct {
		name               string
		stampGrantMarker   bool
		wantStatus         ports.ExecutionStatus
		wantErrCode        model.ErrorCode
		wantReceiptOutcome model.ActionOutcome
	}{
		{
			name: "committed marker proves success", stampGrantMarker: true,
			wantStatus: ports.ExecutionCompleted, wantReceiptOutcome: model.ActionSucceeded,
		},
		{
			name: "diverged object is uncertain", stampGrantMarker: false,
			wantStatus: ports.ExecutionUncertain, wantErrCode: model.CodeExecutionFailed,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "demo-api", Namespace: "outage-arena", ResourceVersion: "rv-8"},
				Spec:       appsv1.DeploymentSpec{Replicas: &beforeReplicas},
			}
			kube := fake.NewSimpleClientset(deployment)
			patchCalls := 0
			kube.PrependReactor("patch", "deployments", func(ktesting.Action) (bool, runtime.Object, error) {
				patchCalls++
				observed := deployment.DeepCopy()
				observed.ResourceVersion = "rv-9"
				if test.stampGrantMarker {
					observed.Spec.Replicas = &requestedReplicas
					observed.Annotations = map[string]string{actionGrantAnnotation: grant.GrantID}
				}
				if err := kube.Tracker().Update(
					appsv1.SchemeGroupVersion.WithResource("deployments"), observed, "outage-arena",
				); err != nil {
					t.Fatalf("update fake Kubernetes tracker: %v", err)
				}
				return true, nil, errors.New("simulated lost patch response")
			})
			store := &memoryExecutionStore{now: now.Add(time.Second)}
			client := &Client{
				Kube: kube, Namespace: "outage-arena", Verifier: verifier, Policy: policy,
				Clock: adapterClock{now.Add(time.Second)}, Audit: &recordingAuditor{}, AllowMutations: true,
				ExecutionStore: store, InstanceID: "action-mcp-patch-error", ExecutionLease: 30 * time.Second,
			}
			output, err := client.ExecuteRemediation(context.Background(), toolapi.ExecuteRemediationInput{Grant: grant})
			if test.wantErrCode == "" {
				if err != nil || output.Receipt.Outcome != test.wantReceiptOutcome {
					t.Fatalf("provably applied patch was not completed: output=%#v err=%v", output, err)
				}
			} else if code, ok := model.ErrorCodeOf(err); !ok || code != test.wantErrCode {
				t.Fatalf("ambiguous patch returned %v, want %s", err, test.wantErrCode)
			}
			if patchCalls != 1 || store.snapshot().Status != test.wantStatus {
				t.Fatalf("unexpected patch reconciliation: calls=%d record=%#v", patchCalls, store.snapshot())
			}
		})
	}
}

func TestDurableExecutionSerializesConcurrentCallers(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 18, 0, 0, 0, time.UTC)
	beforeReplicas := int32(1)
	requestedReplicas := int32(2)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "demo-api", Namespace: "outage-arena", ResourceVersion: "rv-8"},
		Spec:       appsv1.DeploymentSpec{Replicas: &beforeReplicas},
	}
	kube := fake.NewSimpleClientset(deployment)
	patchStarted := make(chan struct{})
	releasePatch := make(chan struct{})
	patchCalls := 0
	kube.PrependReactor("patch", "deployments", func(ktesting.Action) (bool, runtime.Object, error) {
		patchCalls++
		close(patchStarted)
		<-releasePatch
		updated := deployment.DeepCopy()
		updated.ResourceVersion = "rv-9"
		updated.Spec.Replicas = &requestedReplicas
		updated.Annotations = map[string]string{actionGrantAnnotation: "grant-scale"}
		return true, updated, nil
	})
	grant, verifier, policy := signedScaleGrant(t, now)
	store := &memoryExecutionStore{now: now.Add(time.Second)}
	audit := &recordingAuditor{}
	newClient := func(instance string) *Client {
		return &Client{
			Kube: kube, Namespace: "outage-arena", Verifier: verifier, Policy: policy,
			Clock: adapterClock{now.Add(time.Second)}, Audit: audit, AllowMutations: true,
			ExecutionStore: store, InstanceID: instance, ExecutionLease: 30 * time.Second,
		}
	}
	type result struct {
		output toolapi.ExecuteRemediationOutput
		err    error
	}
	firstResult := make(chan result, 1)
	go func() {
		output, err := newClient("action-mcp-a").ExecuteRemediation(
			context.Background(), toolapi.ExecuteRemediationInput{Grant: grant},
		)
		firstResult <- result{output: output, err: err}
	}()
	select {
	case <-patchStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("first caller did not reach the Kubernetes patch")
	}
	_, secondErr := newClient("action-mcp-b").ExecuteRemediation(
		context.Background(), toolapi.ExecuteRemediationInput{Grant: grant},
	)
	if code, ok := model.ErrorCodeOf(secondErr); !ok || code != model.CodeReplayedGrant {
		t.Fatalf("concurrent caller returned %v, want %s", secondErr, model.CodeReplayedGrant)
	}
	close(releasePatch)
	first := <-firstResult
	if first.err != nil || first.output.Receipt.Outcome != model.ActionSucceeded {
		t.Fatalf("lease owner did not complete: output=%#v err=%v", first.output, first.err)
	}
	if patchCalls != 1 {
		t.Fatalf("concurrent callers issued %d Kubernetes patches", patchCalls)
	}
}

func TestScaleStatusRequiresGrantProvenance(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 13, 30, 0, 0, time.UTC)
	requestedReplicas := int32(2)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "demo-api", Namespace: "outage-arena", ResourceVersion: "rv-9", Generation: 2,
		},
		Spec: appsv1.DeploymentSpec{Replicas: &requestedReplicas},
		Status: appsv1.DeploymentStatus{
			ObservedGeneration: 2, ReadyReplicas: 2, AvailableReplicas: 2,
		},
	}
	kube := fake.NewSimpleClientset(deployment)
	grant, verifier, policy := signedScaleGrant(t, now)
	client := &Client{
		Kube: kube, Namespace: "outage-arena", Verifier: verifier, Policy: policy,
		Clock: adapterClock{now.Add(time.Second)},
	}

	status, err := client.GetRemediationStatus(context.Background(), toolapi.GetRemediationStatusInput{Grant: grant})
	if err != nil {
		t.Fatal(err)
	}
	if status.Satisfied {
		t.Fatal("matching replica count without grant provenance was accepted as completed remediation")
	}

	updated, err := kube.AppsV1().Deployments("outage-arena").Get(context.Background(), "demo-api", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	updated.Annotations = map[string]string{"aegissre.io/grant-id": grant.GrantID}
	if _, err := kube.AppsV1().Deployments("outage-arena").Update(context.Background(), updated, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	status, err = client.GetRemediationStatus(context.Background(), toolapi.GetRemediationStatusInput{Grant: grant})
	if err != nil {
		t.Fatal(err)
	}
	if !status.Satisfied {
		t.Fatalf("exact scale postcondition with grant provenance was not recognized: %#v", status)
	}
}

func TestGetPodLogsRejectsInvalidContainerBeforeKubernetesCall(t *testing.T) {
	t.Parallel()
	client := &Client{Namespace: "outage-arena"}
	_, err := client.GetPodLogs(context.Background(), toolapi.GetPodLogsInput{
		Namespace: "outage-arena", Pod: "demo-api-123", Container: "invalid.container",
	})
	if err == nil {
		t.Fatal("invalid container name reached the Kubernetes client")
	}
}

func TestPodSnapshotBoundsContainerStatusMessage(t *testing.T) {
	t.Parallel()
	message := make([]byte, 2048)
	for index := range message {
		message[index] = 'x'
	}
	snapshot := podSnapshot(&corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
		Name: "app", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Message: string(message)}},
	}}}})
	if len(snapshot.Containers) != 1 || len(snapshot.Containers[0].Message) != 1024 {
		t.Fatalf("container status message was not bounded: %#v", snapshot.Containers)
	}
}

func signedScaleGrant(t *testing.T, now time.Time) (model.DelegationGrant, *security.Verifier, *security.Policy) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := security.NewVerifier(publicKey, "key-scale", model.AgentMCPAction)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := security.NewPolicy(security.PolicyConfig{
		AllowedNamespaces: []string{"outage-arena"},
		AllowedActions:    []model.ActionKind{model.ActionScaleDeployment},
		MinimumConfidence: 0.8, MinimumEvidence: 1,
		MaximumGrantTTL: 2 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	expectedReplicas := int32(1)
	requestedReplicas := int32(2)
	grant := model.DelegationGrant{
		SchemaVersion: model.SchemaVersionV1, GrantID: "grant-scale", Issuer: model.AgentMonitor,
		Audiences:  []model.AgentID{model.AgentOperator, model.AgentMCPAction},
		IncidentID: "incident-scale", DiagnosisReportID: "diagnosis-scale",
		DiagnosisDigest:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		DiagnosisConfidence: 0.9, EvidenceIDs: []string{"evidence-scale"}, ProposalID: "proposal-scale",
		Action: model.ActionSpec{
			Kind: model.ActionScaleDeployment,
			Target: model.ResourceTarget{
				APIVersion: "apps/v1", Kind: "Deployment", Namespace: "outage-arena", Name: "demo-api",
			},
			Parameters: model.ActionParameters{Replicas: &requestedReplicas},
		},
		Preconditions:  model.ActionPreconditions{ResourceVersion: "rv-8", ExpectedReplicas: &expectedReplicas},
		IdempotencyKey: "incident-scale:proposal-scale",
		IssuedAt:       now, NotBefore: now, ExpiresAt: now.Add(2 * time.Minute),
	}
	grant, err = security.SignGrant(privateKey, "key-scale", grant)
	if err != nil {
		t.Fatal(err)
	}
	return grant, verifier, policy
}

func signedRestartGrant(t *testing.T, now time.Time, dryRun bool) model.DelegationGrant {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	replicas := int32(1)
	grant := model.DelegationGrant{
		SchemaVersion: model.SchemaVersionV1, GrantID: "grant-restart", Issuer: model.AgentMonitor,
		Audiences:  []model.AgentID{model.AgentOperator, model.AgentMCPAction},
		IncidentID: "incident-restart", DiagnosisReportID: "diagnosis-restart",
		DiagnosisDigest:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		DiagnosisConfidence: 0.9, EvidenceIDs: []string{"evidence-restart"}, ProposalID: "proposal-restart",
		Action: model.ActionSpec{
			Kind: model.ActionRestartDeployment,
			Target: model.ResourceTarget{
				APIVersion: "apps/v1", Kind: "Deployment", Namespace: "outage-arena", Name: "demo-api",
			},
		},
		Preconditions:  model.ActionPreconditions{ResourceVersion: "rv-11", ExpectedReplicas: &replicas},
		DryRun:         dryRun,
		IdempotencyKey: "incident-restart:proposal-restart",
		IssuedAt:       now, NotBefore: now, ExpiresAt: now.Add(2 * time.Minute),
	}
	grant, err = security.SignGrant(privateKey, "key-restart", grant)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func expiredReservation(grant model.DelegationGrant, recoveryTime time.Time, version int64) *memoryExecutionStore {
	startedAt := grant.IssuedAt.Add(time.Second)
	return &memoryExecutionStore{
		now: recoveryTime,
		record: &ports.ExecutionRecord{
			Scope: ports.ExecutionScopeMCPAction, Grant: grant, Status: ports.ExecutionReserved,
			LeaseOwner: "dead-instance", LeaseToken: "dead-lease", LeaseUntil: startedAt.Add(time.Second),
			StartedAt: startedAt, RetentionUntil: grant.ExpiresAt.Add(24 * time.Hour), Version: version,
		},
	}
}
