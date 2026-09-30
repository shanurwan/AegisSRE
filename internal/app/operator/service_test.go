package operator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/security"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

func TestExecuteRejectsUnsignedAndWrongSignatureBeforeActionTool(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 5, 0, 0, 0, time.UTC)
	trustedPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	trustedPublic := trustedPrivate.Public().(ed25519.PublicKey)
	attackerPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))

	unsigned := operatorGrant(now)
	wrongSignature, err := security.SignGrant(attackerPrivate, "operator-test-key", operatorGrant(now))
	if err != nil {
		t.Fatalf("SignGrant(attacker) error = %v", err)
	}

	tests := []struct {
		name     string
		grant    model.DelegationGrant
		wantCode model.ErrorCode
	}{
		{name: "unsigned", grant: unsigned, wantCode: model.CodeDelegationRequired},
		{name: "wrong signature", grant: wrongSignature, wantCode: model.CodeInvalidSignature},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tools := &operatorToolFake{now: now}
			service := newOperatorService(t, now, trustedPublic, tools)

			_, err := service.Execute(context.Background(), tt.grant)
			if err == nil {
				t.Fatal("Execute() error = nil, want rejection")
			}
			if code, ok := model.ErrorCodeOf(err); !ok || code != tt.wantCode {
				t.Fatalf("Execute() error code = %q, %v, want %q", code, err, tt.wantCode)
			}
			if tools.calls != 0 {
				t.Fatalf("action tool calls = %d, want 0", tools.calls)
			}
		})
	}
}

func TestExecuteReturnsCachedReceiptWithoutSecondActionToolCall(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 5, 30, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	grant, err := security.SignGrant(privateKey, "operator-test-key", operatorGrant(now))
	if err != nil {
		t.Fatalf("SignGrant() error = %v", err)
	}
	tools := &operatorToolFake{now: now}
	service := newOperatorService(t, now, publicKey, tools)

	if _, err := service.Execute(context.Background(), grant); err != nil {
		t.Fatalf("first Execute() error = %v", err)
	}
	if tools.calls != 1 {
		t.Fatalf("action tool calls after first execution = %d, want 1", tools.calls)
	}

	second, err := service.Execute(context.Background(), grant)
	if err != nil {
		t.Fatalf("second Execute() error = %v", err)
	}
	if second.ReceiptID != "receipt-1" {
		t.Fatalf("second Execute() did not return cached receipt: %#v", second)
	}
	if tools.calls != 1 {
		t.Fatalf("action tool calls after replay = %d, want 1", tools.calls)
	}
}

func TestExecuteReplayedLiveGrantChecksStatusWithoutRepeatingMutation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 6, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	grant := operatorGrant(now)
	grant.DryRun = false
	grant, err := security.SignGrant(privateKey, "operator-test-key", grant)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := security.NewVerifier(publicKey, "operator-test-key", model.AgentOperator)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := security.NewPolicy(security.PolicyConfig{
		AllowedNamespaces: []string{"outage-arena"},
		AllowedActions:    []model.ActionKind{model.ActionRestartDeployment},
		MinimumConfidence: 0.8, MinimumEvidence: 1, MaximumGrantTTL: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	replay := security.NewMemoryReplayGuard()
	if err := replay.ConsumeGrant(grant, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	tools := &operatorToolFake{now: now.Add(time.Second), statusSatisfied: true}
	service := &Service{
		Tools: tools, Verifier: verifier, Policy: policy, Replay: replay,
		Clock: operatorClock{now: now.Add(time.Second)}, IDs: &operatorIDs{},
	}
	receipt, err := service.Execute(context.Background(), grant)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Outcome != model.ActionSucceeded || tools.calls != 0 || tools.statusCalls != 1 {
		t.Fatalf("unsafe replay recovery: receipt=%#v execute=%d status=%d", receipt, tools.calls, tools.statusCalls)
	}
}

func TestExecuteReplayedGrantRejectsStatusForDifferentTarget(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 6, 15, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	grant := operatorGrant(now)
	grant.DryRun = false
	grant, err := security.SignGrant(privateKey, "operator-test-key", grant)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := security.NewVerifier(publicKey, "operator-test-key", model.AgentOperator)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := security.NewPolicy(security.PolicyConfig{
		AllowedNamespaces: []string{"outage-arena"},
		AllowedActions:    []model.ActionKind{model.ActionRestartDeployment},
		MinimumConfidence: 0.8, MinimumEvidence: 1, MaximumGrantTTL: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	replay := security.NewMemoryReplayGuard()
	if err := replay.ConsumeGrant(grant, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	tools := &operatorToolFake{
		now: now.Add(time.Second), statusSatisfied: true,
		statusTarget: &model.ResourceTarget{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "outage-arena", Name: "other-api"},
	}
	service := &Service{
		Tools: tools, Verifier: verifier, Policy: policy, Replay: replay,
		Clock: operatorClock{now: now.Add(time.Second)}, IDs: &operatorIDs{},
	}
	if _, err := service.Execute(context.Background(), grant); err == nil {
		t.Fatal("replay recovery accepted status for a different target")
	}
	if tools.calls != 0 || tools.statusCalls != 1 {
		t.Fatalf("unexpected tool calls: execute=%d status=%d", tools.calls, tools.statusCalls)
	}
}

func TestExecuteRejectsReceiptWithDifferentDryRunSemantics(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 6, 30, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	grant, err := security.SignGrant(privateKey, "operator-test-key", operatorGrant(now))
	if err != nil {
		t.Fatal(err)
	}
	falseValue := false
	tools := &operatorToolFake{now: now, outcome: model.ActionSucceeded, receiptDryRun: &falseValue}
	service := newOperatorService(t, now, publicKey, tools)
	_, err = service.Execute(context.Background(), grant)
	if err == nil {
		t.Fatal("receipt that changed dry-run semantics was accepted")
	}
	if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeExecutionFailed {
		t.Fatalf("unexpected error: %v", err)
	}
}

func newOperatorService(t *testing.T, now time.Time, publicKey ed25519.PublicKey, tools *operatorToolFake) *Service {
	t.Helper()
	verifier, err := security.NewVerifier(publicKey, "operator-test-key", model.AgentOperator)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	policy, err := security.NewPolicy(security.PolicyConfig{
		AllowedNamespaces: []string{"outage-arena"},
		AllowedActions:    []model.ActionKind{model.ActionRestartDeployment},
		MinimumConfidence: 0.8,
		MinimumEvidence:   1,
		MaximumGrantTTL:   5 * time.Minute,
		RequireDryRun:     true,
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	return &Service{
		Tools: tools, Verifier: verifier, Policy: policy, Replay: security.NewMemoryReplayGuard(),
		Clock: operatorClock{now: now}, IDs: &operatorIDs{},
	}
}

type operatorToolFake struct {
	calls           int
	statusCalls     int
	statusSatisfied bool
	outcome         model.ActionOutcome
	receiptDryRun   *bool
	statusTarget    *model.ResourceTarget
	now             time.Time
}

func (*operatorToolFake) Discover(context.Context) ([]string, error) {
	return []string{toolapi.ToolExecuteRemediation}, nil
}

func (f *operatorToolFake) Call(_ context.Context, name string, input, output any) error {
	if name == toolapi.ToolGetRemediationStatus {
		request, ok := input.(toolapi.GetRemediationStatusInput)
		if !ok {
			return fmt.Errorf("unexpected status input %T", input)
		}
		result, ok := output.(*toolapi.GetRemediationStatusOutput)
		if !ok {
			return fmt.Errorf("unexpected status output %T", output)
		}
		f.statusCalls++
		result.Satisfied = f.statusSatisfied
		target := request.Grant.Action.Target
		if f.statusTarget != nil {
			target = *f.statusTarget
		}
		result.Snapshot = toolapi.WorkloadSnapshot{
			Target: target, ResourceVersion: "rv-after",
			DesiredReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1,
		}
		return nil
	}
	if name != toolapi.ToolExecuteRemediation {
		return fmt.Errorf("unexpected tool %q", name)
	}
	request, ok := input.(toolapi.ExecuteRemediationInput)
	if !ok {
		return fmt.Errorf("unexpected remediation input %T", input)
	}
	result, ok := output.(*toolapi.ExecuteRemediationOutput)
	if !ok {
		return fmt.Errorf("unexpected remediation output %T", output)
	}
	f.calls++
	outcome := f.outcome
	if outcome == "" {
		outcome = model.ActionDryRun
	}
	dryRun := true
	if f.receiptDryRun != nil {
		dryRun = *f.receiptDryRun
	}
	result.Receipt = model.ActionReceipt{
		SchemaVersion: model.SchemaVersionV1, ReceiptID: "receipt-1",
		GrantID: request.Grant.GrantID, IncidentID: request.Grant.IncidentID,
		Action: request.Grant.Action, Outcome: outcome, DryRun: dryRun,
		StartedAt: f.now, CompletedAt: f.now, AuditRef: "audit-1",
	}
	return nil
}

func (*operatorToolFake) Close() error { return nil }

type operatorClock struct{ now time.Time }

func (c operatorClock) Now() time.Time { return c.now }

type operatorIDs struct{ next int }

func (g *operatorIDs) NewID() string {
	g.next++
	return fmt.Sprintf("operator-id-%d", g.next)
}

func operatorGrant(now time.Time) model.DelegationGrant {
	target := model.ResourceTarget{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "outage-arena", Name: "demo-api"}
	expectedReplicas := int32(1)
	return model.DelegationGrant{
		SchemaVersion: model.SchemaVersionV1, GrantID: "grant-1", Issuer: model.AgentMonitor,
		Audiences:  []model.AgentID{model.AgentOperator, model.AgentMCPAction},
		IncidentID: "incident-1", DiagnosisReportID: "diagnosis-1",
		DiagnosisDigest: strings.Repeat("a", 64), DiagnosisConfidence: 0.95,
		EvidenceIDs: []string{"evidence-1"}, ProposalID: "proposal-1",
		Action:        model.ActionSpec{Kind: model.ActionRestartDeployment, Target: target},
		Preconditions: model.ActionPreconditions{ResourceVersion: "rv-1", ExpectedReplicas: &expectedReplicas},
		DryRun:        true, IdempotencyKey: "incident-1:proposal-1",
		IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(2 * time.Minute),
	}
}
