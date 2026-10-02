package operator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"sync"
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

func TestConcurrentDuplicateGrantSharesOneReceiptReservation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 5, 45, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{53}, ed25519.SeedSize))
	grant, err := security.SignGrant(privateKey, "operator-test-key", operatorGrant(now))
	if err != nil {
		t.Fatal(err)
	}
	tools := &operatorToolFake{now: now}
	service := newOperatorService(t, now, privateKey.Public().(ed25519.PublicKey), tools)

	const callers = 16
	start := make(chan struct{})
	type executionResult struct {
		receipt model.ActionReceipt
		err     error
	}
	results := make(chan executionResult, callers)
	var wait sync.WaitGroup
	for index := 0; index < callers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			receipt, executeErr := service.Execute(context.Background(), grant)
			results <- executionResult{receipt: receipt, err: executeErr}
		}()
	}
	close(start)
	wait.Wait()
	close(results)

	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent Execute() error = %v", result.err)
		}
		if result.receipt.ReceiptID != "receipt-1" {
			t.Fatalf("concurrent Execute() receipt = %#v", result.receipt)
		}
	}
	if tools.calls != 1 || len(service.receipts) != 1 {
		t.Fatalf("duplicate execution crossed action boundary %d times with %d cache records", tools.calls, len(service.receipts))
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
	if len(service.receipts) != 0 {
		t.Fatalf("failed execution retained %d receipt reservations", len(service.receipts))
	}
}

func TestHandleIncidentReportIsBoundAndIdempotent(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 3, 0, 0, 0, time.UTC)
	notifier := &operatorNotifierFake{}
	service := newReportOperatorService(t, now, notifier)
	receipt := operatorReportReceipt(now, model.ActionSucceeded, false)
	replicas := int32(3)
	receipt.Action.Kind = model.ActionScaleDeployment
	receipt.Action.Parameters.Replicas = &replicas
	seedOperatorReceipt(service, receipt, false)
	request := operatorReportRequest(t, now, model.IncidentResolved, model.ReportReasonRecoveryVerified)
	request.GrantID, request.ReceiptID = receipt.GrantID, receipt.ReceiptID
	request = signOperatorReportRequest(t, request)

	firstEnvelope := operatorReportEnvelope(t, now, "message-report-1", model.AgentMonitor, request, request.CorrelationID)
	firstResponse, err := service.Handle(context.Background(), firstEnvelope)
	if err != nil {
		t.Fatalf("first Handle() error = %v", err)
	}
	if firstResponse.Kind != model.MessageIncidentReport || firstResponse.CausationID != firstEnvelope.MessageID {
		t.Fatalf("unexpected report response envelope: %#v", firstResponse)
	}
	var first model.IncidentReportResult
	if err := firstResponse.DecodePayload(&first); err != nil {
		t.Fatal(err)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("report result validation failed: %v", err)
	}
	if first.Report.FinalState != model.IncidentResolved || first.Notification.Status != model.NotificationDelivered {
		t.Fatalf("unexpected report result: %#v", first)
	}
	if first.Report.Execution == nil || first.Report.Execution.ReceiptID != receipt.ReceiptID {
		t.Fatalf("report omitted cached receipt binding: %#v", first.Report.Execution)
	}
	*first.Report.Execution.Action.Parameters.Replicas = 99

	secondEnvelope := operatorReportEnvelope(t, now, "message-report-2", model.AgentMonitor, request, request.CorrelationID)
	secondResponse, err := service.Handle(context.Background(), secondEnvelope)
	if err != nil {
		t.Fatalf("duplicate Handle() error = %v", err)
	}
	var second model.IncidentReportResult
	if err := secondResponse.DecodePayload(&second); err != nil {
		t.Fatal(err)
	}
	if notifier.calls != 1 {
		t.Fatalf("notifier calls = %d, want 1", notifier.calls)
	}
	if second.Report.Execution == nil || second.Report.Execution.Action.Parameters.Replicas == nil ||
		*second.Report.Execution.Action.Parameters.Replicas != replicas {
		t.Fatalf("caller mutation corrupted cached sealed report: %#v", second.Report.Execution)
	}
	if err := second.Validate(); err != nil {
		t.Fatalf("cached report failed validation after caller mutation: %v", err)
	}
	if second.Report.ReportID != first.Report.ReportID || second.Report.Digest != first.Report.Digest || second.Notification.ProviderMessageID != first.Notification.ProviderMessageID {
		t.Fatalf("duplicate request returned a different result: first=%#v second=%#v", first, second)
	}

	conflict := request
	conflict.DiagnosisReportID = "diagnosis-conflict"
	conflict = signOperatorReportRequest(t, conflict)
	conflictEnvelope := operatorReportEnvelope(t, now, "message-report-3", model.AgentMonitor, conflict, conflict.CorrelationID)
	if _, err := service.Handle(context.Background(), conflictEnvelope); err == nil {
		t.Fatal("conflicting reuse of report request ID was accepted")
	}
	if notifier.calls != 1 {
		t.Fatalf("conflicting request notified again: calls=%d", notifier.calls)
	}
}

func TestHandleAuthorityEscalationNeverRequiresOrCallsActionPlane(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 3, 30, 0, 0, time.UTC)
	notifier := &operatorNotifierFake{}
	service := newReportOperatorService(t, now, notifier)
	request := operatorReportRequest(t, now, model.IncidentEscalated, model.ReportReasonAuthorityExceeded)
	envelope := operatorReportEnvelope(t, now, "message-escalation", model.AgentMonitor, request, request.CorrelationID)

	response, err := service.Handle(context.Background(), envelope)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	var result model.IncidentReportResult
	if err := response.DecodePayload(&result); err != nil {
		t.Fatal(err)
	}
	if result.Report.FinalState != model.IncidentEscalated || result.Report.Execution != nil {
		t.Fatalf("authority escalation report gained execution data: %#v", result.Report)
	}
	if notifier.calls != 1 || result.Notification.Status != model.NotificationDelivered {
		t.Fatalf("authority escalation notification mismatch: calls=%d result=%#v", notifier.calls, result.Notification)
	}
}

func TestHandleUntrustedOrMismatchedReportNeverNotifies(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 4, 0, 0, 0, time.UTC)
	request := operatorReportRequest(t, now, model.IncidentEscalated, model.ReportReasonPolicyDenied)
	malformed := request
	malformed.DiagnosisReportID = "diagnosis-1\nforged"
	tests := []struct {
		name     string
		envelope model.Envelope
	}{
		{
			name: "untrusted sender",
			envelope: operatorReportEnvelope(t, now, "message-untrusted", model.AgentInvestigator,
				request, request.CorrelationID),
		},
		{
			name: "correlation mismatch",
			envelope: operatorReportEnvelope(t, now, "message-correlation", model.AgentMonitor,
				request, "different-correlation"),
		},
		{
			name: "malformed sanitized field",
			envelope: operatorReportEnvelope(t, now, "message-malformed", model.AgentMonitor,
				malformed, malformed.CorrelationID),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notifier := &operatorNotifierFake{}
			service := newReportOperatorService(t, now, notifier)
			if _, err := service.Handle(context.Background(), tt.envelope); err == nil {
				t.Fatal("Handle() error = nil, want rejection")
			}
			if notifier.calls != 0 {
				t.Fatalf("notifier calls = %d, want 0", notifier.calls)
			}
		})
	}

	notifier := &operatorNotifierFake{}
	service := newReportOperatorService(t, now, notifier)
	unknownReceipt := operatorReportRequest(t, now, model.IncidentResolved, model.ReportReasonRecoveryVerified)
	unknownReceipt.GrantID, unknownReceipt.ReceiptID = "unknown-grant", "unknown-receipt"
	unknownReceipt = signOperatorReportRequest(t, unknownReceipt)
	envelope := operatorReportEnvelope(t, now, "message-unknown-receipt", model.AgentMonitor, unknownReceipt, unknownReceipt.CorrelationID)
	if _, err := service.Handle(context.Background(), envelope); err == nil {
		t.Fatal("unknown receipt binding was accepted")
	}
	if notifier.calls != 0 {
		t.Fatalf("invalid receipt binding notified: calls=%d", notifier.calls)
	}
}

func TestHandleRejectsUnsignedSpoofedTamperedAndExpiredReportsBeforeNotifier(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 4, 15, 0, 0, time.UTC)
	attackerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{32}, ed25519.SeedSize))

	unsigned := unsignedOperatorReportRequest(now, model.IncidentEscalated, model.ReportReasonAuthorityExceeded)
	spoofed, err := security.SignReportRequest(attackerKey, "report-test-key", unsigned)
	if err != nil {
		t.Fatal(err)
	}
	tampered := operatorReportRequest(t, now, model.IncidentEscalated, model.ReportReasonAuthorityExceeded)
	tampered.CorrelationID = "correlation-tampered"
	expired := unsignedOperatorReportRequest(now.Add(-3*time.Minute), model.IncidentEscalated, model.ReportReasonAuthorityExceeded)
	expired.ExpiresAt = now.Add(-time.Minute)
	expired = signOperatorReportRequest(t, expired)

	tests := []struct {
		name     string
		request  model.IncidentReportRequest
		wantCode model.ErrorCode
	}{
		{name: "unsigned", request: unsigned, wantCode: model.CodeDelegationRequired},
		{name: "spoofed key", request: spoofed, wantCode: model.CodeInvalidSignature},
		{name: "tampered contents", request: tampered, wantCode: model.CodeInvalidSignature},
		{name: "expired", request: expired, wantCode: model.CodeGrantExpired},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			notifier := &operatorNotifierFake{}
			service := newReportOperatorService(t, now, notifier)
			envelope := operatorReportEnvelope(
				t, now, fmt.Sprintf("message-auth-%d", index), model.AgentMonitor,
				test.request, test.request.CorrelationID,
			)
			if _, err := service.Handle(context.Background(), envelope); err == nil {
				t.Fatal("Handle() error = nil, want authorization rejection")
			} else if code, ok := model.ErrorCodeOf(err); !ok || code != test.wantCode {
				t.Fatalf("Handle() error = %v, want code %s", err, test.wantCode)
			}
			if notifier.calls != 0 {
				t.Fatalf("notifier calls = %d, want 0", notifier.calls)
			}
		})
	}
}

func TestNotificationFailureDoesNotChangeResolvedIncidentReport(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 4, 30, 0, 0, time.UTC)
	notifier := &operatorNotifierFake{err: errors.New("provider secret must not escape")}
	service := newReportOperatorService(t, now, notifier)
	receipt := operatorReportReceipt(now, model.ActionSucceeded, false)
	seedOperatorReceipt(service, receipt, false)
	request := operatorReportRequest(t, now, model.IncidentResolved, model.ReportReasonRecoveryVerified)
	request.GrantID, request.ReceiptID = receipt.GrantID, receipt.ReceiptID
	request = signOperatorReportRequest(t, request)

	result, err := service.Report(context.Background(), request)
	if err != nil {
		t.Fatalf("Report() returned notification failure as workflow error: %v", err)
	}
	if result.Report.FinalState != model.IncidentResolved || result.Notification.Status != model.NotificationFailed {
		t.Fatalf("notification failure changed incident result: %#v", result)
	}
	if strings.Contains(result.Notification.ErrorMessage, "secret") {
		t.Fatalf("provider error leaked into receipt: %q", result.Notification.ErrorMessage)
	}
	if err := result.Report.VerifyDigest(); err != nil {
		t.Fatalf("report digest failed after notification error: %v", err)
	}
}

func operatorReportRequest(t *testing.T, now time.Time, state model.IncidentState, reason model.IncidentReportReason) model.IncidentReportRequest {
	t.Helper()
	return signOperatorReportRequest(t, unsignedOperatorReportRequest(now, state, reason))
}

func unsignedOperatorReportRequest(now time.Time, state model.IncidentState, reason model.IncidentReportReason) model.IncidentReportRequest {
	return model.IncidentReportRequest{
		SchemaVersion: model.IncidentReportRequestSchemaVersionV2, RequestID: "report-request-1",
		Issuer: model.AgentMonitor, Audience: model.AgentOperator,
		IncidentID: "incident-1", CorrelationID: "correlation-1",
		DiagnosisReportID: "diagnosis-1",
		Target: model.ResourceTarget{
			APIVersion: "apps/v1", Kind: "Deployment",
			Namespace: "outage-arena", Name: "demo-api",
		},
		FinalState: state, Reason: reason, ReportCreatedAt: now, RequestedAt: now,
		ExpiresAt: now.Add(2 * time.Minute),
	}
}

func signOperatorReportRequest(t *testing.T, request model.IncidentReportRequest) model.IncidentReportRequest {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, ed25519.SeedSize))
	signed, err := security.SignReportRequest(privateKey, "report-test-key", request)
	if err != nil {
		t.Fatalf("SignReportRequest() error = %v", err)
	}
	return signed
}

func newReportOperatorService(t *testing.T, now time.Time, notifier *operatorNotifierFake) *Service {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, ed25519.SeedSize))
	verifier, err := security.NewVerifier(privateKey.Public().(ed25519.PublicKey), "report-test-key", model.AgentOperator)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	return &Service{
		ReportVerifier: verifier, Clock: operatorClock{now: now},
		IDs: &operatorIDs{}, Notifier: notifier,
	}
}

func operatorReportEnvelope(t *testing.T, now time.Time, messageID string, sender model.AgentID, request model.IncidentReportRequest, correlationID string) model.Envelope {
	t.Helper()
	envelope, err := model.NewEnvelope(
		messageID, request.IncidentID, correlationID, "prior-message",
		sender, model.AgentOperator, model.MessageIncidentReportRequest, now, request,
	)
	if err != nil {
		t.Fatalf("NewEnvelope() error = %v", err)
	}
	return envelope
}

func operatorReportReceipt(now time.Time, outcome model.ActionOutcome, dryRun bool) model.ActionReceipt {
	return model.ActionReceipt{
		SchemaVersion: model.SchemaVersionV1, ReceiptID: "receipt-report-1",
		GrantID: "grant-report-1", IncidentID: "incident-1",
		Action: model.ActionSpec{
			Kind: model.ActionRestartDeployment,
			Target: model.ResourceTarget{
				APIVersion: "apps/v1", Kind: "Deployment",
				Namespace: "outage-arena", Name: "demo-api",
			},
		},
		Outcome: outcome, DryRun: dryRun, StartedAt: now.Add(-time.Second),
		CompletedAt: now, AuditRef: "audit-report-1",
	}
}

func seedOperatorReceipt(service *Service, receipt model.ActionReceipt, reported bool) {
	if service.receipts == nil {
		service.receipts = make(map[string]*receiptRecord)
	}
	done := make(chan struct{})
	close(done)
	service.receipts[receipt.GrantID] = &receiptRecord{
		grantFingerprint: "test-seed:" + receipt.GrantID,
		done:             done,
		receipt:          cloneActionReceipt(receipt),
		reported:         reported,
	}
}

func TestExecuteRejectsBeforeActionWhenReceiptCacheIsAllUnreported(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 6, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{51}, ed25519.SeedSize))
	tools := &operatorToolFake{now: now}
	service := newOperatorService(t, now, privateKey.Public().(ed25519.PublicKey), tools)
	for index := 0; index < maxOperatorCacheEntries; index++ {
		seedOperatorReceipt(service, model.ActionReceipt{
			GrantID: fmt.Sprintf("grant-%05d", index), CompletedAt: now.Add(time.Duration(index) * time.Second),
		}, false)
	}
	grant, err := security.SignGrant(privateKey, "operator-test-key", operatorGrant(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Execute(context.Background(), grant); err == nil {
		t.Fatal("Execute() error = nil, want bounded receipt-cache rejection")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeToolBudgetExceeded {
		t.Fatalf("Execute() error = %v, want %s", err, model.CodeToolBudgetExceeded)
	}
	if tools.calls != 0 || tools.statusCalls != 0 {
		t.Fatalf("capacity rejection reached action tools: execute=%d status=%d", tools.calls, tools.statusCalls)
	}
	if len(service.receipts) != maxOperatorCacheEntries {
		t.Fatalf("receipt cache size = %d, want %d", len(service.receipts), maxOperatorCacheEntries)
	}
}

func TestCompletedReportReceiptIsEligibleForEviction(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 6, 15, 0, 0, time.UTC)
	actionPrivateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{52}, ed25519.SeedSize))
	tools := &operatorToolFake{now: now}
	service := newOperatorService(t, now, actionPrivateKey.Public().(ed25519.PublicKey), tools)
	reportPrivateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, ed25519.SeedSize))
	reportVerifier, err := security.NewVerifier(
		reportPrivateKey.Public().(ed25519.PublicKey), "report-test-key", model.AgentOperator,
	)
	if err != nil {
		t.Fatal(err)
	}
	service.ReportVerifier = reportVerifier
	service.Notifier = &operatorNotifierFake{}

	reportedReceipt := operatorReportReceipt(now, model.ActionSucceeded, false)
	seedOperatorReceipt(service, reportedReceipt, false)
	request := unsignedOperatorReportRequest(now, model.IncidentResolved, model.ReportReasonRecoveryVerified)
	request.GrantID, request.ReceiptID = reportedReceipt.GrantID, reportedReceipt.ReceiptID
	request = signOperatorReportRequest(t, request)
	if _, err := service.Report(context.Background(), request); err != nil {
		t.Fatalf("Report() error = %v", err)
	}
	if record := service.receipts[reportedReceipt.GrantID]; record == nil || !record.reported {
		t.Fatal("completed report did not make its exact receipt eligible for eviction")
	}

	for index := 0; index < maxOperatorCacheEntries-1; index++ {
		seedOperatorReceipt(service, model.ActionReceipt{
			GrantID:     fmt.Sprintf("grant-unreported-%05d", index),
			CompletedAt: now.Add(-time.Hour).Add(time.Duration(index) * time.Millisecond),
		}, false)
	}
	grant, err := security.SignGrant(actionPrivateKey, "operator-test-key", operatorGrant(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Execute(context.Background(), grant); err != nil {
		t.Fatalf("Execute() with one reported eviction candidate error = %v", err)
	}
	if _, exists := service.receipts[reportedReceipt.GrantID]; exists {
		t.Fatal("completed-report receipt was not evicted")
	}
	if _, exists := service.receipts["grant-unreported-00000"]; !exists {
		t.Fatal("an unreported receipt was evicted")
	}
	if tools.calls != 1 || len(service.receipts) != maxOperatorCacheEntries {
		t.Fatalf("unexpected post-eviction state: action calls=%d receipts=%d", tools.calls, len(service.receipts))
	}
}

func TestOperatorReportCacheRemainsBounded(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 6, 30, 0, 0, time.UTC)
	service := &Service{}

	service.reports = make(map[string]*reportRecord, maxOperatorCacheEntries)
	for index := 0; index < maxOperatorCacheEntries; index++ {
		done := make(chan struct{})
		close(done)
		service.reports[fmt.Sprintf("request-%05d", index)] = &reportRecord{
			requestDigest: "digest", done: done,
			result: model.IncidentReportResult{Notification: model.NotificationReceipt{
				AttemptedAt: now.Add(time.Duration(index) * time.Second),
			}},
		}
	}
	if _, owner, err := service.beginReport("request-new", "digest-new"); err != nil || !owner {
		t.Fatalf("beginReport() = owner %t, error %v", owner, err)
	}
	if len(service.reports) != maxOperatorCacheEntries {
		t.Fatalf("report cache size = %d, want %d", len(service.reports), maxOperatorCacheEntries)
	}
	if _, exists := service.reports["request-00000"]; exists {
		t.Fatal("report cache did not evict its oldest completed entry")
	}
}

type operatorNotifierFake struct {
	calls    int
	err      error
	delivery model.NotificationDelivery
}

func (f *operatorNotifierFake) Notify(_ context.Context, _ model.IncidentReport) (model.NotificationDelivery, error) {
	f.calls++
	if f.err != nil {
		return model.NotificationDelivery{}, f.err
	}
	if f.delivery.Channel == "" {
		return model.NotificationDelivery{
			Channel: model.NotificationChannelWhatsApp, ProviderMessageID: "whatsapp-message-1",
		}, nil
	}
	return f.delivery, nil
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
