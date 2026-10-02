package model

import (
	"strings"
	"testing"
	"time"
)

func TestIncidentReportRequestIsSanitizedAndStateBound(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC)
	request := validIncidentReportRequest(now)
	if err := request.Validate(); err != nil {
		t.Fatalf("valid report request rejected: %v", err)
	}
	if err := request.ValidateSigned(); err == nil {
		t.Fatal("unsigned report request passed signed validation")
	}
	first, err := request.ComputeDigest()
	if err != nil {
		t.Fatal(err)
	}
	request.RequestedAt = now.In(time.FixedZone("MYT", 8*60*60))
	second, err := request.ComputeDigest()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("request digest changed across equivalent time zones: %s != %s", first, second)
	}

	request = validIncidentReportRequest(now)
	request.CorrelationID = "correlation-1\nforged"
	if err := request.Validate(); err == nil {
		t.Fatal("report request accepted control characters")
	}

	request = validIncidentReportRequest(now)
	request.FinalState = IncidentEscalated
	if err := request.Validate(); err == nil {
		t.Fatal("escalated report accepted recovery-verified reason")
	}
}

func TestIncidentReportDigestExcludesNotificationState(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	request := validIncidentReportRequest(now)
	report := IncidentReport{
		SchemaVersion: SchemaVersionV1, ReportID: "report-1", RequestID: request.RequestID,
		IncidentID: request.IncidentID, CorrelationID: request.CorrelationID,
		DiagnosisReportID: request.DiagnosisReportID, Target: request.Target,
		FinalState: request.FinalState, Reason: request.Reason, Summary: request.Reason.Summary(),
		CreatedAt: now,
	}
	if err := report.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := report.VerifyDigest(); err != nil {
		t.Fatalf("sealed report did not verify: %v", err)
	}
	result := IncidentReportResult{
		Report: report,
		Notification: NotificationReceipt{
			ReportID: report.ReportID, IdempotencyKey: report.RequestID,
			Channel: NotificationChannelWhatsApp, Status: NotificationFailed,
			AttemptedAt: now, ErrorCode: CodeExecutionFailed,
			ErrorMessage: "notification delivery failed",
		},
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("failed notification invalidated report result: %v", err)
	}
	report.Summary = ReportReasonAuthorityExceeded.Summary()
	if err := report.VerifyDigest(); err == nil {
		t.Fatal("tampered incident report unexpectedly verified")
	}
}

func TestIncidentReportRejectsContradictoryExecutionEvidence(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 2, 30, 0, 0, time.UTC)
	target := ResourceTarget{
		APIVersion: "apps/v1", Kind: "Deployment", Namespace: "outage-arena", Name: "demo-api",
	}
	tests := []struct {
		name      string
		state     IncidentState
		reason    IncidentReportReason
		execution *IncidentReportExecution
	}{
		{name: "dry run without receipt", state: IncidentEscalated, reason: ReportReasonDryRunCompleted},
		{name: "policy denial with execution", state: IncidentEscalated, reason: ReportReasonPolicyDenied, execution: &IncidentReportExecution{
			GrantID: "grant-1", ReceiptID: "receipt-1", Action: ActionSpec{Kind: ActionRestartDeployment, Target: target},
			Outcome: ActionSucceeded, CompletedAt: now,
		}},
		{name: "recovery with dry run", state: IncidentResolved, reason: ReportReasonRecoveryVerified, execution: &IncidentReportExecution{
			GrantID: "grant-1", ReceiptID: "receipt-1", Action: ActionSpec{Kind: ActionRestartDeployment, Target: target},
			Outcome: ActionDryRun, DryRun: true, CompletedAt: now,
		}},
		{name: "timeout without live execution", state: IncidentEscalated, reason: ReportReasonVerificationTimedOut},
		{name: "unverified outcome with execution", state: IncidentEscalated, reason: ReportReasonActionOutcomeUnverified, execution: &IncidentReportExecution{
			GrantID: "grant-1", ReceiptID: "receipt-1", Action: ActionSpec{Kind: ActionRestartDeployment, Target: target},
			Outcome: ActionFailed, CompletedAt: now,
		}},
		{name: "action failure without execution", state: IncidentFailed, reason: ReportReasonActionFailed},
		{name: "rejected action falsely marked dry run", state: IncidentFailed, reason: ReportReasonActionRejected, execution: &IncidentReportExecution{
			GrantID: "grant-1", ReceiptID: "receipt-1", Action: ActionSpec{Kind: ActionRestartDeployment, Target: target},
			Outcome: ActionRejected, DryRun: true, CompletedAt: now,
		}},
		{name: "failed action falsely marked dry run", state: IncidentFailed, reason: ReportReasonActionFailed, execution: &IncidentReportExecution{
			GrantID: "grant-1", ReceiptID: "receipt-1", Action: ActionSpec{Kind: ActionRestartDeployment, Target: target},
			Outcome: ActionFailed, DryRun: true, CompletedAt: now,
		}},
		{name: "authority escalation falsely marked dry run", state: IncidentEscalated, reason: ReportReasonAuthorityExceeded, execution: &IncidentReportExecution{
			GrantID: "grant-1", ReceiptID: "receipt-1", Action: ActionSpec{Kind: ActionRestartDeployment, Target: target},
			Outcome: ActionEscalated, DryRun: true, CompletedAt: now,
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := IncidentReport{
				SchemaVersion: SchemaVersionV1, ReportID: "report-1", RequestID: "request-1",
				IncidentID: "incident-1", CorrelationID: "correlation-1", DiagnosisReportID: "diagnosis-1",
				Target: target, FinalState: test.state, Reason: test.reason, Summary: test.reason.Summary(),
				Execution: test.execution, CreatedAt: now,
			}
			if err := report.Seal(); err == nil {
				t.Fatal("contradictory incident report unexpectedly sealed")
			}
		})
	}
}

func TestUnverifiableActionOutcomeUsesDistinctReceiptFreeEscalation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 2, 45, 0, 0, time.UTC)
	request := validIncidentReportRequest(now)
	request.FinalState = IncidentEscalated
	request.Reason = ReportReasonActionOutcomeUnverified
	if err := request.Validate(); err != nil {
		t.Fatalf("receipt-free unverified-outcome request rejected: %v", err)
	}
	if !strings.Contains(request.Reason.Summary(), "outcome could not be verified") {
		t.Fatalf("unverified-outcome summary overstates an ambiguous result: %q", request.Reason.Summary())
	}
	report := IncidentReport{
		SchemaVersion: SchemaVersionV1, ReportID: "report-ambiguous", RequestID: request.RequestID,
		IncidentID: request.IncidentID, CorrelationID: request.CorrelationID,
		DiagnosisReportID: request.DiagnosisReportID, Target: request.Target,
		FinalState: request.FinalState, Reason: request.Reason, Summary: request.Reason.Summary(),
		CreatedAt: now,
	}
	if err := report.Seal(); err != nil {
		t.Fatalf("receipt-free unverified-outcome report rejected: %v", err)
	}

	request.Reason = ReportReasonActionFailed
	request.FinalState = IncidentFailed
	if err := request.Validate(); err == nil {
		t.Fatal("action_failed request without a validated receipt was accepted")
	}
}

func TestIncidentReportReasonStateMatrixIsClosed(t *testing.T) {
	t.Parallel()
	reasons := []IncidentReportReason{
		ReportReasonRecoveryVerified, ReportReasonAuthorityExceeded,
		ReportReasonDiagnosisInconclusive, ReportReasonPolicyDenied,
		ReportReasonDryRunCompleted, ReportReasonActionRejected,
		ReportReasonActionFailed, ReportReasonActionOutcomeUnverified,
		ReportReasonVerificationTimedOut,
	}
	allowed := map[IncidentState]map[IncidentReportReason]bool{
		IncidentResolved: {
			ReportReasonRecoveryVerified: true,
		},
		IncidentEscalated: {
			ReportReasonAuthorityExceeded: true, ReportReasonDiagnosisInconclusive: true,
			ReportReasonPolicyDenied: true, ReportReasonDryRunCompleted: true,
			ReportReasonActionOutcomeUnverified: true, ReportReasonVerificationTimedOut: true,
		},
		IncidentFailed: {
			ReportReasonActionRejected: true, ReportReasonActionFailed: true,
		},
	}
	for state, allowedReasons := range allowed {
		for _, reason := range reasons {
			err := validateReportState(state, reason)
			if allowedReasons[reason] && err != nil {
				t.Errorf("validateReportState(%q, %q) rejected allowed pair: %v", state, reason, err)
			}
			if !allowedReasons[reason] && err == nil {
				t.Errorf("validateReportState(%q, %q) accepted forbidden pair", state, reason)
			}
		}
	}
}

func validIncidentReportRequest(now time.Time) IncidentReportRequest {
	return IncidentReportRequest{
		SchemaVersion: SchemaVersionV1, RequestID: "report-request-1",
		Issuer: AgentMonitor, Audience: AgentOperator,
		IncidentID: "incident-1", CorrelationID: "correlation-1",
		DiagnosisReportID: "diagnosis-1",
		Target: ResourceTarget{
			APIVersion: "apps/v1", Kind: "Deployment",
			Namespace: "outage-arena", Name: "demo-api",
		},
		FinalState: IncidentResolved, Reason: ReportReasonRecoveryVerified,
		RequestedAt: now, ExpiresAt: now.Add(2 * time.Minute),
	}
}
