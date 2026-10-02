package monitor

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
	"github.com/shanurwan/AegisSRE/internal/core/ports"
	"github.com/shanurwan/AegisSRE/internal/security"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

func TestDurableMonitorLeaseAllowsOnlyOneReplicaToScan(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 1, 0, 0, 0, time.UTC)
	state := &monitorStateFake{}
	firstTools := &monitorToolFake{now: now}
	first := monitorService(now, firstTools, &monitorPeerFake{now: now, diagnosisStatus: model.DiagnosisInconclusive})
	first.StateStore, first.InstanceID, first.StateLease = state, "monitor-a", time.Minute
	if _, err := first.Scan(context.Background(), ScanRequest{}); err != nil {
		t.Fatal(err)
	}

	secondTools := &monitorToolFake{now: now}
	secondPeers := &monitorPeerFake{now: now, diagnosisStatus: model.DiagnosisInconclusive}
	second := monitorService(now, secondTools, secondPeers)
	second.StateStore, second.InstanceID, second.StateLease = state, "monitor-b", time.Minute
	result, err := second.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Candidates != 0 || len(result.Outcomes) != 0 || len(secondTools.calls) != 0 || len(secondPeers.endpoints) != 0 {
		t.Fatalf("standby Monitor performed work: result=%#v tools=%v peers=%v", result, secondTools.calls, secondPeers.endpoints)
	}
}

func TestDurableMonitorRestartResumesVerificationWithoutRedelegation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 1, 10, 0, 0, time.UTC)
	state := &monitorStateFake{}
	tools := &monitorToolFake{now: now}
	peers := &monitorPeerFake{now: now, diagnosisStatus: model.DiagnosisConfirmed, remediationOutcome: model.ActionSucceeded}
	first := durableActionMonitor(t, now, tools, peers, state, "monitor-a")
	result, err := first.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outcomes) != 1 || result.Outcomes[0].Status != "verification_pending" || peers.remediationCalls != 1 {
		t.Fatalf("initial durable action = %#v, remediation calls=%d", result.Outcomes, peers.remediationCalls)
	}

	state.expire()
	tools.healthySnapshot = true
	second := durableActionMonitor(t, now, tools, peers, state, "monitor-b")
	result, err = second.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outcomes) != 1 || result.Outcomes[0].Status != "resolved" {
		t.Fatalf("restarted Monitor did not resume verification: %#v", result.Outcomes)
	}
	if peers.remediationCalls != 1 {
		t.Fatalf("restart repeated remediation %d times", peers.remediationCalls)
	}
	if len(peers.reportRequests) != 1 || result.Outcomes[0].Report == nil {
		t.Fatalf("restarted Monitor did not complete durable reporting: %#v", result.Outcomes[0])
	}
}

func TestDurableMonitorRetriesExactGrantAfterAmbiguousDelivery(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 1, 20, 0, 0, time.UTC)
	state := &monitorStateFake{}
	tools := &monitorToolFake{now: now}
	peers := &monitorPeerFake{
		now: now, diagnosisStatus: model.DiagnosisConfirmed,
		remediationOutcome: model.ActionSucceeded,
		remediationErr: model.WrapError(
			model.CodeExecutionPending,
			"durable action outcome reconciliation is pending",
			errors.New("ambiguous transport failure"),
		),
	}
	first := durableActionMonitor(t, now, tools, peers, state, "monitor-a")
	result, err := first.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outcomes) != 1 || result.Outcomes[0].Status != "remediation_delivery_pending" {
		t.Fatalf("ambiguous delivery was not retained: %#v", result.Outcomes)
	}
	if len(peers.reportRequests) != 0 {
		t.Fatalf("retryable execution-pending response switched to terminal reporting: %#v", peers.reportRequests)
	}

	state.expire()
	peers.remediationErr = nil
	second := durableActionMonitor(t, now, tools, peers, state, "monitor-b")
	result, err = second.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outcomes) != 1 || result.Outcomes[0].Status != "verification_pending" {
		t.Fatalf("exact dispatch did not resume: %#v", result.Outcomes)
	}
	if len(peers.remediationGrantIDs) != 2 || peers.remediationGrantIDs[0] != peers.remediationGrantIDs[1] {
		t.Fatalf("restart issued a different grant: %v", peers.remediationGrantIDs)
	}
	investigations := 0
	for _, kind := range peers.kinds {
		if kind == model.MessageInvestigationRequest {
			investigations++
		}
	}
	if investigations != 1 {
		t.Fatalf("restart repeated investigation instead of resuming exact dispatch: %d", investigations)
	}
}

func TestDurableMonitorRestartRetriesExactSignedReport(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 1, 30, 0, 0, time.UTC)
	state := &monitorStateFake{}
	tools := &monitorToolFake{now: now, healthyAfterSnapshot: 2}
	peers := &monitorPeerFake{
		now: now, diagnosisStatus: model.DiagnosisConfirmed,
		remediationOutcome: model.ActionSucceeded, reportErr: errors.New("ambiguous report transport failure"),
	}
	first := durableActionMonitor(t, now, tools, peers, state, "monitor-a")
	result, err := first.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outcomes) != 1 || result.Outcomes[0].Status != "resolved" || len(peers.reportRequestAttempts) != 1 {
		t.Fatalf("initial report attempt was not checkpointed: outcomes=%#v attempts=%d", result.Outcomes, len(peers.reportRequestAttempts))
	}

	state.expire()
	peers.reportErr = nil
	second := durableActionMonitor(t, now, tools, peers, state, "monitor-b")
	result, err = second.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outcomes) != 1 || result.Outcomes[0].Report == nil || peers.remediationCalls != 1 {
		t.Fatalf("restarted Monitor did not finish report-only recovery: outcomes=%#v actions=%d", result.Outcomes, peers.remediationCalls)
	}
	if len(peers.reportRequestAttempts) != 2 || !sameJSON(peers.reportRequestAttempts[0], peers.reportRequestAttempts[1]) {
		t.Fatalf("restart did not retry the exact signed report request: %#v", peers.reportRequestAttempts)
	}
}

func TestDurableMonitorResignsReportAfterDefinitiveExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 1, 40, 0, 0, time.UTC)
	state := &monitorStateFake{}
	tools := &monitorToolFake{now: now, healthyAfterSnapshot: 2}
	peers := &monitorPeerFake{
		now: now, diagnosisStatus: model.DiagnosisConfirmed,
		remediationOutcome: model.ActionSucceeded, reportErr: errors.New("Operator unavailable"),
	}
	first := durableActionMonitor(t, now, tools, peers, state, "monitor-a")
	if _, err := first.Scan(context.Background(), ScanRequest{}); err != nil {
		t.Fatal(err)
	}

	later := now.Add(model.MaxIncidentReportRequestTTL + time.Minute)
	state.expire()
	tools.now = later
	peers.now = later
	peers.reportErr = nil
	second := durableActionMonitor(t, later, tools, peers, state, "monitor-b")
	result, err := second.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outcomes) != 1 || result.Outcomes[0].Report == nil || peers.remediationCalls != 1 {
		t.Fatalf("expired report recovery failed: outcomes=%#v actions=%d", result.Outcomes, peers.remediationCalls)
	}
	if len(peers.reportRequestAttempts) != 3 {
		t.Fatalf("report attempts = %d, want initial, definitive expiry, and renewed request", len(peers.reportRequestAttempts))
	}
	initial, expiredRetry, renewed := peers.reportRequestAttempts[0], peers.reportRequestAttempts[1], peers.reportRequestAttempts[2]
	if !sameJSON(initial, expiredRetry) {
		t.Fatal("Monitor did not first query Operator with the exact checkpointed report request")
	}
	if renewed.RequestID != initial.RequestID || !renewed.ReportCreatedAt.Equal(initial.ReportCreatedAt) ||
		!renewed.RequestedAt.Equal(later) || !later.Before(renewed.ExpiresAt) {
		t.Fatalf("renewed report request identity/window is invalid: %#v", renewed)
	}
	initialReportID, err := initial.DeterministicReportID()
	if err != nil {
		t.Fatal(err)
	}
	renewedReportID, err := renewed.DeterministicReportID()
	if err != nil {
		t.Fatal(err)
	}
	if initialReportID != renewedReportID {
		t.Fatalf("renewal changed logical report ID: initial=%q renewed=%q", initialReportID, renewedReportID)
	}
}

func TestDurableMonitorRenewsExpiredReportAfterSigningKeyRetirement(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 1, 45, 0, 0, time.UTC)
	state := &monitorStateFake{}
	tools := &monitorToolFake{now: now, healthyAfterSnapshot: 2}
	peers := &monitorPeerFake{
		now: now, diagnosisStatus: model.DiagnosisConfirmed,
		remediationOutcome: model.ActionSucceeded,
		rejectReportKeyID:  "durable-monitor-test-key",
	}
	first := durableActionMonitor(t, now, tools, peers, state, "monitor-old-key")
	firstResult, err := first.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(firstResult.Outcomes) != 1 || firstResult.Outcomes[0].Report != nil ||
		len(peers.reportRequestAttempts) != 1 || peers.remediationCalls != 1 {
		t.Fatalf("old-key report was not durably retained: outcomes=%#v attempts=%d actions=%d", firstResult.Outcomes, len(peers.reportRequestAttempts), peers.remediationCalls)
	}
	original := peers.reportRequestAttempts[0]

	later := now.Add(model.MaxIncidentReportRequestTTL + time.Minute)
	state.expire()
	tools.now = later
	peers.now = later
	rotated := durableActionMonitor(t, later, tools, peers, state, "monitor-new-key")
	newPrivateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{99}, ed25519.SeedSize))
	newSigner, err := security.NewSigner(newPrivateKey, "rotated-monitor-report-key")
	if err != nil {
		t.Fatal(err)
	}
	rotated.ReportSigner = newSigner

	result, err := rotated.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outcomes) != 1 || result.Outcomes[0].Report == nil || peers.remediationCalls != 1 {
		t.Fatalf("rotated-key report-only recovery failed: outcomes=%#v actions=%d", result.Outcomes, peers.remediationCalls)
	}
	if len(peers.reportRequestAttempts) != 3 {
		t.Fatalf("report attempts = %d, want initial old key, expired old key, renewed key", len(peers.reportRequestAttempts))
	}
	retriedOld, renewed := peers.reportRequestAttempts[1], peers.reportRequestAttempts[2]
	if retriedOld.Signature.KeyID != original.Signature.KeyID ||
		renewed.Signature.KeyID != "rotated-monitor-report-key" {
		t.Fatalf("report key lineage = %q -> %q -> %q", original.Signature.KeyID, retriedOld.Signature.KeyID, renewed.Signature.KeyID)
	}
	if renewed.RequestID != original.RequestID || !renewed.ReportCreatedAt.Equal(original.ReportCreatedAt) ||
		renewed.IncidentID != original.IncidentID || renewed.Reason != original.Reason ||
		!renewed.Target.Equal(original.Target) {
		t.Fatalf("key rotation changed immutable report semantics: original=%#v renewed=%#v", original, renewed)
	}
	originalID, err := original.DeterministicReportID()
	if err != nil {
		t.Fatal(err)
	}
	renewedID, err := renewed.DeterministicReportID()
	if err != nil {
		t.Fatal(err)
	}
	if renewedID != originalID || result.Outcomes[0].Report.Report.ReportID != originalID {
		t.Fatalf("key rotation changed report identity: original=%q renewed=%q result=%q", originalID, renewedID, result.Outcomes[0].Report.Report.ReportID)
	}
}

func TestDurableMonitorRetriesExpiredReportSignaturesWithoutAbandonment(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 1, 50, 0, 0, time.UTC)
	state := &monitorStateFake{}
	tools := &monitorToolFake{now: now, healthyAfterSnapshot: 2}
	peers := &monitorPeerFake{
		now: now, diagnosisStatus: model.DiagnosisConfirmed,
		remediationOutcome: model.ActionSucceeded, reportErr: errors.New("Operator unavailable"),
	}
	service := durableActionMonitor(t, now, tools, peers, state, "monitor-1")
	if _, err := service.Scan(context.Background(), ScanRequest{}); err != nil {
		t.Fatal(err)
	}

	var result ScanResult
	const renewalCount = 5
	for attempt := 2; attempt <= renewalCount+1; attempt++ {
		now = now.Add(model.MaxIncidentReportRequestTTL + time.Minute)
		state.expire()
		tools.now = now
		peers.now = now
		service = durableActionMonitor(t, now, tools, peers, state, fmt.Sprintf("monitor-%d", attempt))
		var err error
		result, err = service.Scan(context.Background(), ScanRequest{})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(result.Outcomes) != 1 || result.Outcomes[0].Status != "report_delivery_pending" {
		t.Fatalf("durably retried report workflow = %#v", result.Outcomes)
	}
	unique := make(map[string]struct{})
	for _, request := range peers.reportRequestAttempts {
		unique[request.RequestID] = struct{}{}
	}
	if len(unique) != 1 || peers.remediationCalls != 1 {
		t.Fatalf("signed report identities=%d actions=%d, want one stable identity and one action", len(unique), peers.remediationCalls)
	}
}

func TestScanDoesNotDelegateBeforeVerificationThreshold(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 6, 0, 0, 0, time.UTC)
	tools := &monitorToolFake{now: now}
	peers := &monitorPeerFake{now: now, diagnosisStatus: model.DiagnosisInconclusive}
	service := monitorService(now, tools, peers)
	service.VerificationCount = 2

	first, err := service.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatalf("first Scan() error = %v", err)
	}
	if first.Candidates != 1 || len(first.Outcomes) != 0 {
		t.Fatalf("first Scan() = %#v, want one unverified candidate and no outcome", first)
	}
	if len(peers.endpoints) != 0 {
		t.Fatalf("peer calls before verification = %v, want none", peers.endpoints)
	}

	second, err := service.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatalf("second Scan() error = %v", err)
	}
	if len(peers.endpoints) != 2 || peers.endpoints[0] != service.InvestigatorURL || peers.endpoints[1] != service.OperatorURL {
		t.Fatalf("peer calls after verification = %v, want Investigator then Operator report", peers.endpoints)
	}
	if len(second.Outcomes) != 1 || second.Outcomes[0].Status != "escalated" {
		t.Fatalf("second Scan() outcomes = %#v, want inconclusive escalation", second.Outcomes)
	}
}

func TestScanWithoutSigningKeyStopsAfterDiagnosis(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 6, 30, 0, 0, time.UTC)
	tools := &monitorToolFake{now: now}
	peers := &monitorPeerFake{now: now, diagnosisStatus: model.DiagnosisConfirmed}
	service := monitorService(now, tools, peers)
	service.VerificationCount = 1
	service.Signer = nil

	result, err := service.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(result.Outcomes) != 1 {
		t.Fatalf("outcomes = %d, want 1", len(result.Outcomes))
	}
	outcome := result.Outcomes[0]
	if outcome.Status != "awaiting_delegation_key" {
		t.Fatalf("outcome status = %q, want awaiting_delegation_key", outcome.Status)
	}
	if outcome.Grant != nil || outcome.Receipt != nil {
		t.Fatalf("no-key outcome delegated authority: grant=%#v receipt=%#v", outcome.Grant, outcome.Receipt)
	}
	if outcome.Incident.State != model.IncidentEscalated {
		t.Fatalf("incident state = %q, want %q", outcome.Incident.State, model.IncidentEscalated)
	}
	if len(peers.endpoints) != 2 || peers.kinds[1] != model.MessageIncidentReportRequest {
		t.Fatalf("peer calls = %v (%v), want Investigator then non-authoritative Operator report", peers.endpoints, peers.kinds)
	}
	if got := tools.count(toolapi.ToolGetWorkloadSnapshot); got != 1 {
		t.Fatalf("precondition snapshot calls = %d, want 1", got)
	}
}

func TestDuplicateMetricSamplesDoNotSatisfyTemporalVerification(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 6, 45, 0, 0, time.UTC)
	sample := toolapi.MetricSample{
		Labels:    map[string]string{"namespace": "outage-arena", "deployment": "demo-api"},
		Timestamp: now, Value: 1,
	}
	tools := &monitorToolFake{now: now, samples: []toolapi.MetricSample{sample, sample}}
	peers := &monitorPeerFake{now: now, diagnosisStatus: model.DiagnosisInconclusive}
	service := monitorService(now, tools, peers)
	service.VerificationCount = 2
	result, err := service.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Candidates != 1 || len(result.Outcomes) != 0 || len(peers.endpoints) != 0 {
		t.Fatalf("duplicate rows bypassed temporal verification: result=%#v peers=%v", result, peers.endpoints)
	}
}

func TestMetricFailureBreaksConsecutiveVerification(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 6, 50, 0, 0, time.UTC)
	tools := &monitorToolFake{now: now}
	peers := &monitorPeerFake{now: now, diagnosisStatus: model.DiagnosisInconclusive}
	service := monitorService(now, tools, peers)
	service.VerificationCount = 2

	if _, err := service.Scan(context.Background(), ScanRequest{}); err != nil {
		t.Fatal(err)
	}
	tools.metricErr = fmt.Errorf("metrics unavailable")
	if _, err := service.Scan(context.Background(), ScanRequest{}); err == nil {
		t.Fatal("metric failure was not returned")
	}
	tools.metricErr = nil
	result, err := service.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outcomes) != 0 || len(peers.endpoints) != 0 {
		t.Fatalf("failed scan did not break consecutive verification: outcomes=%#v peers=%v", result.Outcomes, peers.endpoints)
	}
}

func TestTelemetryRulesKeepIndependentVerificationCounters(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 6, 55, 0, 0, time.UTC)
	logSignal := toolapi.DetectionSample{Namespace: "outage-arena", Workload: "demo-api", Timestamp: now, Value: 5}
	traceSignal := toolapi.DetectionSample{Namespace: "outage-arena", Workload: "demo-api", Timestamp: now, Value: 3}
	tools := &monitorToolFake{now: now, noDefaultMetric: true, logSamples: []toolapi.DetectionSample{logSignal}}
	peers := &monitorPeerFake{now: now, diagnosisStatus: model.DiagnosisInconclusive}
	service := monitorService(now, tools, peers)
	service.VerificationCount = 2

	first, err := service.Scan(context.Background(), ScanRequest{})
	if err != nil || len(first.Outcomes) != 0 {
		t.Fatalf("first log observation = %#v, %v", first, err)
	}
	tools.logSamples = nil
	tools.traceSamples = []toolapi.DetectionSample{traceSignal}
	second, err := service.Scan(context.Background(), ScanRequest{})
	if err != nil || len(second.Outcomes) != 0 {
		t.Fatalf("first trace observation reused the log counter: %#v, %v", second, err)
	}
	third, err := service.Scan(context.Background(), ScanRequest{})
	if err != nil || len(third.Outcomes) != 1 {
		t.Fatalf("second trace observation did not verify: %#v, %v", third, err)
	}
}

func TestConcurrentTelemetrySignalsProduceOneWorkloadIncident(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 6, 57, 0, 0, time.UTC)
	tools := &monitorToolFake{
		now: now,
		logSamples: []toolapi.DetectionSample{{
			Namespace: "outage-arena", Workload: "demo-api", Timestamp: now, Value: 5,
		}},
		traceSamples: []toolapi.DetectionSample{{
			Namespace: "outage-arena", Workload: "demo-api", Timestamp: now, Value: 3,
		}},
	}
	peers := &monitorPeerFake{now: now, diagnosisStatus: model.DiagnosisInconclusive}
	service := monitorService(now, tools, peers)
	service.VerificationCount = 1
	result, err := service.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Candidates != 3 || len(result.Outcomes) != 1 {
		t.Fatalf("cross-signal dedupe result = %#v, want three candidates and one incident", result)
	}
}

func TestLiveLogSignalRequiresExplicitProvenanceOptIn(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 6, 58, 0, 0, time.UTC)
	tools := &monitorToolFake{
		now: now, noDefaultMetric: true,
		logSamples: []toolapi.DetectionSample{{
			Namespace: "outage-arena", Workload: "demo-api", Timestamp: now, Value: 5,
		}},
	}
	peers := &monitorPeerFake{now: now, diagnosisStatus: model.DiagnosisConfirmed}
	service := monitorService(now, tools, peers)
	service.VerificationCount = 1
	service.DryRun = false

	result, err := service.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outcomes) != 1 {
		t.Fatalf("outcomes = %#v, want one policy escalation", result.Outcomes)
	}
	outcome := result.Outcomes[0]
	if outcome.Status != "escalated" || outcome.Incident.State != model.IncidentEscalated || outcome.Grant != nil {
		t.Fatalf("untrusted log identity authorized a live action: %#v", outcome)
	}
	if outcome.Report == nil || outcome.Report.Report.Reason != model.ReportReasonPolicyDenied {
		t.Fatalf("blocked live log action did not produce a terminal policy report: %#v", outcome.Report)
	}
	if len(peers.kinds) != 2 || peers.kinds[0] != model.MessageInvestigationRequest || peers.kinds[1] != model.MessageIncidentReportRequest {
		t.Fatalf("unexpected live log workflow messages: %v", peers.kinds)
	}
}

func TestRuleCannotMislabelLogToolAsTrustedMetricEvidence(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 6, 58, 30, 0, time.UTC)
	tools := &monitorToolFake{
		now: now, noDefaultMetric: true,
		logSamples: []toolapi.DetectionSample{{
			Namespace: "outage-arena", Workload: "demo-api", Timestamp: now, Value: 5,
		}},
	}
	peers := &monitorPeerFake{now: now, diagnosisStatus: model.DiagnosisConfirmed}
	service := monitorService(now, tools, peers)
	service.Rules = []Rule{{
		ID: "mislabelled-log-rule", Tool: toolapi.ToolQueryLogSignals, Source: model.EvidenceMetrics,
		TemplateID: toolapi.LogErrorBurst5m, Threshold: 5, Severity: model.SeverityWarning,
		Summary: "mislabelled log signal",
	}}
	service.VerificationCount = 1
	service.DryRun = false
	service.AllowLogTraceActions = true

	result, err := service.Scan(context.Background(), ScanRequest{})
	if err == nil {
		t.Fatal("rule with a mismatched tool/source trust label was accepted")
	}
	if result.Candidates != 0 || len(result.Outcomes) != 0 || len(peers.kinds) != 0 {
		t.Fatalf("mislabelled rule reached the incident workflow: result=%#v peers=%v", result, peers.kinds)
	}
}

func TestDetectionResultValidationFailsClosed(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 6, 59, 0, 0, time.UTC)
	valid := toolapi.DetectionSample{
		Namespace: "outage-arena", Workload: "demo-api", Timestamp: now, Value: 5,
	}
	tests := []struct {
		name    string
		samples []toolapi.DetectionSample
		start   time.Time
		end     time.Time
	}{
		{name: "cross namespace", samples: []toolapi.DetectionSample{{Namespace: "other", Workload: "demo-api", Timestamp: now, Value: 5}}, start: now.Add(-5 * time.Minute), end: now},
		{name: "fractional count", samples: []toolapi.DetectionSample{{Namespace: "outage-arena", Workload: "demo-api", Timestamp: now, Value: 1.5}}, start: now.Add(-5 * time.Minute), end: now},
		{name: "stale window", samples: []toolapi.DetectionSample{valid}, start: now.Add(-25 * time.Minute), end: now.Add(-20 * time.Minute)},
		{name: "duplicate identity", samples: []toolapi.DetectionSample{valid, valid}, start: now.Add(-5 * time.Minute), end: now},
		{name: "too many groups", samples: make([]toolapi.DetectionSample, maxDetectionSamples+1), start: now.Add(-5 * time.Minute), end: now},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := validateNormalizedSamples(test.samples, "outage-arena", test.start, test.end, now); err == nil {
				t.Fatal("malformed detection result was accepted")
			}
		})
	}
}

func TestFreshHealthySnapshotStopsBeforeDelegation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 7, 0, 0, 0, time.UTC)
	tools := &monitorToolFake{now: now, healthySnapshot: true}
	peers := &monitorPeerFake{now: now, diagnosisStatus: model.DiagnosisConfirmed}
	service := monitorService(now, tools, peers)
	service.VerificationCount = 1
	result, err := service.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outcomes) != 1 || result.Outcomes[0].Status != "resolved_without_action" {
		t.Fatalf("self-recovered workload did not stop before delegation: %#v", result.Outcomes)
	}
	if result.Outcomes[0].Grant != nil || len(peers.endpoints) != 2 || peers.kinds[1] != model.MessageIncidentReportRequest {
		t.Fatalf("self-recovered workload was delegated: outcome=%#v peers=%v", result.Outcomes[0], peers.endpoints)
	}
}

func TestPendingVerificationBlocksRedelegationAndResolvesOriginalIncident(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 7, 15, 0, 0, time.UTC)
	tools := &monitorToolFake{now: now}
	peers := &monitorPeerFake{now: now, diagnosisStatus: model.DiagnosisConfirmed}
	service := monitorService(now, tools, peers)
	service.VerificationCount = 1
	_, incident := installPendingVerification(t, service, now, 30*time.Second)

	first, err := service.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Outcomes) != 1 || first.Outcomes[0].Status != "verification_pending" {
		t.Fatalf("first pending scan = %#v", first.Outcomes)
	}
	if len(peers.endpoints) != 0 {
		t.Fatalf("pending action caused new delegation: %v", peers.endpoints)
	}

	tools.healthySnapshot = true
	second, err := service.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Outcomes) != 1 || second.Outcomes[0].Status != "resolved" || second.Outcomes[0].Incident.ID != incident.ID {
		t.Fatalf("resolved pending scan = %#v", second.Outcomes)
	}
	if len(peers.endpoints) != 1 || peers.kinds[0] != model.MessageIncidentReportRequest {
		t.Fatalf("resolved pending action did not produce one report request: %v (%v)", peers.endpoints, peers.kinds)
	}
}

func TestPendingVerificationRunsWhenMetricQueryFails(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 7, 20, 0, 0, time.UTC)
	tools := &monitorToolFake{now: now, healthySnapshot: true, metricErr: fmt.Errorf("metrics unavailable")}
	peers := &monitorPeerFake{now: now, diagnosisStatus: model.DiagnosisConfirmed}
	service := monitorService(now, tools, peers)
	key, incident := installPendingVerification(t, service, now, 30*time.Second)

	result, err := service.Scan(context.Background(), ScanRequest{})
	if err == nil {
		t.Fatal("metric query failure was not returned")
	}
	if len(result.Outcomes) != 1 || result.Outcomes[0].Status != "resolved" || result.Outcomes[0].Incident.ID != incident.ID {
		t.Fatalf("pending verification was starved by metric failure: %#v", result.Outcomes)
	}
	if _, pending := service.pending(key); pending {
		t.Fatal("resolved pending verification was retained")
	}
	if len(peers.endpoints) != 1 || peers.kinds[0] != model.MessageIncidentReportRequest {
		t.Fatalf("metric failure changed the resolved incident workflow: %v (%v)", peers.endpoints, peers.kinds)
	}
}

func TestResponseValidationBindsCorrelationAndCausation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 7, 30, 0, 0, time.UTC)
	envelope, err := model.NewEnvelope(
		"response", "incident-1", "correlation-1", "request-1",
		model.AgentInvestigator, model.AgentMonitor, model.MessageDiagnosisReport, now,
		map[string]string{"status": "ok"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateResponse(
		envelope, "incident-1", "correlation-1", "request-1",
		model.AgentInvestigator, model.AgentMonitor, model.MessageDiagnosisReport,
	); err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}
	for name, mutate := range map[string]func(*model.Envelope){
		"correlation": func(value *model.Envelope) { value.CorrelationID = "other-correlation" },
		"causation":   func(value *model.Envelope) { value.CausationID = "other-request" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := envelope
			mutate(&changed)
			if err := validateResponse(
				changed, "incident-1", "correlation-1", "request-1",
				model.AgentInvestigator, model.AgentMonitor, model.MessageDiagnosisReport,
			); err == nil {
				t.Fatal("mismatched response chain was accepted")
			}
		})
	}
}

func TestReceiptValidationBindsExactGrantAndDryRunSemantics(t *testing.T) {
	t.Parallel()
	target := model.ResourceTarget{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "outage-arena", Name: "demo-api"}
	grant := model.DelegationGrant{
		GrantID: "grant-1", IncidentID: "incident-1", DryRun: true,
		Action: model.ActionSpec{Kind: model.ActionRestartDeployment, Target: target},
	}
	receipt := model.ActionReceipt{
		GrantID: grant.GrantID, IncidentID: grant.IncidentID, DryRun: true, Outcome: model.ActionDryRun,
		Action: grant.Action,
	}
	if err := validateReceiptForGrant(receipt, grant); err != nil {
		t.Fatalf("matching receipt rejected: %v", err)
	}
	receipt.GrantID = "another-grant"
	if err := validateReceiptForGrant(receipt, grant); err == nil {
		t.Fatal("receipt for another grant was accepted")
	}
	receipt.GrantID = grant.GrantID
	receipt.Outcome = model.ActionSucceeded
	if err := validateReceiptForGrant(receipt, grant); err == nil {
		t.Fatal("successful receipt was accepted for a dry-run grant")
	}
}

func TestPostGrantUnverifiedOutcomesProduceSignedEscalationReport(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 7, 35, 0, 0, time.UTC)
	tests := []struct {
		name              string
		remediationErr    error
		mismatchedReceipt bool
	}{
		{name: "expired grant", remediationErr: model.NewError(model.CodeGrantExpired, "grant expired at Operator")},
		{name: "replayed grant", remediationErr: model.NewError(model.CodeReplayedGrant, "grant replay was not recoverable")},
		{name: "execution error", remediationErr: model.NewError(model.CodeExecutionFailed, "action backend returned no receipt")},
		{
			name: "uncertain recovery after policy denial",
			remediationErr: model.WrapError(
				model.CodeExecutionFailed,
				"delegated execution outcome is uncertain and requires reconciliation",
				model.NewError(model.CodePolicyDenied, "current policy no longer authorizes a retry"),
			),
		},
		{name: "transport failure", remediationErr: fmt.Errorf("operator connection reset")},
		{name: "mismatched receipt", mismatchedReceipt: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tools := &monitorToolFake{now: now}
			peers := &monitorPeerFake{
				now: now, diagnosisStatus: model.DiagnosisConfirmed,
				remediationErr: test.remediationErr, mismatchedReceipt: test.mismatchedReceipt,
			}
			service := monitorService(now, tools, peers)
			service.VerificationCount = 1
			privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
			signer, err := security.NewSigner(privateKey, "monitor-action-test-key")
			if err != nil {
				t.Fatal(err)
			}
			service.Signer = signer
			service.Policy = allowProposalPolicy{}

			result, err := service.Scan(context.Background(), ScanRequest{})
			if err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			if len(result.Outcomes) != 1 {
				t.Fatalf("outcomes = %#v, want one escalated incident", result.Outcomes)
			}
			outcome := result.Outcomes[0]
			if outcome.Status != "escalated" || outcome.Incident.State != model.IncidentEscalated {
				t.Fatalf("post-grant outcome = %#v, want terminal escalation", outcome)
			}
			if outcome.Grant == nil || outcome.Receipt != nil {
				t.Fatalf("untrusted receipt was retained: grant=%#v receipt=%#v", outcome.Grant, outcome.Receipt)
			}
			if outcome.Report == nil || outcome.Report.Report.Reason != model.ReportReasonActionOutcomeUnverified {
				t.Fatalf("post-grant failure report = %#v, want action_outcome_unverified", outcome.Report)
			}
			if peers.remediationCalls != 1 || len(peers.reportRequests) != 1 {
				t.Fatalf("Operator calls = remediation %d, reports %d; want one each", peers.remediationCalls, len(peers.reportRequests))
			}
			request := peers.reportRequests[0]
			if request.GrantID != outcome.Grant.GrantID || request.ReceiptID != "" {
				t.Fatalf("failure report did not carry the exact grant-only ambiguity reference: %#v", request)
			}
		})
	}
}

func TestValidatedFailedReceiptProducesExactActionFailureReport(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 7, 37, 0, 0, time.UTC)
	tools := &monitorToolFake{now: now}
	peers := &monitorPeerFake{
		now: now, diagnosisStatus: model.DiagnosisConfirmed,
		remediationOutcome: model.ActionFailed,
	}
	service := monitorService(now, tools, peers)
	service.VerificationCount = 1
	service.DryRun = false
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{44}, ed25519.SeedSize))
	signer, err := security.NewSigner(privateKey, "monitor-failed-receipt-test-key")
	if err != nil {
		t.Fatal(err)
	}
	service.Signer = signer
	service.Policy = allowProposalPolicy{}

	result, err := service.Scan(context.Background(), ScanRequest{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(result.Outcomes) != 1 {
		t.Fatalf("outcomes = %#v, want one failed incident", result.Outcomes)
	}
	outcome := result.Outcomes[0]
	if outcome.Status != string(model.ActionFailed) || outcome.Incident.State != model.IncidentFailed || outcome.Receipt == nil {
		t.Fatalf("validated failed receipt did not produce a failed incident: %#v", outcome)
	}
	if outcome.Report == nil || outcome.Report.Report.Reason != model.ReportReasonActionFailed || outcome.Report.Report.Execution == nil {
		t.Fatalf("validated failed receipt did not produce an execution-backed action_failed report: %#v", outcome.Report)
	}
	execution := outcome.Report.Report.Execution
	if execution.GrantID != outcome.Grant.GrantID || execution.ReceiptID != outcome.Receipt.ReceiptID ||
		!execution.Action.Equal(outcome.Receipt.Action) || execution.Outcome != outcome.Receipt.Outcome ||
		execution.DryRun != outcome.Receipt.DryRun || !execution.CompletedAt.Equal(outcome.Receipt.CompletedAt) {
		t.Fatalf("action_failed report did not preserve the exact validated receipt: report=%#v receipt=%#v", execution, outcome.Receipt)
	}
}

func TestMonitorRejectsReportFieldsNotAuthorizedBySignedRequest(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 7, 40, 0, 0, time.UTC)
	tests := []struct {
		name           string
		forgeExecution bool
		forgeReportID  bool
		forgeCreatedAt bool
	}{
		{name: "execution projection", forgeExecution: true},
		{name: "report id", forgeReportID: true},
		{name: "creation time", forgeCreatedAt: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tools := &monitorToolFake{now: now}
			peers := &monitorPeerFake{
				now: now, diagnosisStatus: model.DiagnosisConfirmed,
				forgeReportExecution: test.forgeExecution,
				forgeReportID:        test.forgeReportID,
				forgeReportCreatedAt: test.forgeCreatedAt,
			}
			service := monitorService(now, tools, peers)
			service.VerificationCount = 1
			privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{43}, ed25519.SeedSize))
			signer, err := security.NewSigner(privateKey, "monitor-report-binding-test-key")
			if err != nil {
				t.Fatal(err)
			}
			service.Signer = signer
			service.Policy = allowProposalPolicy{}

			result, err := service.Scan(context.Background(), ScanRequest{})
			if err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			if len(result.Outcomes) != 1 {
				t.Fatalf("outcomes = %#v, want one dry-run incident", result.Outcomes)
			}
			outcome := result.Outcomes[0]
			if outcome.Report != nil || !strings.Contains(outcome.Detail, "incident report response was rejected") {
				t.Fatalf("Monitor accepted report data absent from its signed request: %#v", outcome)
			}
		})
	}
}

func remediatingIncident(t *testing.T, now time.Time, target model.ResourceTarget) model.Incident {
	t.Helper()
	incident, err := model.NewIncident("incident-pending", model.IncidentSignal{
		ID: "signal-1", Source: "victoriametrics", RuleID: DefaultRules()[0].ID,
		Fingerprint: workloadFingerprint(target.Namespace, target.Name),
		Summary:     "deployment unavailable", Severity: model.SeverityCritical,
		ObservedAt: now, Labels: map[string]string{"namespace": target.Namespace, "deployment": target.Name},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []model.IncidentState{
		model.IncidentVerifying, model.IncidentVerified, model.IncidentInvestigating,
		model.IncidentDiagnosed, model.IncidentRemediationPending, model.IncidentRemediating,
	} {
		if err := incident.Transition(state, now); err != nil {
			t.Fatal(err)
		}
	}
	return incident
}

func installPendingVerification(t *testing.T, service *Service, now time.Time, age time.Duration) (string, model.Incident) {
	t.Helper()
	target := model.ResourceTarget{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "outage-arena", Name: "demo-api"}
	startedAt := now.Add(-age)
	incident := remediatingIncident(t, startedAt, target)
	key := workloadFingerprint(target.Namespace, target.Name)
	service.tracker = map[string]*observation{
		key: {
			Dispatched: startedAt,
			Pending: &pendingVerification{
				Incident: incident,
				Diagnosis: model.DiagnosisReport{
					SchemaVersion: model.SchemaVersionV1, ID: "diagnosis-1", IncidentID: incident.ID,
				},
				Grant: model.DelegationGrant{
					GrantID: "grant-1", IncidentID: incident.ID,
					Action: model.ActionSpec{Kind: model.ActionRestartDeployment, Target: target},
				},
				Receipt: model.ActionReceipt{
					ReceiptID: "receipt-1", GrantID: "grant-1", IncidentID: incident.ID,
					Action:  model.ActionSpec{Kind: model.ActionRestartDeployment, Target: target},
					Outcome: model.ActionSucceeded,
				},
				Target: target, StartedAt: startedAt,
				CorrelationID: incident.ID, CausationID: "receipt-message-1",
			},
		},
	}
	return key, incident
}

func monitorService(now time.Time, tools *monitorToolFake, peers *monitorPeerFake) *Service {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, ed25519.SeedSize))
	signer, err := security.NewSigner(privateKey, "monitor-report-test-key")
	if err != nil {
		panic(err)
	}
	return &Service{
		Tools: tools, Peers: peers, Clock: monitorClock{now: now}, IDs: &monitorIDs{},
		ReportSigner: signer,
		Namespace:    "outage-arena", InvestigatorURL: "http://investigator", OperatorURL: "http://operator",
		Rules: DefaultRules(), VerificationCount: 2, Cooldown: time.Minute,
		DelegationTTL: 2 * time.Minute, RequestTimeout: time.Second, EvidenceBudget: 4, DryRun: true,
	}
}

func durableActionMonitor(
	t *testing.T,
	now time.Time,
	tools *monitorToolFake,
	peers *monitorPeerFake,
	state ports.MonitorStateStore,
	instanceID string,
) *Service {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{52}, ed25519.SeedSize))
	signer, err := security.NewSigner(privateKey, "durable-monitor-test-key")
	if err != nil {
		t.Fatal(err)
	}
	service := monitorService(now, tools, peers)
	service.Signer = signer
	service.ReportSigner = signer
	service.Policy = allowProposalPolicy{}
	service.DryRun = false
	service.VerificationCount = 1
	service.StateStore = state
	service.InstanceID = instanceID
	service.StateLease = time.Minute
	return service
}

type monitorToolFake struct {
	now                  time.Time
	calls                []string
	snapshotCalls        int
	samples              []toolapi.MetricSample
	logSamples           []toolapi.DetectionSample
	traceSamples         []toolapi.DetectionSample
	noDefaultMetric      bool
	healthySnapshot      bool
	healthyAfterSnapshot int
	metricErr            error
}

func (*monitorToolFake) Discover(context.Context) ([]string, error) {
	return []string{
		toolapi.ToolQueryMetrics, toolapi.ToolQueryLogSignals,
		toolapi.ToolQueryTraceSignals, toolapi.ToolGetWorkloadSnapshot,
	}, nil
}

func (f *monitorToolFake) Call(_ context.Context, name string, input, output any) error {
	f.calls = append(f.calls, name)
	switch name {
	case toolapi.ToolQueryMetrics:
		if f.metricErr != nil {
			return f.metricErr
		}
		request, ok := input.(toolapi.QueryMetricsInput)
		if !ok {
			return fmt.Errorf("unexpected metric input %T", input)
		}
		result, ok := output.(*toolapi.QueryMetricsOutput)
		if !ok {
			return fmt.Errorf("unexpected metric output %T", output)
		}
		result.TemplateID = request.TemplateID
		result.ObservedAt = f.now
		result.Samples = append([]toolapi.MetricSample(nil), f.samples...)
		if len(result.Samples) == 0 && !f.noDefaultMetric {
			result.Samples = []toolapi.MetricSample{{
				Labels:    map[string]string{"namespace": "outage-arena", "deployment": "demo-api"},
				Timestamp: f.now, Value: 1,
			}}
		}
		return nil
	case toolapi.ToolGetWorkloadSnapshot:
		f.snapshotCalls++
		request, ok := input.(toolapi.GetWorkloadSnapshotInput)
		if !ok {
			return fmt.Errorf("unexpected snapshot input %T", input)
		}
		result, ok := output.(*toolapi.GetWorkloadSnapshotOutput)
		if !ok {
			return fmt.Errorf("unexpected snapshot output %T", output)
		}
		result.Snapshot = toolapi.WorkloadSnapshot{
			Target:          model.ResourceTarget{APIVersion: "apps/v1", Kind: request.Kind, Namespace: request.Namespace, Name: request.Name},
			ResourceVersion: "rv-1", Generation: 1, ObservedGeneration: 1,
			DesiredReplicas: 1, ReadyReplicas: 0, AvailableReplicas: 0, UnavailableReplicas: 1,
			ObservedAt: f.now,
		}
		if f.healthySnapshot || f.healthyAfterSnapshot > 0 && f.snapshotCalls >= f.healthyAfterSnapshot {
			result.Snapshot.ReadyReplicas = 1
			result.Snapshot.AvailableReplicas = 1
			result.Snapshot.UnavailableReplicas = 0
		}
		return nil
	case toolapi.ToolQueryLogSignals:
		request, ok := input.(toolapi.QueryLogSignalsInput)
		if !ok {
			return fmt.Errorf("unexpected log signal input %T", input)
		}
		result, ok := output.(*toolapi.QueryLogSignalsOutput)
		if !ok {
			return fmt.Errorf("unexpected log signal output %T", output)
		}
		result.TemplateID = request.TemplateID
		result.WindowStart = f.now.Add(-5 * time.Minute)
		result.WindowEnd = f.now
		result.Samples = append([]toolapi.DetectionSample(nil), f.logSamples...)
		return nil
	case toolapi.ToolQueryTraceSignals:
		request, ok := input.(toolapi.QueryTraceSignalsInput)
		if !ok {
			return fmt.Errorf("unexpected trace signal input %T", input)
		}
		result, ok := output.(*toolapi.QueryTraceSignalsOutput)
		if !ok {
			return fmt.Errorf("unexpected trace signal output %T", output)
		}
		result.TemplateID = request.TemplateID
		result.WindowStart = f.now.Add(-5 * time.Minute)
		result.WindowEnd = f.now
		result.Samples = append([]toolapi.DetectionSample(nil), f.traceSamples...)
		return nil
	default:
		return fmt.Errorf("unexpected tool %q", name)
	}
}

func (*monitorToolFake) Close() error { return nil }

func (f *monitorToolFake) count(name string) int {
	total := 0
	for _, call := range f.calls {
		if call == name {
			total++
		}
	}
	return total
}

type monitorPeerFake struct {
	now                   time.Time
	diagnosisStatus       model.DiagnosisStatus
	remediationErr        error
	remediationOutcome    model.ActionOutcome
	mismatchedReceipt     bool
	remediationCalls      int
	remediationGrantIDs   []string
	lastReceipt           *model.ActionReceipt
	reportRequests        []model.IncidentReportRequest
	reportRequestAttempts []model.IncidentReportRequest
	reportErr             error
	rejectReportKeyID     string
	forgeReportExecution  bool
	forgeReportID         bool
	forgeReportCreatedAt  bool
	endpoints             []string
	kinds                 []model.MessageKind
}

func (f *monitorPeerFake) Send(_ context.Context, endpoint string, envelope model.Envelope, response any) error {
	f.endpoints = append(f.endpoints, endpoint)
	f.kinds = append(f.kinds, envelope.Kind)
	if endpoint == "http://operator" {
		if envelope.Kind == model.MessageRemediationRequest {
			f.remediationCalls++
			var grant model.DelegationGrant
			if err := envelope.DecodePayload(&grant); err != nil {
				return err
			}
			f.remediationGrantIDs = append(f.remediationGrantIDs, grant.GrantID)
			if f.remediationErr != nil {
				return f.remediationErr
			}
			grantID := grant.GrantID
			if f.mismatchedReceipt {
				grantID = "different-grant"
			}
			outcome := f.remediationOutcome
			if outcome == "" {
				if grant.DryRun {
					outcome = model.ActionDryRun
				} else {
					outcome = model.ActionSucceeded
				}
			}
			receipt := model.ActionReceipt{
				SchemaVersion: model.SchemaVersionV1, ReceiptID: "receipt-1",
				GrantID: grantID, IncidentID: grant.IncidentID, Action: grant.Action,
				Outcome: outcome, DryRun: grant.DryRun, StartedAt: f.now, CompletedAt: f.now,
				AuditRef: "audit-1",
			}
			if outcome == model.ActionFailed || outcome == model.ActionRejected {
				receipt.ErrorCode = model.CodeExecutionFailed
				receipt.ErrorMessage = "bounded fixture action failure"
			}
			f.lastReceipt = &receipt
			reply, err := model.NewEnvelope(
				"receipt-message", grant.IncidentID, envelope.CorrelationID, envelope.MessageID,
				model.AgentOperator, model.AgentMonitor, model.MessageActionReceipt, f.now, receipt,
			)
			if err != nil {
				return err
			}
			destination, ok := response.(*model.Envelope)
			if !ok {
				return fmt.Errorf("unexpected peer response destination %T", response)
			}
			*destination = reply
			return nil
		}
		if envelope.Kind != model.MessageIncidentReportRequest {
			return fmt.Errorf("unexpected Operator message kind %q", envelope.Kind)
		}
		var request model.IncidentReportRequest
		if err := envelope.DecodePayload(&request); err != nil {
			return err
		}
		if err := request.ValidateSigned(); err != nil {
			return fmt.Errorf("Monitor sent an unauthorized report request: %w", err)
		}
		f.reportRequestAttempts = append(f.reportRequestAttempts, request)
		if f.rejectReportKeyID != "" && request.Signature.KeyID == f.rejectReportKeyID {
			return model.NewError(model.CodeInvalidSignature, "incident report signing key is retired")
		}
		if !f.now.Before(request.ExpiresAt) {
			return model.NewError(model.CodeGrantExpired, "incident report request has expired")
		}
		if f.reportErr != nil {
			return f.reportErr
		}
		f.reportRequests = append(f.reportRequests, request)
		reportID, err := request.DeterministicReportID()
		if err != nil {
			return err
		}
		report := model.IncidentReport{
			SchemaVersion: model.SchemaVersionV1, ReportID: reportID, RequestID: request.RequestID,
			IncidentID: request.IncidentID, CorrelationID: request.CorrelationID,
			DiagnosisReportID: request.DiagnosisReportID, Target: request.Target,
			FinalState: request.FinalState, Reason: request.Reason, Summary: request.Reason.Summary(),
			CreatedAt: request.ReportCreatedAt,
		}
		if request.ReceiptID != "" && f.lastReceipt != nil {
			report.Execution = &model.IncidentReportExecution{
				GrantID: request.GrantID, ReceiptID: request.ReceiptID, Action: f.lastReceipt.Action,
				Outcome: f.lastReceipt.Outcome, DryRun: f.lastReceipt.DryRun, CompletedAt: f.lastReceipt.CompletedAt,
			}
		}
		if f.forgeReportID {
			report.ReportID = "report-forged"
		}
		if f.forgeReportCreatedAt {
			report.CreatedAt = request.ReportCreatedAt.Add(time.Second)
		}
		if f.forgeReportExecution {
			replicas := int32(2)
			report.Execution = &model.IncidentReportExecution{
				GrantID: request.GrantID, ReceiptID: request.ReceiptID,
				Action: model.ActionSpec{
					Kind: model.ActionScaleDeployment, Target: request.Target,
					Parameters: model.ActionParameters{Replicas: &replicas},
				},
				Outcome: model.ActionDryRun, DryRun: true, CompletedAt: f.now,
			}
		}
		if err := report.Seal(); err != nil {
			return err
		}
		result := model.IncidentReportResult{
			Report: report,
			Notification: model.NotificationReceipt{
				ReportID: report.ReportID, IdempotencyKey: report.RequestID,
				Channel: model.NotificationChannelWhatsApp, Status: model.NotificationDelivered,
				ProviderMessageID: "wamid.test", AttemptedAt: f.now,
			},
		}
		reply, err := model.NewEnvelope(
			"report-message", request.IncidentID, envelope.CorrelationID, envelope.MessageID,
			model.AgentOperator, model.AgentMonitor, model.MessageIncidentReport, f.now, result,
		)
		if err != nil {
			return err
		}
		destination, ok := response.(*model.Envelope)
		if !ok {
			return fmt.Errorf("unexpected peer response destination %T", response)
		}
		*destination = reply
		return nil
	}
	if endpoint != "http://investigator" {
		return fmt.Errorf("unexpected peer endpoint %q", endpoint)
	}
	var request model.InvestigationRequest
	if err := envelope.DecodePayload(&request); err != nil {
		return err
	}
	evidenceIDs := []string{"evidence-1"}
	report := model.DiagnosisReport{
		SchemaVersion: model.SchemaVersionV1, ID: "diagnosis-1", IncidentID: request.Incident.ID,
		Status: f.diagnosisStatus, Confidence: 0.9, EvidenceIDs: evidenceIDs, CreatedAt: f.now,
	}
	if f.diagnosisStatus == model.DiagnosisConfirmed {
		target := request.Scope.Targets[0]
		report.RootCause = "fixture dependency timeout"
		report.Proposals = []model.ActionProposal{{
			ID:        "proposal-1",
			Action:    model.ActionSpec{Kind: model.ActionRestartDeployment, Target: target},
			Rationale: "restart the unhealthy fixture deployment", Confidence: 0.9,
			EvidenceIDs: evidenceIDs, SuccessCriteria: []string{"deployment becomes available"},
		}}
	}
	if err := report.Seal(); err != nil {
		return err
	}
	reply, err := model.NewEnvelope(
		"diagnosis-message", request.Incident.ID, envelope.CorrelationID, envelope.MessageID,
		model.AgentInvestigator, model.AgentMonitor, model.MessageDiagnosisReport, f.now, report,
	)
	if err != nil {
		return err
	}
	destination, ok := response.(*model.Envelope)
	if !ok {
		return fmt.Errorf("unexpected peer response destination %T", response)
	}
	*destination = reply
	return nil
}

type allowProposalPolicy struct{}

func (allowProposalPolicy) AuthorizeProposal(model.DiagnosisReport, model.DelegationGrant, time.Time) model.PolicyDecision {
	return model.Allow()
}

type monitorClock struct{ now time.Time }

func (c monitorClock) Now() time.Time { return c.now }

type monitorIDs struct{ next int }

func (g *monitorIDs) NewID() string {
	g.next++
	return fmt.Sprintf("monitor-id-%d", g.next)
}

type monitorStateFake struct {
	mu      sync.Mutex
	lease   ports.MonitorLease
	payload []byte
	version int64
	next    int64
}

func (s *monitorStateFake) AcquireMonitorLease(
	_ context.Context,
	namespace, owner string,
	duration time.Duration,
) (ports.MonitorLease, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lease.Owner != "" && s.lease.Owner != owner {
		return ports.MonitorLease{}, false, nil
	}
	s.next++
	s.lease = ports.MonitorLease{
		Namespace: namespace, Owner: owner, Token: fmt.Sprintf("lease-%d", s.next),
		FencingToken: s.next, LeaseUntil: time.Now().Add(duration),
	}
	return s.lease, true, nil
}

func (s *monitorStateFake) RenewMonitorLease(
	_ context.Context,
	lease ports.MonitorLease,
	duration time.Duration,
) (ports.MonitorLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !sameMonitorLease(s.lease, lease) {
		return ports.MonitorLease{}, errors.New("lease lost")
	}
	s.lease.LeaseUntil = time.Now().Add(duration)
	return s.lease, nil
}

func (s *monitorStateFake) LoadMonitorCheckpoint(
	_ context.Context,
	lease ports.MonitorLease,
) (ports.MonitorCheckpoint, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !sameMonitorLease(s.lease, lease) {
		return ports.MonitorCheckpoint{}, false, errors.New("lease lost")
	}
	if len(s.payload) == 0 {
		return ports.MonitorCheckpoint{}, false, nil
	}
	return ports.MonitorCheckpoint{
		Payload: append([]byte(nil), s.payload...), Version: s.version,
		FencingToken: lease.FencingToken, UpdatedAt: time.Now(),
	}, true, nil
}

func (s *monitorStateFake) SaveMonitorCheckpoint(
	_ context.Context,
	lease ports.MonitorLease,
	payload []byte,
) (ports.MonitorCheckpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !sameMonitorLease(s.lease, lease) {
		return ports.MonitorCheckpoint{}, errors.New("lease lost")
	}
	s.version++
	s.payload = append(s.payload[:0], payload...)
	return ports.MonitorCheckpoint{
		Payload: append([]byte(nil), payload...), Version: s.version,
		FencingToken: lease.FencingToken, UpdatedAt: time.Now(),
	}, nil
}

func (s *monitorStateFake) expire() {
	s.mu.Lock()
	s.lease = ports.MonitorLease{}
	s.mu.Unlock()
}

func sameMonitorLease(left, right ports.MonitorLease) bool {
	return left.Namespace == right.Namespace && left.Owner == right.Owner && left.Token == right.Token &&
		left.FencingToken == right.FencingToken
}
