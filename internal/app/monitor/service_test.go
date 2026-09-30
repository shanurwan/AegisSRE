package monitor

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

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
	if len(peers.endpoints) != 1 || peers.endpoints[0] != service.InvestigatorURL {
		t.Fatalf("peer calls after verification = %v, want Investigator only", peers.endpoints)
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
	if len(peers.endpoints) != 1 || peers.endpoints[0] != service.InvestigatorURL {
		t.Fatalf("peer calls = %v, want Investigator only and no Operator delegation", peers.endpoints)
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
	if result.Outcomes[0].Grant != nil || len(peers.endpoints) != 1 {
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
	if len(peers.endpoints) != 0 {
		t.Fatalf("resolved pending action caused new delegation: %v", peers.endpoints)
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
	if len(peers.endpoints) != 0 {
		t.Fatalf("metric failure caused delegation: %v", peers.endpoints)
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

func remediatingIncident(t *testing.T, now time.Time, target model.ResourceTarget) model.Incident {
	t.Helper()
	incident, err := model.NewIncident("incident-pending", model.IncidentSignal{
		ID: "signal-1", Source: "victoriametrics", RuleID: DefaultRules()[0].ID,
		Fingerprint: fingerprint(DefaultRules()[0].ID, target.Namespace, target.Name),
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
	key := fingerprint(DefaultRules()[0].ID, target.Namespace, target.Name)
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
					GrantID: "grant-1", IncidentID: incident.ID,
					Action:  model.ActionSpec{Kind: model.ActionRestartDeployment, Target: target},
					Outcome: model.ActionSucceeded,
				},
				Target: target, StartedAt: startedAt,
			},
		},
	}
	return key, incident
}

func monitorService(now time.Time, tools *monitorToolFake, peers *monitorPeerFake) *Service {
	return &Service{
		Tools: tools, Peers: peers, Clock: monitorClock{now: now}, IDs: &monitorIDs{},
		Namespace: "outage-arena", InvestigatorURL: "http://investigator", OperatorURL: "http://operator",
		Rules: DefaultRules(), VerificationCount: 2, Cooldown: time.Minute,
		DelegationTTL: 2 * time.Minute, RequestTimeout: time.Second, EvidenceBudget: 4, DryRun: true,
	}
}

type monitorToolFake struct {
	now             time.Time
	calls           []string
	samples         []toolapi.MetricSample
	healthySnapshot bool
	metricErr       error
}

func (*monitorToolFake) Discover(context.Context) ([]string, error) {
	return []string{toolapi.ToolQueryMetrics, toolapi.ToolGetWorkloadSnapshot}, nil
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
		if len(result.Samples) == 0 {
			result.Samples = []toolapi.MetricSample{{
				Labels:    map[string]string{"namespace": "outage-arena", "deployment": "demo-api"},
				Timestamp: f.now, Value: 1,
			}}
		}
		return nil
	case toolapi.ToolGetWorkloadSnapshot:
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
		if f.healthySnapshot {
			result.Snapshot.ReadyReplicas = 1
			result.Snapshot.AvailableReplicas = 1
			result.Snapshot.UnavailableReplicas = 0
		}
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
	now             time.Time
	diagnosisStatus model.DiagnosisStatus
	endpoints       []string
}

func (f *monitorPeerFake) Send(_ context.Context, endpoint string, envelope model.Envelope, response any) error {
	f.endpoints = append(f.endpoints, endpoint)
	if endpoint != "http://investigator" {
		return fmt.Errorf("unexpected delegation endpoint %q", endpoint)
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

type monitorClock struct{ now time.Time }

func (c monitorClock) Now() time.Time { return c.now }

type monitorIDs struct{ next int }

func (g *monitorIDs) NewID() string {
	g.next++
	return fmt.Sprintf("monitor-id-%d", g.next)
}
