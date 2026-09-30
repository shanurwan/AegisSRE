package model

import (
	"encoding/json"
	"testing"
	"time"
)

func testSignal(now time.Time) IncidentSignal {
	return IncidentSignal{
		ID:          "signal-1",
		Source:      "fixture",
		RuleID:      "deployment-unavailable",
		Fingerprint: "outage-arena/demo-api",
		Summary:     "deployment has no available replicas",
		Severity:    SeverityCritical,
		ObservedAt:  now,
		Labels:      map[string]string{"namespace": "outage-arena"},
	}
}

func testAction(replicas int32) ActionSpec {
	return ActionSpec{
		Kind: ActionScaleDeployment,
		Target: ResourceTarget{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
			Namespace:  "outage-arena",
			Name:       "demo-api",
		},
		Parameters: ActionParameters{Replicas: &replicas},
	}
}

func TestIncidentTransitionRejectsIllegalMutation(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	incident, err := NewIncident("incident-1", testSignal(now), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := incident.Transition(IncidentVerifying, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	before := incident
	if err := incident.Transition(IncidentResolved, now.Add(2*time.Second)); err == nil {
		t.Fatal("expected illegal transition to fail")
	}
	if incident.State != before.State || !incident.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatal("failed transition mutated incident")
	}
	if code, ok := ErrorCodeOf(ValidateIncidentTransition(IncidentResolved, IncidentVerifying)); !ok || code != CodeInvalidStateTransition {
		t.Fatalf("unexpected transition error code: %q, %v", code, ok)
	}
}

func TestEvidenceDigestDetectsTampering(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.FixedZone("MYT", 8*60*60))
	evidence := EvidenceItem{
		ID: "evidence-1", IncidentID: "incident-1", Source: EvidenceMetrics,
		Tool: "metrics_query_template", Query: "deployment_unavailable",
		Summary: "zero replicas available", ObservedAt: now,
		Payload: json.RawMessage(`{"value":1}`),
	}
	if err := evidence.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := evidence.VerifyDigest(); err != nil {
		t.Fatalf("sealed evidence did not verify: %v", err)
	}
	evidence.Summary = "tampered"
	if err := evidence.VerifyDigest(); err == nil {
		t.Fatal("tampered evidence unexpectedly verified")
	}
}

func TestDiagnosisDigestAndProposalLookup(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	report := DiagnosisReport{
		SchemaVersion: SchemaVersionV1,
		ID:            "diagnosis-1", IncidentID: "incident-1", Status: DiagnosisConfirmed,
		RootCause: "deployment was scaled to zero", Confidence: 0.98,
		EvidenceIDs: []string{"evidence-1"}, CreatedAt: now,
		Proposals: []ActionProposal{{
			ID: "proposal-1", Action: testAction(1), Rationale: "restore baseline",
			Confidence: 0.98, EvidenceIDs: []string{"evidence-1"},
			SuccessCriteria: []string{"one available replica"},
		}},
	}
	if err := report.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := report.VerifyDigest(); err != nil {
		t.Fatal(err)
	}
	if proposal, ok := report.Proposal("proposal-1"); !ok || proposal.Action.Kind != ActionScaleDeployment {
		t.Fatal("proposal lookup failed")
	}
	report.Proposals[0].Rationale = "tampered"
	if err := report.VerifyDigest(); err == nil {
		t.Fatal("tampered diagnosis unexpectedly verified")
	}
}

func TestEnvelopeStrictPayloadDecode(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	type payload struct {
		Name string `json:"name"`
	}
	envelope, err := NewEnvelope(
		"message-1", "incident-1", "correlation-1", "",
		AgentMonitor, AgentInvestigator, MessageInvestigationRequest, now,
		payload{Name: "demo-api"},
	)
	if err != nil {
		t.Fatal(err)
	}
	var decoded payload
	if err := envelope.DecodePayload(&decoded); err != nil || decoded.Name != "demo-api" {
		t.Fatalf("decode failed: %#v, %v", decoded, err)
	}
	envelope.Payload = json.RawMessage(`{"name":"demo-api","unexpected":true}`)
	if err := envelope.DecodePayload(&decoded); err == nil {
		t.Fatal("unknown payload field unexpectedly accepted")
	}
}

func TestDelegationRequiresBothNarrowAudiences(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	grant := DelegationGrant{
		SchemaVersion: SchemaVersionV1, GrantID: "grant-1", Issuer: AgentMonitor,
		Audiences: []AgentID{AgentOperator}, IncidentID: "incident-1",
		DiagnosisReportID:   "diagnosis-1",
		DiagnosisDigest:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		DiagnosisConfidence: 0.9, EvidenceIDs: []string{"evidence-1"},
		ProposalID: "proposal-1", Action: testAction(1), DryRun: true,
		IdempotencyKey: "action-1", IssuedAt: now, NotBefore: now,
		ExpiresAt: now.Add(time.Minute),
	}
	if err := grant.Validate(); err == nil {
		t.Fatal("grant with missing MCP audience unexpectedly validated")
	}
	grant.Audiences = []AgentID{AgentOperator, AgentMCPAction}
	if err := grant.Validate(); err != nil {
		t.Fatalf("valid unsigned grant rejected: %v", err)
	}
}
