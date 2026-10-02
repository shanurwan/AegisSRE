package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
)

const (
	MessageScanRequest model.MessageKind = "monitor.scan"
	MessageScanResult  model.MessageKind = "monitor.scan_result"
)

type Rule struct {
	ID         string
	Tool       string
	Source     model.EvidenceSource
	TemplateID string
	Threshold  float64
	Severity   model.Severity
	Summary    string
}

func DefaultRules() []Rule {
	return []Rule{
		{
			ID: "deployment-unavailable", Tool: toolapi.ToolQueryMetrics, Source: model.EvidenceMetrics,
			TemplateID: toolapi.MetricDeploymentUnavailable, Threshold: 1,
			Severity: model.SeverityCritical, Summary: "deployment has unavailable replicas",
		},
		{
			ID: "application-error-burst", Tool: toolapi.ToolQueryLogSignals, Source: model.EvidenceLogs,
			TemplateID: toolapi.LogErrorBurst5m, Threshold: 5,
			Severity: model.SeverityWarning, Summary: "application error volume exceeded the bounded five-minute threshold",
		},
		{
			ID: "trace-error-burst", Tool: toolapi.ToolQueryTraceSignals, Source: model.EvidenceTraces,
			TemplateID: toolapi.TraceErrorCount5m, Threshold: 3,
			Severity: model.SeverityWarning, Summary: "failed traces exceeded the bounded five-minute threshold",
		},
	}
}

type ScanRequest struct {
	Namespace string `json:"namespace,omitempty"`
}

type IncidentOutcome struct {
	Incident  model.Incident              `json:"incident"`
	Diagnosis *model.DiagnosisReport      `json:"diagnosis,omitempty"`
	Grant     *model.DelegationGrant      `json:"grant,omitempty"`
	Receipt   *model.ActionReceipt        `json:"receipt,omitempty"`
	Report    *model.IncidentReportResult `json:"report,omitempty"`
	Status    string                      `json:"status"`
	Detail    string                      `json:"detail,omitempty"`
}

type ScanResult struct {
	ScannedAt  time.Time         `json:"scanned_at"`
	Candidates int               `json:"candidates"`
	Outcomes   []IncidentOutcome `json:"outcomes,omitempty"`
}

type Service struct {
	Tools                ports.ToolCaller
	Peers                ports.PeerMessenger
	Signer               ports.GrantSigner
	ReportSigner         ports.ReportRequestSigner
	Policy               ports.ProposalAuthorizer
	Clock                ports.Clock
	IDs                  ports.IDGenerator
	Audit                ports.Auditor
	Namespace            string
	InvestigatorURL      string
	OperatorURL          string
	Rules                []Rule
	VerificationCount    int
	Cooldown             time.Duration
	DelegationTTL        time.Duration
	RequestTimeout       time.Duration
	EvidenceBudget       int
	DryRun               bool
	AllowLogTraceActions bool

	mu      sync.Mutex
	tracker map[string]*observation
}

type observation struct {
	Consecutive int
	LastSeen    time.Time
	Dispatched  time.Time
	WorkloadKey string
	Pending     *pendingVerification
}

type pendingVerification struct {
	Incident      model.Incident
	Diagnosis     model.DiagnosisReport
	Grant         model.DelegationGrant
	Receipt       model.ActionReceipt
	Target        model.ResourceTarget
	StartedAt     time.Time
	CorrelationID string
	CausationID   string
}

const (
	maxTrackedIncidents    = 4096
	maxDetectionSamples    = 50
	maxExactDetectionCount = 1<<53 - 1
)

func (s *Service) Scan(ctx context.Context, request ScanRequest) (ScanResult, error) {
	if s.Tools == nil || s.Peers == nil || s.Clock == nil || s.IDs == nil {
		return ScanResult{}, errors.New("monitor dependencies are incomplete")
	}
	namespace := request.Namespace
	if namespace == "" {
		namespace = s.Namespace
	}
	if namespace != s.Namespace {
		return ScanResult{}, model.NewError(model.CodeOutOfScope, "scan namespace is not allowed")
	}
	rules := s.Rules
	if len(rules) == 0 {
		rules = DefaultRules()
	}
	now := s.Clock.Now().UTC()
	result := ScanResult{ScannedAt: now}
	seen := make(map[string]struct{})
	pendingChecked := make(map[string]struct{})
	for _, key := range s.pendingNotSeen(nil) {
		if outcome, pending := s.verifyPending(ctx, key, now); pending {
			result.Outcomes = append(result.Outcomes, outcome)
			pendingChecked[key] = struct{}{}
		}
	}

	var scanErrors []error
	succeeded := 0
	for _, rule := range rules {
		source, err := ruleEvidenceSource(rule)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Errorf("evaluate rule %s: %w", rule.ID, err))
			continue
		}
		samples, err := s.evaluateRule(ctx, rule, namespace)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Errorf("evaluate rule %s: %w", rule.ID, err))
			continue
		}
		succeeded++
		for _, sample := range samples {
			if sample.Value < rule.Threshold {
				continue
			}
			deployment := sample.Workload
			if deployment == "" || sample.Namespace != namespace {
				continue
			}
			confirmationKey := fingerprint(rule.ID, namespace, deployment)
			workloadKey := workloadFingerprint(namespace, deployment)
			if _, duplicate := seen[confirmationKey]; duplicate {
				continue
			}
			seen[confirmationKey] = struct{}{}
			result.Candidates++
			if _, checked := pendingChecked[workloadKey]; checked {
				continue
			}
			if outcome, pending := s.verifyPending(ctx, workloadKey, now); pending {
				result.Outcomes = append(result.Outcomes, outcome)
				pendingChecked[workloadKey] = struct{}{}
				continue
			}
			if !s.confirm(confirmationKey, workloadKey, now) {
				continue
			}
			signal := model.IncidentSignal{
				ID: s.IDs.NewID(), Source: string(source), RuleID: rule.ID,
				Fingerprint: workloadKey, Summary: rule.Summary, Severity: rule.Severity,
				ObservedAt: sample.Timestamp,
				Labels:     map[string]string{"namespace": sample.Namespace, "deployment": sample.Workload},
			}
			outcome, err := s.coordinate(ctx, signal, rule.Tool, namespace, deployment, now)
			if err != nil {
				outcome.Status = "failed"
				outcome.Detail = err.Error()
				if outcome.Incident.ID != "" && !outcome.Incident.State.Terminal() {
					_ = outcome.Incident.Transition(model.IncidentFailed, s.Clock.Now())
				}
				if outcome.Grant != nil {
					s.markDispatched(workloadKey, now)
				} else {
					s.resetFailed(confirmationKey, now)
				}
			} else {
				s.markDispatched(workloadKey, now)
			}
			result.Outcomes = append(result.Outcomes, outcome)
		}
	}
	s.resetMissing(seen, now)
	if succeeded == 0 {
		s.resetConfirmations(now)
	}
	return result, errors.Join(scanErrors...)
}

func ruleEvidenceSource(rule Rule) (model.EvidenceSource, error) {
	var expected model.EvidenceSource
	switch rule.Tool {
	case "", toolapi.ToolQueryMetrics:
		expected = model.EvidenceMetrics
	case toolapi.ToolQueryLogSignals:
		expected = model.EvidenceLogs
	case toolapi.ToolQueryTraceSignals:
		expected = model.EvidenceTraces
	default:
		return "", model.NewError(model.CodeInvalidInput, "monitor rule uses an unsupported constrained tool")
	}
	if rule.Source != "" && rule.Source != expected {
		return "", model.NewError(model.CodeInvalidInput, "monitor rule evidence source does not match its constrained tool")
	}
	return expected, nil
}

type detectionSample struct {
	Namespace string
	Workload  string
	Timestamp time.Time
	Value     float64
}

func (s *Service) evaluateRule(ctx context.Context, rule Rule, namespace string) ([]detectionSample, error) {
	switch rule.Tool {
	case "", toolapi.ToolQueryMetrics:
		var output toolapi.QueryMetricsOutput
		if err := s.Tools.Call(ctx, toolapi.ToolQueryMetrics, toolapi.QueryMetricsInput{
			TemplateID: rule.TemplateID, Namespace: namespace,
		}, &output); err != nil {
			return nil, err
		}
		if output.TemplateID != rule.TemplateID {
			return nil, model.NewError(model.CodeExecutionFailed, "metric result template differs from the requested rule template")
		}
		result := make([]detectionSample, 0, len(output.Samples))
		for _, sample := range output.Samples {
			normalized := detectionSample{
				Namespace: sample.Labels["namespace"], Workload: sample.Labels["deployment"],
				Timestamp: sample.Timestamp, Value: sample.Value,
			}
			if err := validateDetectionSample(normalized, namespace, time.Time{}, time.Time{}, false); err != nil {
				return nil, fmt.Errorf("metric detection sample: %w", err)
			}
			result = append(result, normalized)
		}
		return result, nil
	case toolapi.ToolQueryLogSignals:
		var output toolapi.QueryLogSignalsOutput
		if err := s.Tools.Call(ctx, toolapi.ToolQueryLogSignals, toolapi.QueryLogSignalsInput{
			TemplateID: rule.TemplateID, Namespace: namespace,
		}, &output); err != nil {
			return nil, err
		}
		if output.TemplateID != rule.TemplateID {
			return nil, model.NewError(model.CodeExecutionFailed, "log result template differs from the requested rule template")
		}
		return validateNormalizedSamples(output.Samples, namespace, output.WindowStart, output.WindowEnd, s.Clock.Now())
	case toolapi.ToolQueryTraceSignals:
		var output toolapi.QueryTraceSignalsOutput
		if err := s.Tools.Call(ctx, toolapi.ToolQueryTraceSignals, toolapi.QueryTraceSignalsInput{
			TemplateID: rule.TemplateID, Namespace: namespace,
		}, &output); err != nil {
			return nil, err
		}
		if output.TemplateID != rule.TemplateID {
			return nil, model.NewError(model.CodeExecutionFailed, "trace result template differs from the requested rule template")
		}
		return validateNormalizedSamples(output.Samples, namespace, output.WindowStart, output.WindowEnd, s.Clock.Now())
	default:
		return nil, model.NewError(model.CodeInvalidInput, "monitor rule uses an unsupported constrained tool")
	}
}

func validateNormalizedSamples(samples []toolapi.DetectionSample, namespace string, start, end, now time.Time) ([]detectionSample, error) {
	if len(samples) > maxDetectionSamples {
		return nil, model.NewError(model.CodeExecutionFailed, "detection result exceeds the workload group limit")
	}
	if start.IsZero() || end.IsZero() || end.Before(start) || end.Sub(start) > 6*time.Minute {
		return nil, model.NewError(model.CodeExecutionFailed, "detection result has an invalid observation window")
	}
	now = now.UTC()
	if end.Before(now.Add(-10*time.Minute)) || end.After(now.Add(time.Minute)) {
		return nil, model.NewError(model.CodeExecutionFailed, "detection result observation window is stale or in the future")
	}
	result := make([]detectionSample, 0, len(samples))
	seen := make(map[string]struct{}, len(samples))
	for _, sample := range samples {
		normalized := detectionSample{
			Namespace: sample.Namespace, Workload: sample.Workload,
			Timestamp: sample.Timestamp, Value: sample.Value,
		}
		if err := validateDetectionSample(normalized, namespace, start, end, true); err != nil {
			return nil, err
		}
		key := normalized.Namespace + "\x00" + normalized.Workload
		if _, duplicate := seen[key]; duplicate {
			return nil, model.NewError(model.CodeExecutionFailed, "detection result contains a duplicate workload identity")
		}
		seen[key] = struct{}{}
		result = append(result, normalized)
	}
	return result, nil
}

func validateDetectionSample(sample detectionSample, namespace string, start, end time.Time, exactCount bool) error {
	if sample.Namespace != namespace || sample.Workload == "" {
		return model.NewError(model.CodeOutOfScope, "detection sample lacks the exact requested namespace and workload identity")
	}
	target := model.ResourceTarget{
		APIVersion: "apps/v1", Kind: "Deployment", Namespace: sample.Namespace, Name: sample.Workload,
	}
	if err := target.Validate(); err != nil {
		return model.WrapError(model.CodeInvalidInput, "detection sample has an invalid workload identity", err)
	}
	if sample.Timestamp.IsZero() || (!start.IsZero() && sample.Timestamp.Before(start)) || (!end.IsZero() && sample.Timestamp.After(end)) {
		return model.NewError(model.CodeExecutionFailed, "detection sample timestamp is outside its observation window")
	}
	if math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) || sample.Value < 0 {
		return model.NewError(model.CodeExecutionFailed, "detection sample value is invalid")
	}
	if exactCount && (math.Trunc(sample.Value) != sample.Value || sample.Value > maxExactDetectionCount) {
		return model.NewError(model.CodeExecutionFailed, "detection sample count is not an exact bounded integer")
	}
	return nil
}

func (s *Service) coordinate(ctx context.Context, signal model.IncidentSignal, detectionTool, namespace, deployment string, now time.Time) (IncidentOutcome, error) {
	incident, err := model.NewIncident("inc-"+s.IDs.NewID(), signal, now)
	if err != nil {
		return IncidentOutcome{}, err
	}
	if err := incident.Transition(model.IncidentVerifying, now); err != nil {
		return IncidentOutcome{Incident: incident}, err
	}
	if err := incident.Transition(model.IncidentVerified, now); err != nil {
		return IncidentOutcome{Incident: incident}, err
	}
	if err := incident.Transition(model.IncidentInvestigating, now); err != nil {
		return IncidentOutcome{Incident: incident}, err
	}
	target := model.ResourceTarget{APIVersion: "apps/v1", Kind: "Deployment", Namespace: namespace, Name: deployment}
	request := model.InvestigationRequest{
		SchemaVersion: model.SchemaVersionV1,
		Incident:      incident,
		Scope: model.InvestigationScope{
			Namespaces: []string{namespace}, Targets: []model.ResourceTarget{target},
		},
		Budget: model.InvestigationBudget{
			MaxToolCalls: s.evidenceBudget(), MaxEvidence: s.evidenceBudget(), Timeout: s.requestTimeout(),
		},
		RequestedAt: now,
	}
	requestEnvelope, err := model.NewEnvelope(
		s.IDs.NewID(), incident.ID, incident.ID, signal.ID,
		model.AgentMonitor, model.AgentInvestigator, model.MessageInvestigationRequest, now, request,
	)
	if err != nil {
		return IncidentOutcome{Incident: incident}, err
	}
	var diagnosisEnvelope model.Envelope
	if err := s.Peers.Send(ctx, s.InvestigatorURL, requestEnvelope, &diagnosisEnvelope); err != nil {
		return IncidentOutcome{Incident: incident}, fmt.Errorf("delegate investigation: %w", err)
	}
	if err := validateResponse(
		diagnosisEnvelope, incident.ID, requestEnvelope.CorrelationID, requestEnvelope.MessageID,
		model.AgentInvestigator, model.AgentMonitor, model.MessageDiagnosisReport,
	); err != nil {
		return IncidentOutcome{Incident: incident}, err
	}
	var diagnosis model.DiagnosisReport
	if err := diagnosisEnvelope.DecodePayload(&diagnosis); err != nil {
		return IncidentOutcome{Incident: incident}, err
	}
	if err := diagnosis.VerifyDigest(); err != nil {
		return IncidentOutcome{Incident: incident}, err
	}
	if diagnosis.IncidentID != incident.ID {
		return IncidentOutcome{Incident: incident}, model.NewError(model.CodeInvalidInput, "diagnosis is bound to a different incident")
	}
	incident.EvidenceIDs = append([]string(nil), diagnosis.EvidenceIDs...)
	incident.DiagnosisReportID = diagnosis.ID
	outcome := IncidentOutcome{Incident: incident, Diagnosis: &diagnosis, Status: "diagnosed"}
	if err := incident.Transition(model.IncidentDiagnosed, s.Clock.Now()); err != nil {
		return outcome, err
	}
	outcome.Incident = incident
	if diagnosis.Status != model.DiagnosisConfirmed || len(diagnosis.Proposals) == 0 {
		if err := incident.Transition(model.IncidentEscalated, s.Clock.Now()); err != nil {
			return outcome, err
		}
		outcome.Incident = incident
		outcome.Status = "escalated"
		outcome.Detail = "diagnosis did not contain an automatically delegable action"
		s.attachIncidentReport(ctx, &outcome, target, requestEnvelope.CorrelationID, diagnosisEnvelope.MessageID, model.ReportReasonDiagnosisInconclusive)
		return outcome, nil
	}
	proposal := diagnosis.Proposals[0]
	if !proposal.Action.Target.Equal(target) {
		if err := incident.Transition(model.IncidentEscalated, s.Clock.Now()); err != nil {
			return outcome, err
		}
		outcome.Incident = incident
		outcome.Status = "escalated"
		outcome.Detail = "proposal target differs from the verified incident target"
		s.attachIncidentReport(ctx, &outcome, target, requestEnvelope.CorrelationID, diagnosisEnvelope.MessageID, model.ReportReasonPolicyDenied)
		return outcome, nil
	}
	if !s.DryRun && detectionTool != "" && detectionTool != toolapi.ToolQueryMetrics && !s.AllowLogTraceActions {
		if err := incident.Transition(model.IncidentEscalated, s.Clock.Now()); err != nil {
			return outcome, err
		}
		outcome.Incident = incident
		outcome.Status = "escalated"
		outcome.Detail = "live remediation from log or trace evidence is disabled until workload identity provenance is explicitly trusted"
		s.attachIncidentReport(ctx, &outcome, target, requestEnvelope.CorrelationID, diagnosisEnvelope.MessageID, model.ReportReasonPolicyDenied)
		return outcome, nil
	}

	var snapshot toolapi.GetWorkloadSnapshotOutput
	if err := s.Tools.Call(ctx, toolapi.ToolGetWorkloadSnapshot, toolapi.GetWorkloadSnapshotInput{
		Namespace: namespace, Kind: "Deployment", Name: deployment,
	}, &snapshot); err != nil {
		return outcome, fmt.Errorf("refresh action precondition: %w", err)
	}
	if !snapshot.Snapshot.Target.Equal(target) {
		return outcome, model.NewError(model.CodeExecutionFailed, "pre-action snapshot target differs from the verified incident target")
	}
	if workloadAvailable(snapshot.Snapshot) {
		if err := incident.Transition(model.IncidentResolved, s.Clock.Now()); err != nil {
			return outcome, err
		}
		outcome.Incident = incident
		outcome.Status = "resolved_without_action"
		outcome.Detail = "fresh pre-action observation shows the workload already recovered"
		s.attachIncidentReport(ctx, &outcome, target, requestEnvelope.CorrelationID, diagnosisEnvelope.MessageID, model.ReportReasonRecoveryVerified)
		return outcome, nil
	}
	expected := snapshot.Snapshot.DesiredReplicas
	issuedAt := s.Clock.Now().UTC()
	grant := model.DelegationGrant{
		SchemaVersion: model.SchemaVersionV1,
		GrantID:       s.IDs.NewID(), Issuer: model.AgentMonitor,
		Audiences:  []model.AgentID{model.AgentOperator, model.AgentMCPAction},
		IncidentID: incident.ID, DiagnosisReportID: diagnosis.ID,
		DiagnosisDigest: diagnosis.Digest, DiagnosisConfidence: diagnosis.Confidence,
		EvidenceIDs: append([]string(nil), proposal.EvidenceIDs...), ProposalID: proposal.ID,
		Action: proposal.Action,
		Preconditions: model.ActionPreconditions{
			ResourceVersion: snapshot.Snapshot.ResourceVersion, ExpectedReplicas: &expected,
		},
		DryRun: s.DryRun, IdempotencyKey: incident.ID + ":" + proposal.ID,
		IssuedAt: issuedAt, NotBefore: issuedAt, ExpiresAt: issuedAt.Add(s.delegationTTL()),
	}
	if s.Signer == nil {
		if err := incident.Transition(model.IncidentEscalated, s.Clock.Now()); err != nil {
			return outcome, err
		}
		outcome.Incident = incident
		outcome.Status = "awaiting_delegation_key"
		outcome.Detail = "diagnosis complete; Monitor has no delegation private key"
		s.attachIncidentReport(ctx, &outcome, target, requestEnvelope.CorrelationID, diagnosisEnvelope.MessageID, model.ReportReasonAuthorityExceeded)
		return outcome, nil
	}
	if err := s.Signer.Sign(&grant); err != nil {
		return outcome, fmt.Errorf("sign action delegation: %w", err)
	}
	if s.Policy == nil {
		if err := incident.Transition(model.IncidentEscalated, s.Clock.Now()); err != nil {
			return outcome, err
		}
		outcome.Incident = incident
		outcome.Status = "escalated"
		outcome.Detail = "Monitor delegation policy is unavailable"
		s.attachIncidentReport(ctx, &outcome, target, requestEnvelope.CorrelationID, diagnosisEnvelope.MessageID, model.ReportReasonAuthorityExceeded)
		return outcome, nil
	}
	decision := s.Policy.AuthorizeProposal(diagnosis, grant, s.Clock.Now())
	if !decision.Allowed {
		if err := incident.Transition(model.IncidentEscalated, s.Clock.Now()); err != nil {
			return outcome, err
		}
		outcome.Incident = incident
		outcome.Status = "escalated"
		outcome.Detail = "delegation policy denied proposal: " + decision.Reason
		s.attachIncidentReport(ctx, &outcome, target, requestEnvelope.CorrelationID, diagnosisEnvelope.MessageID, model.ReportReasonPolicyDenied)
		return outcome, nil
	}
	if err := incident.Transition(model.IncidentRemediationPending, s.Clock.Now()); err != nil {
		return outcome, err
	}
	outcome.Incident = incident
	outcome.Grant = &grant
	failAfterGrant := func(failure error, correlationID, causationID string) (IncidentOutcome, error) {
		if !incident.State.Terminal() {
			if transitionErr := incident.Transition(model.IncidentEscalated, s.Clock.Now()); transitionErr != nil {
				return outcome, transitionErr
			}
		}
		outcome.Incident = incident
		outcome.Status = "escalated"
		outcome.Detail = "delegated remediation outcome could not be verified: " + failure.Error()
		// No receipt is trusted on this path. The outcome-unverified report deliberately
		// carries no execution reference, even if the peer returned malformed data.
		s.attachIncidentReport(ctx, &outcome, target, correlationID, causationID, model.ReportReasonActionOutcomeUnverified)
		return outcome, nil
	}
	grantEnvelope, err := model.NewEnvelope(
		s.IDs.NewID(), incident.ID, requestEnvelope.CorrelationID, diagnosisEnvelope.MessageID,
		model.AgentMonitor, model.AgentOperator, model.MessageRemediationRequest, s.Clock.Now(), grant,
	)
	if err != nil {
		return failAfterGrant(err, requestEnvelope.CorrelationID, diagnosisEnvelope.MessageID)
	}
	var receiptEnvelope model.Envelope
	if err := s.Peers.Send(ctx, s.OperatorURL, grantEnvelope, &receiptEnvelope); err != nil {
		if reason, finalState, ok := reportableOperatorError(err); ok {
			if transitionErr := incident.Transition(finalState, s.Clock.Now()); transitionErr != nil {
				return outcome, transitionErr
			}
			outcome.Incident = incident
			outcome.Status = string(finalState)
			outcome.Detail = "Operator declined the delegated task: " + err.Error()
			s.attachIncidentReport(ctx, &outcome, target, grantEnvelope.CorrelationID, grantEnvelope.MessageID, reason)
			return outcome, nil
		}
		return failAfterGrant(fmt.Errorf("delegate remediation: %w", err), grantEnvelope.CorrelationID, grantEnvelope.MessageID)
	}
	if err := validateResponse(
		receiptEnvelope, incident.ID, grantEnvelope.CorrelationID, grantEnvelope.MessageID,
		model.AgentOperator, model.AgentMonitor, model.MessageActionReceipt,
	); err != nil {
		return failAfterGrant(err, grantEnvelope.CorrelationID, grantEnvelope.MessageID)
	}
	var receipt model.ActionReceipt
	if err := receiptEnvelope.DecodePayload(&receipt); err != nil {
		return failAfterGrant(err, grantEnvelope.CorrelationID, receiptEnvelope.MessageID)
	}
	if err := receipt.Validate(); err != nil {
		return failAfterGrant(err, grantEnvelope.CorrelationID, receiptEnvelope.MessageID)
	}
	if err := validateReceiptForGrant(receipt, grant); err != nil {
		return failAfterGrant(err, grantEnvelope.CorrelationID, receiptEnvelope.MessageID)
	}
	outcome.Receipt = &receipt
	outcome.Status = string(receipt.Outcome)
	if err := incident.Transition(model.IncidentRemediating, s.Clock.Now()); err != nil {
		return outcome, err
	}
	outcome.Incident = incident
	if s.Audit != nil {
		_ = s.Audit.Record(ctx, model.AuditEvent{
			ID: s.IDs.NewID(), IncidentID: incident.ID, Actor: model.AgentMonitor,
			Operation: "coordinate_remediation", Decision: string(receipt.Outcome),
			SideEffect: receipt.Outcome == model.ActionSucceeded, OccurredAt: s.Clock.Now(),
		})
	}
	if receipt.Outcome == model.ActionDryRun {
		if err := incident.Transition(model.IncidentEscalated, s.Clock.Now()); err != nil {
			return outcome, err
		}
		outcome.Incident = incident
		outcome.Detail = "dry-run completed; no recovery state was inferred"
		s.attachIncidentReport(ctx, &outcome, target, grantEnvelope.CorrelationID, receiptEnvelope.MessageID, model.ReportReasonDryRunCompleted)
	} else if receipt.Outcome == model.ActionSucceeded {
		var postcondition toolapi.GetWorkloadSnapshotOutput
		observationErr := s.Tools.Call(ctx, toolapi.ToolGetWorkloadSnapshot, toolapi.GetWorkloadSnapshotInput{
			Namespace: namespace, Kind: "Deployment", Name: deployment,
		}, &postcondition)
		if observationErr == nil && !postcondition.Snapshot.Target.Equal(target) {
			observationErr = model.NewError(model.CodeExecutionFailed, "post-action snapshot target differs from the delegated target")
		}
		if observationErr != nil {
			outcome.Status = "verification_pending"
			outcome.Detail = "action succeeded but post-action observation failed: " + observationErr.Error()
		} else if workloadAvailable(postcondition.Snapshot) {
			if err := incident.Transition(model.IncidentResolved, s.Clock.Now()); err != nil {
				return outcome, err
			}
			outcome.Incident = incident
			outcome.Status = "resolved"
			outcome.Detail = "fresh post-action observation meets availability criteria"
			s.attachIncidentReport(ctx, &outcome, target, grantEnvelope.CorrelationID, receiptEnvelope.MessageID, model.ReportReasonRecoveryVerified)
		} else {
			outcome.Status = "verification_pending"
			outcome.Detail = "action succeeded; fresh observation has not yet met availability criteria"
		}
		if outcome.Status == "verification_pending" {
			s.storePending(signal.Fingerprint, pendingVerification{
				Incident: incident, Diagnosis: diagnosis, Grant: grant, Receipt: receipt,
				Target: target, StartedAt: s.Clock.Now().UTC(),
				CorrelationID: grantEnvelope.CorrelationID, CausationID: receiptEnvelope.MessageID,
			})
			outcome.Incident = incident
		}
	} else if receipt.Outcome == model.ActionEscalated {
		if err := incident.Transition(model.IncidentEscalated, s.Clock.Now()); err != nil {
			return outcome, err
		}
		outcome.Incident = incident
		outcome.Detail = "Operator reported that the action requires authority outside the delegation"
		s.attachIncidentReport(ctx, &outcome, target, grantEnvelope.CorrelationID, receiptEnvelope.MessageID, model.ReportReasonAuthorityExceeded)
	} else {
		if err := incident.Transition(model.IncidentFailed, s.Clock.Now()); err != nil {
			return outcome, err
		}
		outcome.Incident = incident
		reason := model.ReportReasonActionFailed
		if receipt.Outcome == model.ActionRejected {
			reason = model.ReportReasonActionRejected
		}
		s.attachIncidentReport(ctx, &outcome, target, grantEnvelope.CorrelationID, receiptEnvelope.MessageID, reason)
	}
	return outcome, nil
}

func (s *Service) attachIncidentReport(
	ctx context.Context,
	outcome *IncidentOutcome,
	target model.ResourceTarget,
	correlationID, causationID string,
	reason model.IncidentReportReason,
) {
	if outcome == nil || outcome.Diagnosis == nil || !outcome.Incident.State.Terminal() {
		return
	}
	if s.ReportSigner == nil {
		appendOutcomeDetail(outcome, "incident report request was not sent: Monitor report signing key is unavailable")
		return
	}
	requestedAt := s.Clock.Now().UTC()
	request := model.IncidentReportRequest{
		SchemaVersion: model.SchemaVersionV1,
		RequestID:     "report-request-" + outcome.Incident.ID + "-" + string(reason),
		Issuer:        model.AgentMonitor, Audience: model.AgentOperator,
		IncidentID: outcome.Incident.ID, CorrelationID: correlationID,
		DiagnosisReportID: outcome.Diagnosis.ID, Target: target,
		FinalState: outcome.Incident.State, Reason: reason,
		RequestedAt: requestedAt, ExpiresAt: requestedAt.Add(s.delegationTTL()),
	}
	if outcome.Grant != nil && outcome.Receipt != nil {
		request.GrantID = outcome.Grant.GrantID
		request.ReceiptID = outcome.Receipt.ReceiptID
	}
	if err := s.ReportSigner.SignReportRequest(&request); err != nil {
		appendOutcomeDetail(outcome, "incident report request could not be signed: "+err.Error())
		return
	}
	if err := request.ValidateSigned(); err != nil {
		appendOutcomeDetail(outcome, "incident report request was invalid: "+err.Error())
		return
	}
	expectedReportID, err := request.DeterministicReportID()
	if err != nil {
		appendOutcomeDetail(outcome, "incident report identity could not be derived: "+err.Error())
		return
	}
	envelope, err := model.NewEnvelope(
		s.IDs.NewID(), outcome.Incident.ID, correlationID, causationID,
		model.AgentMonitor, model.AgentOperator, model.MessageIncidentReportRequest,
		s.Clock.Now(), request,
	)
	if err != nil {
		appendOutcomeDetail(outcome, "incident report request could not be created: "+err.Error())
		return
	}
	var response model.Envelope
	if err := s.Peers.Send(ctx, s.OperatorURL, envelope, &response); err != nil {
		appendOutcomeDetail(outcome, "incident report delivery request failed: "+err.Error())
		return
	}
	if err := validateResponse(
		response, outcome.Incident.ID, correlationID, envelope.MessageID,
		model.AgentOperator, model.AgentMonitor, model.MessageIncidentReport,
	); err != nil {
		appendOutcomeDetail(outcome, "incident report response was rejected: "+err.Error())
		return
	}
	var result model.IncidentReportResult
	if err := response.DecodePayload(&result); err != nil {
		appendOutcomeDetail(outcome, "incident report response could not be decoded: "+err.Error())
		return
	}
	if err := result.Validate(); err != nil ||
		result.Report.ReportID != expectedReportID ||
		result.Report.RequestID != request.RequestID ||
		result.Report.IncidentID != request.IncidentID ||
		result.Report.CorrelationID != request.CorrelationID ||
		result.Report.DiagnosisReportID != request.DiagnosisReportID ||
		!result.Report.Target.Equal(request.Target) ||
		result.Report.FinalState != request.FinalState || result.Report.Reason != request.Reason ||
		!result.Report.CreatedAt.Equal(request.RequestedAt) ||
		!reportExecutionMatchesRequest(result.Report.Execution, request, outcome.Receipt) {
		if err == nil {
			err = model.NewError(model.CodeInvalidInput, "incident report result differs from the Monitor request")
		}
		appendOutcomeDetail(outcome, "incident report response was rejected: "+err.Error())
		return
	}
	outcome.Report = &result
}

func reportExecutionMatchesRequest(
	execution *model.IncidentReportExecution,
	request model.IncidentReportRequest,
	receipt *model.ActionReceipt,
) bool {
	if request.GrantID == "" || request.ReceiptID == "" {
		return execution == nil
	}
	return execution != nil && receipt != nil &&
		execution.GrantID == request.GrantID && execution.ReceiptID == request.ReceiptID &&
		execution.GrantID == receipt.GrantID && execution.ReceiptID == receipt.ReceiptID &&
		execution.Action.Equal(receipt.Action) && execution.Outcome == receipt.Outcome &&
		execution.DryRun == receipt.DryRun && execution.CompletedAt.Equal(receipt.CompletedAt)
}

func appendOutcomeDetail(outcome *IncidentOutcome, detail string) {
	if outcome.Detail == "" {
		outcome.Detail = detail
		return
	}
	outcome.Detail += "; " + detail
}

func reportableOperatorError(err error) (model.IncidentReportReason, model.IncidentState, bool) {
	code, ok := model.ErrorCodeOf(err)
	if !ok {
		return "", "", false
	}
	switch code {
	case model.CodePolicyDenied, model.CodeOutOfScope, model.CodeDelegationRequired:
		return model.ReportReasonAuthorityExceeded, model.IncidentEscalated, true
	case model.CodeExecutionFailed:
		return model.ReportReasonActionOutcomeUnverified, model.IncidentEscalated, true
	default:
		return "", "", false
	}
}

func validateResponse(
	envelope model.Envelope,
	incidentID, correlationID, causationID string,
	sender, recipient model.AgentID,
	kind model.MessageKind,
) error {
	if err := envelope.Validate(); err != nil {
		return err
	}
	if envelope.IncidentID != incidentID || envelope.CorrelationID != correlationID || envelope.CausationID != causationID ||
		envelope.Sender != sender || envelope.Recipient != recipient || envelope.Kind != kind {
		return model.NewError(model.CodeInvalidInput, "A2A response chain, identity, or kind did not match the request")
	}
	return nil
}

func validateReceiptForGrant(receipt model.ActionReceipt, grant model.DelegationGrant) error {
	if receipt.GrantID != grant.GrantID || receipt.IncidentID != grant.IncidentID || !receipt.Action.Equal(grant.Action) {
		return model.NewError(model.CodeExecutionFailed, "Operator receipt does not match the delegated grant")
	}
	if receipt.DryRun != grant.DryRun ||
		(grant.DryRun && receipt.Outcome != model.ActionDryRun) ||
		(!grant.DryRun && receipt.Outcome == model.ActionDryRun) {
		return model.NewError(model.CodeExecutionFailed, "Operator receipt dry-run semantics do not match the delegated grant")
	}
	return nil
}

func (s *Service) verifyPending(ctx context.Context, key string, now time.Time) (IncidentOutcome, bool) {
	pending, ok := s.pending(key)
	if !ok {
		return IncidentOutcome{}, false
	}
	outcome := IncidentOutcome{
		Incident: pending.Incident, Diagnosis: &pending.Diagnosis,
		Grant: &pending.Grant, Receipt: &pending.Receipt,
		Status: "verification_pending",
	}
	var snapshot toolapi.GetWorkloadSnapshotOutput
	err := s.Tools.Call(ctx, toolapi.ToolGetWorkloadSnapshot, toolapi.GetWorkloadSnapshotInput{
		Namespace: pending.Target.Namespace, Kind: pending.Target.Kind, Name: pending.Target.Name,
	}, &snapshot)
	if err == nil && !snapshot.Snapshot.Target.Equal(pending.Target) {
		err = model.NewError(model.CodeExecutionFailed, "follow-up snapshot target differs from the delegated target")
	}
	if err == nil && workloadAvailable(snapshot.Snapshot) {
		if transitionErr := pending.Incident.Transition(model.IncidentResolved, s.Clock.Now()); transitionErr != nil {
			outcome.Status = "failed"
			outcome.Detail = transitionErr.Error()
			return outcome, true
		}
		s.clearPending(key, pending.Grant.GrantID, now)
		outcome.Incident = pending.Incident
		outcome.Status = "resolved"
		outcome.Detail = "follow-up observation meets availability criteria"
		s.attachIncidentReport(ctx, &outcome, pending.Target, pending.CorrelationID, pending.CausationID, model.ReportReasonRecoveryVerified)
		return outcome, true
	}
	if !now.Before(pending.StartedAt) && now.Sub(pending.StartedAt) >= s.cooldown() {
		if transitionErr := pending.Incident.Transition(model.IncidentEscalated, s.Clock.Now()); transitionErr != nil {
			outcome.Status = "failed"
			outcome.Detail = transitionErr.Error()
			return outcome, true
		}
		s.clearPending(key, pending.Grant.GrantID, now)
		outcome.Incident = pending.Incident
		outcome.Status = "escalated"
		outcome.Detail = "post-action verification window elapsed without recovery"
		if err != nil {
			outcome.Detail += ": " + err.Error()
		}
		s.attachIncidentReport(ctx, &outcome, pending.Target, pending.CorrelationID, pending.CausationID, model.ReportReasonVerificationTimedOut)
		return outcome, true
	}
	if err != nil {
		outcome.Detail = "follow-up post-action observation failed: " + err.Error()
	} else {
		outcome.Detail = "action succeeded; follow-up observation has not yet met availability criteria"
	}
	return outcome, true
}

func (s *Service) pending(key string) (pendingVerification, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item := s.tracker[key]
	if item == nil || item.Pending == nil {
		return pendingVerification{}, false
	}
	return *item.Pending, true
}

func (s *Service) storePending(key string, pending pendingVerification) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tracker == nil {
		s.tracker = make(map[string]*observation)
	}
	item := s.tracker[key]
	if item == nil {
		item = &observation{WorkloadKey: key}
		s.tracker[key] = item
	}
	item.Pending = &pending
}

func (s *Service) clearPending(key, grantID string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item := s.tracker[key]
	if item == nil || item.Pending == nil || item.Pending.Grant.GrantID != grantID {
		return
	}
	item.Pending = nil
	item.Dispatched = now
	item.LastSeen = now
	item.Consecutive = 0
}

func (s *Service) pendingNotSeen(seen map[string]struct{}) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0)
	for key, item := range s.tracker {
		if item.Pending == nil {
			continue
		}
		if _, ok := seen[key]; !ok {
			keys = append(keys, key)
		}
	}
	return keys
}

func (s *Service) confirm(key, workloadKey string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tracker == nil {
		s.tracker = make(map[string]*observation)
	}
	if workload := s.tracker[workloadKey]; workload != nil {
		if workload.Pending != nil || (!workload.Dispatched.IsZero() && now.Sub(workload.Dispatched) < s.cooldown()) {
			return false
		}
	}
	item := s.tracker[key]
	if item == nil {
		if len(s.tracker) >= maxTrackedIncidents {
			return false
		}
		item = &observation{WorkloadKey: workloadKey}
		s.tracker[key] = item
	}
	item.Consecutive++
	item.LastSeen = now
	want := s.VerificationCount
	if want < 1 {
		want = 2
	}
	return item.Consecutive >= want
}

func (s *Service) markDispatched(key string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item := s.tracker[key]
	if item == nil {
		item = &observation{WorkloadKey: key}
		s.tracker[key] = item
	}
	item.Dispatched = now
	item.Consecutive = 0
	for _, candidate := range s.tracker {
		if candidate.WorkloadKey == key {
			candidate.Consecutive = 0
		}
	}
}

func (s *Service) resetFailed(key string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if item := s.tracker[key]; item != nil {
		item.Consecutive = 0
		item.LastSeen = now
	}
}

func (s *Service) resetConfirmations(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.tracker {
		if item.Pending == nil {
			item.Consecutive = 0
			item.LastSeen = now
		}
	}
}

func (s *Service) resetMissing(seen map[string]struct{}, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, item := range s.tracker {
		if item.Pending != nil {
			continue
		}
		if _, ok := seen[key]; !ok {
			item.Consecutive = 0
			if item.Dispatched.IsZero() {
				delete(s.tracker, key)
				continue
			}
		}
		if !item.Dispatched.IsZero() && now.Sub(item.Dispatched) > 2*s.cooldown() {
			delete(s.tracker, key)
		}
	}
}

func (s *Service) cooldown() time.Duration {
	if s.Cooldown <= 0 {
		return 15 * time.Minute
	}
	return s.Cooldown
}

func (s *Service) delegationTTL() time.Duration {
	if s.DelegationTTL <= 0 || s.DelegationTTL > 5*time.Minute {
		return 2 * time.Minute
	}
	return s.DelegationTTL
}

func (s *Service) requestTimeout() time.Duration {
	if s.RequestTimeout <= 0 || s.RequestTimeout > 10*time.Minute {
		return 30 * time.Second
	}
	return s.RequestTimeout
}

func (s *Service) evidenceBudget() int {
	if s.EvidenceBudget < 1 || s.EvidenceBudget > 20 {
		return 6
	}
	return s.EvidenceBudget
}

func fingerprint(ruleID, namespace, deployment string) string {
	sum := sha256.Sum256([]byte(ruleID + "\x00" + namespace + "\x00" + deployment))
	return hex.EncodeToString(sum[:])
}

func workloadFingerprint(namespace, deployment string) string {
	sum := sha256.Sum256([]byte(namespace + "\x00" + deployment))
	return hex.EncodeToString(sum[:])
}

func workloadAvailable(snapshot toolapi.WorkloadSnapshot) bool {
	return snapshot.ObservedGeneration >= snapshot.Generation &&
		snapshot.DesiredReplicas > 0 &&
		snapshot.AvailableReplicas >= snapshot.DesiredReplicas &&
		snapshot.UnavailableReplicas == 0
}
