package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	TemplateID string
	Threshold  float64
	Severity   model.Severity
	Summary    string
}

func DefaultRules() []Rule {
	return []Rule{{
		ID: "deployment-unavailable", TemplateID: toolapi.MetricDeploymentUnavailable,
		Threshold: 1, Severity: model.SeverityCritical, Summary: "deployment has unavailable replicas",
	}}
}

type ScanRequest struct {
	Namespace string `json:"namespace,omitempty"`
}

type IncidentOutcome struct {
	Incident  model.Incident         `json:"incident"`
	Diagnosis *model.DiagnosisReport `json:"diagnosis,omitempty"`
	Grant     *model.DelegationGrant `json:"grant,omitempty"`
	Receipt   *model.ActionReceipt   `json:"receipt,omitempty"`
	Status    string                 `json:"status"`
	Detail    string                 `json:"detail,omitempty"`
}

type ScanResult struct {
	ScannedAt  time.Time         `json:"scanned_at"`
	Candidates int               `json:"candidates"`
	Outcomes   []IncidentOutcome `json:"outcomes,omitempty"`
}

type Service struct {
	Tools             ports.ToolCaller
	Peers             ports.PeerMessenger
	Signer            ports.GrantSigner
	Policy            ports.ProposalAuthorizer
	Clock             ports.Clock
	IDs               ports.IDGenerator
	Audit             ports.Auditor
	Namespace         string
	InvestigatorURL   string
	OperatorURL       string
	Rules             []Rule
	VerificationCount int
	Cooldown          time.Duration
	DelegationTTL     time.Duration
	RequestTimeout    time.Duration
	EvidenceBudget    int
	DryRun            bool

	mu      sync.Mutex
	tracker map[string]*observation
}

type observation struct {
	Consecutive int
	LastSeen    time.Time
	Dispatched  time.Time
	Pending     *pendingVerification
}

type pendingVerification struct {
	Incident  model.Incident
	Diagnosis model.DiagnosisReport
	Grant     model.DelegationGrant
	Receipt   model.ActionReceipt
	Target    model.ResourceTarget
	StartedAt time.Time
}

const maxTrackedIncidents = 4096

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

	for _, rule := range rules {
		var metrics toolapi.QueryMetricsOutput
		if err := s.Tools.Call(ctx, toolapi.ToolQueryMetrics, toolapi.QueryMetricsInput{
			TemplateID: rule.TemplateID, Namespace: namespace,
		}, &metrics); err != nil {
			s.resetConfirmations(now)
			return result, fmt.Errorf("evaluate rule %s: %w", rule.ID, err)
		}
		if metrics.TemplateID != rule.TemplateID {
			s.resetConfirmations(now)
			return result, model.NewError(model.CodeExecutionFailed, "metric result template differs from the requested rule template")
		}
		for _, sample := range metrics.Samples {
			if sample.Value < rule.Threshold {
				continue
			}
			deployment := sample.Labels["deployment"]
			if deployment == "" || sample.Labels["namespace"] != namespace {
				continue
			}
			fingerprint := fingerprint(rule.ID, namespace, deployment)
			if _, duplicate := seen[fingerprint]; duplicate {
				continue
			}
			seen[fingerprint] = struct{}{}
			result.Candidates++
			if _, checked := pendingChecked[fingerprint]; checked {
				continue
			}
			if outcome, pending := s.verifyPending(ctx, fingerprint, now); pending {
				result.Outcomes = append(result.Outcomes, outcome)
				continue
			}
			if !s.confirm(fingerprint, now) {
				continue
			}
			signal := model.IncidentSignal{
				ID: s.IDs.NewID(), Source: "victoriametrics", RuleID: rule.ID,
				Fingerprint: fingerprint, Summary: rule.Summary, Severity: rule.Severity,
				ObservedAt: sample.Timestamp, Labels: cloneLabels(sample.Labels),
			}
			outcome, err := s.coordinate(ctx, signal, namespace, deployment, now)
			if err != nil {
				outcome.Status = "failed"
				outcome.Detail = err.Error()
				if outcome.Incident.ID != "" && !outcome.Incident.State.Terminal() {
					_ = outcome.Incident.Transition(model.IncidentFailed, s.Clock.Now())
				}
				if outcome.Grant != nil {
					s.markDispatched(fingerprint, now)
				} else {
					s.resetFailed(fingerprint, now)
				}
			} else {
				s.markDispatched(fingerprint, now)
			}
			result.Outcomes = append(result.Outcomes, outcome)
		}
	}
	s.resetMissing(seen, now)
	return result, nil
}

func (s *Service) coordinate(ctx context.Context, signal model.IncidentSignal, namespace, deployment string, now time.Time) (IncidentOutcome, error) {
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
		return outcome, nil
	}
	proposal := diagnosis.Proposals[0]
	if !proposal.Action.Target.Equal(target) {
		return outcome, model.NewError(model.CodePolicyDenied, "proposal target differs from verified incident target")
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
		return outcome, nil
	}
	if err := s.Signer.Sign(&grant); err != nil {
		return outcome, fmt.Errorf("sign action delegation: %w", err)
	}
	if s.Policy == nil {
		return outcome, errors.New("monitor delegation policy is unavailable")
	}
	decision := s.Policy.AuthorizeProposal(diagnosis, grant, s.Clock.Now())
	if !decision.Allowed {
		if err := incident.Transition(model.IncidentEscalated, s.Clock.Now()); err != nil {
			return outcome, err
		}
		outcome.Incident = incident
		outcome.Status = "escalated"
		outcome.Detail = "delegation policy denied proposal: " + decision.Reason
		return outcome, nil
	}
	if err := incident.Transition(model.IncidentRemediationPending, s.Clock.Now()); err != nil {
		return outcome, err
	}
	outcome.Incident = incident
	outcome.Grant = &grant
	grantEnvelope, err := model.NewEnvelope(
		s.IDs.NewID(), incident.ID, requestEnvelope.CorrelationID, diagnosisEnvelope.MessageID,
		model.AgentMonitor, model.AgentOperator, model.MessageRemediationRequest, s.Clock.Now(), grant,
	)
	if err != nil {
		return outcome, err
	}
	var receiptEnvelope model.Envelope
	if err := s.Peers.Send(ctx, s.OperatorURL, grantEnvelope, &receiptEnvelope); err != nil {
		return outcome, fmt.Errorf("delegate remediation: %w", err)
	}
	if err := validateResponse(
		receiptEnvelope, incident.ID, grantEnvelope.CorrelationID, grantEnvelope.MessageID,
		model.AgentOperator, model.AgentMonitor, model.MessageActionReceipt,
	); err != nil {
		return outcome, err
	}
	var receipt model.ActionReceipt
	if err := receiptEnvelope.DecodePayload(&receipt); err != nil {
		return outcome, err
	}
	if err := receipt.Validate(); err != nil {
		return outcome, err
	}
	if err := validateReceiptForGrant(receipt, grant); err != nil {
		return outcome, err
	}
	outcome.Receipt = &receipt
	outcome.Status = string(receipt.Outcome)
	if err := incident.Transition(model.IncidentRemediating, s.Clock.Now()); err != nil {
		return outcome, err
	}
	outcome.Incident = incident
	if receipt.Outcome == model.ActionDryRun {
		if err := incident.Transition(model.IncidentEscalated, s.Clock.Now()); err != nil {
			return outcome, err
		}
		outcome.Incident = incident
		outcome.Detail = "dry-run completed; no recovery state was inferred"
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
		} else {
			outcome.Status = "verification_pending"
			outcome.Detail = "action succeeded; fresh observation has not yet met availability criteria"
		}
		if outcome.Status == "verification_pending" {
			s.storePending(signal.Fingerprint, pendingVerification{
				Incident: incident, Diagnosis: diagnosis, Grant: grant, Receipt: receipt,
				Target: target, StartedAt: s.Clock.Now().UTC(),
			})
			outcome.Incident = incident
		}
	} else {
		if err := incident.Transition(model.IncidentFailed, s.Clock.Now()); err != nil {
			return outcome, err
		}
		outcome.Incident = incident
	}
	if s.Audit != nil {
		_ = s.Audit.Record(ctx, model.AuditEvent{
			ID: s.IDs.NewID(), IncidentID: incident.ID, Actor: model.AgentMonitor,
			Operation: "coordinate_remediation", Decision: string(receipt.Outcome),
			SideEffect: receipt.Outcome == model.ActionSucceeded, OccurredAt: s.Clock.Now(),
		})
	}
	return outcome, nil
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
		item = &observation{}
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

func (s *Service) confirm(key string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tracker == nil {
		s.tracker = make(map[string]*observation)
	}
	item := s.tracker[key]
	if item == nil {
		if len(s.tracker) >= maxTrackedIncidents {
			return false
		}
		item = &observation{}
		s.tracker[key] = item
	}
	if !item.Dispatched.IsZero() && now.Sub(item.Dispatched) < s.cooldown() {
		item.LastSeen = now
		return false
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
	if item := s.tracker[key]; item != nil {
		item.Dispatched = now
		item.Consecutive = 0
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

func cloneLabels(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func workloadAvailable(snapshot toolapi.WorkloadSnapshot) bool {
	return snapshot.ObservedGeneration >= snapshot.Generation &&
		snapshot.DesiredReplicas > 0 &&
		snapshot.AvailableReplicas >= snapshot.DesiredReplicas &&
		snapshot.UnavailableReplicas == 0
}
