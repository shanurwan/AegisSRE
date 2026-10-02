package monitor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
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
	StateStore           ports.MonitorStateStore
	InstanceID           string
	StateLease           time.Duration

	scanMu      sync.Mutex
	mu          sync.Mutex
	tracker     map[string]*observation
	leaseMu     sync.RWMutex
	activeLease *ports.MonitorLease
}

type observation struct {
	Consecutive int
	LastSeen    time.Time
	Dispatched  time.Time
	WorkloadKey string
	Pending     *pendingVerification
	Dispatch    *pendingDispatch
	Report      *pendingReport
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

type pendingDispatch struct {
	Incident  model.Incident
	Diagnosis model.DiagnosisReport
	Grant     model.DelegationGrant
	Target    model.ResourceTarget
	Envelope  model.Envelope
	StartedAt time.Time
}

type pendingReport struct {
	Outcome          IncidentOutcome
	Target           model.ResourceTarget
	Request          model.IncidentReportRequest
	Envelope         model.Envelope
	ExpectedReportID string
}

type durableMonitorState struct {
	SchemaVersion string                  `json:"schema_version"`
	Tracker       map[string]*observation `json:"tracker"`
}

const (
	maxTrackedIncidents    = 4096
	maxDetectionSamples    = 50
	maxExactDetectionCount = 1<<53 - 1
	monitorStateSchemaV2   = "aegissre.io/monitor-state/v2"
)

func (s *Service) Scan(ctx context.Context, request ScanRequest) (ScanResult, error) {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	if s.StateStore == nil {
		return s.scan(ctx, request)
	}
	if s.Clock == nil {
		return ScanResult{}, errors.New("monitor clock is required for durable coordination")
	}
	if s.InstanceID == "" {
		return ScanResult{}, errors.New("monitor instance ID is required for durable coordination")
	}
	leaseDuration := s.stateLease()
	lease, acquired, err := s.StateStore.AcquireMonitorLease(ctx, s.Namespace, s.InstanceID, leaseDuration)
	if err != nil {
		return ScanResult{}, fmt.Errorf("acquire monitor leadership: %w", err)
	}
	if !acquired {
		return ScanResult{ScannedAt: s.Clock.Now().UTC()}, nil
	}
	checkpoint, exists, err := s.StateStore.LoadMonitorCheckpoint(ctx, lease)
	if err != nil {
		return ScanResult{}, fmt.Errorf("load monitor checkpoint: %w", err)
	}
	if exists {
		if err := s.restoreCheckpoint(checkpoint.Payload); err != nil {
			return ScanResult{}, fmt.Errorf("restore monitor checkpoint: %w", err)
		}
	} else {
		s.mu.Lock()
		s.tracker = make(map[string]*observation)
		s.mu.Unlock()
	}
	s.setActiveLease(&lease)
	defer s.setActiveLease(nil)

	scanContext, cancel := context.WithCancelCause(ctx)
	heartbeatDone := make(chan error, 1)
	go s.maintainLease(scanContext, leaseDuration, cancel, heartbeatDone)
	result, scanErr := s.scan(scanContext, request)
	if persistErr := s.persistCheckpoint(ctx); persistErr != nil {
		scanErr = errors.Join(scanErr, fmt.Errorf("persist monitor checkpoint: %w", persistErr))
	}
	cancel(nil)
	if heartbeatErr := <-heartbeatDone; heartbeatErr != nil {
		scanErr = errors.Join(scanErr, heartbeatErr)
	}
	return result, scanErr
}

func (s *Service) scan(ctx context.Context, request ScanRequest) (ScanResult, error) {
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
	var scanErrors []error
	for _, key := range s.workflowKeys() {
		outcome, handled, err := s.resumeWorkflow(ctx, key, now)
		if !handled {
			continue
		}
		result.Outcomes = append(result.Outcomes, outcome)
		pendingChecked[key] = struct{}{}
		if err != nil {
			scanErrors = append(scanErrors, fmt.Errorf("resume durable workflow %s: %w", key, err))
		}
	}
	for _, key := range s.pendingNotSeen(nil) {
		if _, recovered := pendingChecked[key]; recovered {
			continue
		}
		if outcome, pending := s.verifyPending(ctx, key, now); pending {
			result.Outcomes = append(result.Outcomes, outcome)
			pendingChecked[key] = struct{}{}
		}
	}

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
			target := model.ResourceTarget{APIVersion: "apps/v1", Kind: "Deployment", Namespace: sample.Namespace, Name: deployment}
			if binding, ok := s.Policy.(ports.WorkloadPolicyBinding); ok && binding.RequiresBinding() && !binding.AllowsSignal(target, source) {
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
			if s.hasWorkflow(workloadKey) {
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

func (s *Service) maintainLease(
	ctx context.Context,
	duration time.Duration,
	cancel context.CancelCauseFunc,
	done chan<- error,
) {
	interval := duration / 3
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			done <- nil
			return
		case <-ticker.C:
			lease, ok := s.currentLease()
			if !ok {
				err := errors.New("monitor leadership lease disappeared")
				cancel(err)
				done <- err
				return
			}
			renewed, err := s.StateStore.RenewMonitorLease(ctx, lease, duration)
			if err != nil {
				err = fmt.Errorf("renew monitor leadership: %w", err)
				cancel(err)
				done <- err
				return
			}
			s.setActiveLease(&renewed)
		}
	}
}

func (s *Service) persistCheckpoint(ctx context.Context) error {
	if s.StateStore == nil {
		return nil
	}
	lease, ok := s.currentLease()
	if !ok {
		return errors.New("monitor leadership lease is unavailable")
	}
	s.mu.Lock()
	payload, err := json.Marshal(durableMonitorState{SchemaVersion: monitorStateSchemaV2, Tracker: s.tracker})
	s.mu.Unlock()
	if err != nil {
		return fmt.Errorf("marshal monitor checkpoint: %w", err)
	}
	_, err = s.StateStore.SaveMonitorCheckpoint(ctx, lease, payload)
	return err
}

func (s *Service) restoreCheckpoint(payload []byte) error {
	var state durableMonitorState
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return model.WrapError(model.CodeInvalidInput, "decode durable monitor state", err)
	}
	if state.SchemaVersion != monitorStateSchemaV2 || state.Tracker == nil || len(state.Tracker) > maxTrackedIncidents {
		return model.NewError(model.CodeInvalidInput, "durable monitor state has an unsupported schema or size")
	}
	for key, item := range state.Tracker {
		if err := validateDurableObservation(key, item); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.tracker = state.Tracker
	s.mu.Unlock()
	return nil
}

func validateDurableObservation(key string, item *observation) error {
	if !validFingerprint(key) || item == nil || !validFingerprint(item.WorkloadKey) ||
		item.Consecutive < 0 || item.Consecutive > 10 {
		return model.NewError(model.CodeInvalidInput, "durable monitor state contains an invalid observation")
	}
	active := 0
	if item.Pending != nil {
		active++
	}
	if item.Dispatch != nil {
		active++
	}
	if item.Report != nil {
		active++
	}
	if active > 1 {
		return model.NewError(model.CodeInvalidInput, "durable monitor observation contains conflicting workflow stages")
	}
	if pending := item.Pending; pending != nil {
		if err := pending.Incident.Validate(); err != nil {
			return model.WrapError(model.CodeInvalidInput, "durable pending incident is invalid", err)
		}
		if err := pending.Diagnosis.VerifyDigest(); err != nil {
			return model.WrapError(model.CodeInvalidInput, "durable pending diagnosis is invalid", err)
		}
		if err := pending.Grant.ValidateSigned(); err != nil {
			return model.WrapError(model.CodeInvalidInput, "durable pending grant is invalid", err)
		}
		if err := pending.Receipt.Validate(); err != nil {
			return model.WrapError(model.CodeInvalidInput, "durable pending receipt is invalid", err)
		}
		if !pending.Target.Equal(pending.Grant.Action.Target) ||
			pending.Incident.ID != pending.Grant.IncidentID ||
			pending.Diagnosis.ID != pending.Grant.DiagnosisReportID ||
			pending.Diagnosis.Digest != pending.Grant.DiagnosisDigest ||
			pending.Incident.DiagnosisReportID != pending.Diagnosis.ID ||
			pending.Receipt.Outcome != model.ActionSucceeded || pending.StartedAt.IsZero() ||
			validateReceiptForGrant(pending.Receipt, pending.Grant) != nil ||
			item.WorkloadKey != workloadFingerprint(pending.Target.Namespace, pending.Target.Name) {
			return model.NewError(model.CodeInvalidInput, "durable pending verification bindings are invalid")
		}
	}
	if dispatch := item.Dispatch; dispatch != nil {
		if err := dispatch.Incident.Validate(); err != nil {
			return model.WrapError(model.CodeInvalidInput, "durable dispatch incident is invalid", err)
		}
		if err := dispatch.Diagnosis.VerifyDigest(); err != nil {
			return model.WrapError(model.CodeInvalidInput, "durable dispatch diagnosis is invalid", err)
		}
		if err := dispatch.Grant.ValidateSigned(); err != nil {
			return model.WrapError(model.CodeInvalidInput, "durable monitor dispatch grant is invalid", err)
		}
		if err := dispatch.Envelope.Validate(); err != nil {
			return model.WrapError(model.CodeInvalidInput, "durable monitor dispatch envelope is invalid", err)
		}
		var envelopeGrant model.DelegationGrant
		if err := dispatch.Envelope.DecodePayload(&envelopeGrant); err != nil || !sameJSON(envelopeGrant, dispatch.Grant) {
			return model.NewError(model.CodeInvalidInput, "durable dispatch envelope differs from its signed grant")
		}
		if dispatch.Envelope.IncidentID != dispatch.Incident.ID ||
			dispatch.Envelope.Sender != model.AgentMonitor || dispatch.Envelope.Recipient != model.AgentOperator ||
			dispatch.Envelope.Kind != model.MessageRemediationRequest ||
			!dispatch.Target.Equal(dispatch.Grant.Action.Target) ||
			dispatch.Incident.ID != dispatch.Grant.IncidentID ||
			dispatch.Diagnosis.ID != dispatch.Grant.DiagnosisReportID ||
			dispatch.Diagnosis.Digest != dispatch.Grant.DiagnosisDigest ||
			dispatch.Incident.DiagnosisReportID != dispatch.Diagnosis.ID || dispatch.StartedAt.IsZero() ||
			item.WorkloadKey != workloadFingerprint(dispatch.Target.Namespace, dispatch.Target.Name) {
			return model.NewError(model.CodeInvalidInput, "durable remediation dispatch bindings are invalid")
		}
	}
	if report := item.Report; report != nil {
		if err := report.Request.ValidateSigned(); err != nil {
			return model.WrapError(model.CodeInvalidInput, "durable monitor report request is invalid", err)
		}
		if err := report.Envelope.Validate(); err != nil {
			return model.WrapError(model.CodeInvalidInput, "durable monitor report envelope is invalid", err)
		}
		if err := report.Outcome.Incident.Validate(); err != nil || report.Outcome.Diagnosis == nil {
			return model.NewError(model.CodeInvalidInput, "durable report outcome incident or diagnosis is invalid")
		}
		if err := report.Outcome.Diagnosis.VerifyDigest(); err != nil {
			return model.WrapError(model.CodeInvalidInput, "durable report outcome diagnosis is invalid", err)
		}
		var envelopeRequest model.IncidentReportRequest
		if err := report.Envelope.DecodePayload(&envelopeRequest); err != nil || !sameJSON(envelopeRequest, report.Request) {
			return model.NewError(model.CodeInvalidInput, "durable report envelope differs from its signed request")
		}
		expectedID, err := report.Request.DeterministicReportID()
		if err != nil || expectedID != report.ExpectedReportID ||
			report.Envelope.IncidentID != report.Outcome.Incident.ID ||
			report.Envelope.Sender != model.AgentMonitor || report.Envelope.Recipient != model.AgentOperator ||
			report.Envelope.Kind != model.MessageIncidentReportRequest ||
			!report.Target.Equal(report.Request.Target) ||
			report.Request.IncidentID != report.Outcome.Incident.ID ||
			report.Request.DiagnosisReportID != report.Outcome.Diagnosis.ID ||
			report.Request.FinalState != report.Outcome.Incident.State ||
			item.WorkloadKey != workloadFingerprint(report.Target.Namespace, report.Target.Name) {
			return model.NewError(model.CodeInvalidInput, "durable incident report bindings are invalid")
		}
		switch {
		case report.Request.GrantID == "":
			if report.Request.ReceiptID != "" || report.Outcome.Receipt != nil {
				return model.NewError(model.CodeInvalidInput, "durable receipt-free report contains execution evidence")
			}
		case report.Request.ReceiptID == "":
			if report.Request.Reason != model.ReportReasonActionOutcomeUnverified &&
				report.Request.Reason != model.ReportReasonAuthorityExceeded {
				return model.NewError(model.CodeInvalidInput, "durable grant-only report reason is invalid")
			}
			if report.Outcome.Grant == nil || report.Outcome.Receipt != nil ||
				report.Request.GrantID != report.Outcome.Grant.GrantID {
				return model.NewError(model.CodeInvalidInput, "durable grant-only report binding is invalid")
			}
		default:
			if report.Outcome.Grant == nil || report.Outcome.Receipt == nil ||
				report.Request.GrantID != report.Outcome.Grant.GrantID ||
				report.Request.ReceiptID != report.Outcome.Receipt.ReceiptID ||
				validateReceiptForGrant(*report.Outcome.Receipt, *report.Outcome.Grant) != nil {
				return model.NewError(model.CodeInvalidInput, "durable incident report receipt binding is invalid")
			}
		}
	}
	return nil
}

func validFingerprint(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func sameJSON(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func (s *Service) setActiveLease(lease *ports.MonitorLease) {
	s.leaseMu.Lock()
	defer s.leaseMu.Unlock()
	if lease == nil {
		s.activeLease = nil
		return
	}
	copy := *lease
	s.activeLease = &copy
}

func (s *Service) currentLease() (ports.MonitorLease, bool) {
	s.leaseMu.RLock()
	defer s.leaseMu.RUnlock()
	if s.activeLease == nil {
		return ports.MonitorLease{}, false
	}
	return *s.activeLease, true
}

func (s *Service) stateLease() time.Duration {
	if s.StateLease < 5*time.Second || s.StateLease > 5*time.Minute {
		return time.Minute
	}
	return s.StateLease
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
	if binding, ok := s.Policy.(ports.WorkloadPolicyBinding); ok && binding.RequiresBinding() {
		grant.PolicyDigest = binding.BindingDigest()
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
	grantEnvelope, err := model.NewEnvelope(
		s.IDs.NewID(), incident.ID, requestEnvelope.CorrelationID, diagnosisEnvelope.MessageID,
		model.AgentMonitor, model.AgentOperator, model.MessageRemediationRequest, s.Clock.Now(), grant,
	)
	if err != nil {
		return outcome, err
	}
	dispatch := pendingDispatch{
		Incident: incident, Diagnosis: diagnosis, Grant: grant, Target: target,
		Envelope: grantEnvelope, StartedAt: s.Clock.Now().UTC(),
	}
	if err := s.storeDispatch(ctx, signal.Fingerprint, dispatch); err != nil {
		return outcome, fmt.Errorf("checkpoint delegated remediation before delivery: %w", err)
	}
	recovered, _, err := s.resumeDispatch(ctx, signal.Fingerprint, s.Clock.Now().UTC())
	return recovered, err
}

func (s *Service) resumeWorkflow(ctx context.Context, key string, now time.Time) (IncidentOutcome, bool, error) {
	s.mu.Lock()
	item := s.tracker[key]
	hasReport := item != nil && item.Report != nil
	hasDispatch := item != nil && item.Dispatch != nil
	s.mu.Unlock()
	if hasReport {
		return s.resumeReport(ctx, key)
	}
	if hasDispatch {
		return s.resumeDispatch(ctx, key, now)
	}
	return IncidentOutcome{}, false, nil
}

func (s *Service) resumeDispatch(ctx context.Context, key string, now time.Time) (IncidentOutcome, bool, error) {
	s.mu.Lock()
	item := s.tracker[key]
	if item == nil || item.Dispatch == nil {
		s.mu.Unlock()
		return IncidentOutcome{}, false, nil
	}
	dispatch := *item.Dispatch
	s.mu.Unlock()
	outcome := IncidentOutcome{
		Incident: dispatch.Incident, Diagnosis: &dispatch.Diagnosis,
		Grant: &dispatch.Grant, Status: "remediation_delivery_pending",
	}
	failAfterGrant := func(failure error, causationID string) (IncidentOutcome, bool, error) {
		incident := dispatch.Incident
		if !incident.State.Terminal() {
			if transitionErr := incident.Transition(model.IncidentEscalated, s.Clock.Now()); transitionErr != nil {
				return outcome, true, transitionErr
			}
		}
		outcome.Incident = incident
		outcome.Status = "escalated"
		outcome.Detail = "delegated remediation outcome could not be verified: " + failure.Error()
		// No receipt is trusted on this path. The report deliberately carries no
		// execution reference, even if the peer returned malformed data.
		s.attachIncidentReport(ctx, &outcome, dispatch.Target, dispatch.Envelope.CorrelationID, causationID, model.ReportReasonActionOutcomeUnverified)
		return outcome, true, nil
	}

	var receiptEnvelope model.Envelope
	if err := s.Peers.Send(ctx, s.OperatorURL, dispatch.Envelope, &receiptEnvelope); err != nil {
		if reason, finalState, reportable := reportableOperatorError(err); reportable {
			incident := dispatch.Incident
			if transitionErr := incident.Transition(finalState, s.Clock.Now()); transitionErr != nil {
				return outcome, true, transitionErr
			}
			outcome.Incident = incident
			outcome.Status = string(finalState)
			outcome.Detail = "Operator declined the delegated task: " + err.Error()
			s.attachIncidentReport(ctx, &outcome, dispatch.Target, dispatch.Envelope.CorrelationID, dispatch.Envelope.MessageID, reason)
			return outcome, true, nil
		}
		if s.StateStore != nil && (now.Before(dispatch.StartedAt) || now.Sub(dispatch.StartedAt) < s.cooldown()) {
			outcome.Detail = "exact delegated remediation will be retried after an ambiguous delivery failure: " + err.Error()
			return outcome, true, nil
		}
		return failAfterGrant(fmt.Errorf("delegate remediation: %w", err), dispatch.Envelope.MessageID)
	}
	if err := validateResponse(
		receiptEnvelope, dispatch.Incident.ID, dispatch.Envelope.CorrelationID, dispatch.Envelope.MessageID,
		model.AgentOperator, model.AgentMonitor, model.MessageActionReceipt,
	); err != nil {
		return failAfterGrant(err, dispatch.Envelope.MessageID)
	}
	var receipt model.ActionReceipt
	if err := receiptEnvelope.DecodePayload(&receipt); err != nil {
		return failAfterGrant(err, receiptEnvelope.MessageID)
	}
	if err := receipt.Validate(); err != nil {
		return failAfterGrant(err, receiptEnvelope.MessageID)
	}
	if err := validateReceiptForGrant(receipt, dispatch.Grant); err != nil {
		return failAfterGrant(err, receiptEnvelope.MessageID)
	}
	outcome.Receipt = &receipt
	outcome.Status = string(receipt.Outcome)
	incident := dispatch.Incident
	if err := incident.Transition(model.IncidentRemediating, s.Clock.Now()); err != nil {
		return outcome, true, err
	}
	outcome.Incident = incident
	if s.Audit != nil {
		_ = s.Audit.Record(ctx, model.AuditEvent{
			ID: s.IDs.NewID(), IncidentID: incident.ID, Actor: model.AgentMonitor,
			Operation: "coordinate_remediation", Decision: string(receipt.Outcome),
			SideEffect: receipt.Outcome == model.ActionSucceeded, OccurredAt: s.Clock.Now(),
		})
	}
	if receipt.Outcome == model.ActionSucceeded {
		pending := pendingVerification{
			Incident: incident, Diagnosis: dispatch.Diagnosis, Grant: dispatch.Grant, Receipt: receipt,
			Target: dispatch.Target, StartedAt: s.Clock.Now().UTC(),
			CorrelationID: dispatch.Envelope.CorrelationID, CausationID: receiptEnvelope.MessageID,
		}
		if err := s.replaceDispatchWithPending(ctx, key, pending); err != nil {
			return outcome, true, fmt.Errorf("checkpoint action receipt before verification: %w", err)
		}
		verified, _ := s.verifyPending(ctx, key, s.Clock.Now().UTC())
		return verified, true, nil
	}
	if receipt.Outcome == model.ActionDryRun {
		if err := incident.Transition(model.IncidentEscalated, s.Clock.Now()); err != nil {
			return outcome, true, err
		}
		outcome.Incident = incident
		outcome.Detail = "dry-run completed; no recovery state was inferred"
		s.attachIncidentReport(ctx, &outcome, dispatch.Target, dispatch.Envelope.CorrelationID, receiptEnvelope.MessageID, model.ReportReasonDryRunCompleted)
		return outcome, true, nil
	}
	if receipt.Outcome == model.ActionEscalated {
		if err := incident.Transition(model.IncidentEscalated, s.Clock.Now()); err != nil {
			return outcome, true, err
		}
		outcome.Incident = incident
		outcome.Detail = "Operator reported that the action requires authority outside the delegation"
		s.attachIncidentReport(ctx, &outcome, dispatch.Target, dispatch.Envelope.CorrelationID, receiptEnvelope.MessageID, model.ReportReasonAuthorityExceeded)
		return outcome, true, nil
	}
	if err := incident.Transition(model.IncidentFailed, s.Clock.Now()); err != nil {
		return outcome, true, err
	}
	outcome.Incident = incident
	reason := model.ReportReasonActionFailed
	if receipt.Outcome == model.ActionRejected {
		reason = model.ReportReasonActionRejected
	}
	s.attachIncidentReport(ctx, &outcome, dispatch.Target, dispatch.Envelope.CorrelationID, receiptEnvelope.MessageID, reason)
	return outcome, true, nil
}

func (s *Service) storeDispatch(ctx context.Context, key string, dispatch pendingDispatch) error {
	s.mu.Lock()
	if s.tracker == nil {
		s.tracker = make(map[string]*observation)
	}
	item := s.tracker[key]
	if item == nil {
		item = &observation{WorkloadKey: key}
		s.tracker[key] = item
	}
	item.Dispatch = &dispatch
	item.Pending = nil
	item.Report = nil
	s.mu.Unlock()
	return s.persistCheckpoint(ctx)
}

func (s *Service) replaceDispatchWithPending(ctx context.Context, key string, pending pendingVerification) error {
	s.mu.Lock()
	item := s.tracker[key]
	if item == nil || item.Dispatch == nil || item.Dispatch.Grant.GrantID != pending.Grant.GrantID {
		s.mu.Unlock()
		return model.NewError(model.CodeExecutionFailed, "durable remediation dispatch changed before receipt checkpoint")
	}
	item.Dispatch = nil
	item.Pending = &pending
	s.mu.Unlock()
	return s.persistCheckpoint(ctx)
}

func (s *Service) workflowKeys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0)
	for key, item := range s.tracker {
		if item != nil && (item.Dispatch != nil || item.Report != nil) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func (s *Service) hasWorkflow(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	item := s.tracker[key]
	return item != nil && (item.Pending != nil || item.Dispatch != nil || item.Report != nil)
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
	key := workloadFingerprint(target.Namespace, target.Name)
	if s.ReportSigner == nil {
		appendOutcomeDetail(outcome, "incident report request was not sent: Monitor report signing key is unavailable")
		_ = s.completeWorkflow(ctx, key)
		return
	}
	requestedAt := s.Clock.Now().UTC()
	request := model.IncidentReportRequest{
		SchemaVersion: model.IncidentReportRequestSchemaVersionV2,
		RequestID:     "report-request-" + outcome.Incident.ID + "-" + string(reason),
		Issuer:        model.AgentMonitor, Audience: model.AgentOperator,
		IncidentID: outcome.Incident.ID, CorrelationID: correlationID,
		DiagnosisReportID: outcome.Diagnosis.ID, Target: target,
		FinalState: outcome.Incident.State, Reason: reason,
		ReportCreatedAt: requestedAt, RequestedAt: requestedAt,
		ExpiresAt: requestedAt.Add(model.MaxIncidentReportRequestTTL),
	}
	if outcome.Grant != nil && outcome.Receipt != nil {
		request.GrantID = outcome.Grant.GrantID
		request.ReceiptID = outcome.Receipt.ReceiptID
	} else if outcome.Grant != nil &&
		(reason == model.ReportReasonActionOutcomeUnverified || reason == model.ReportReasonAuthorityExceeded) {
		request.GrantID = outcome.Grant.GrantID
	}
	if err := s.ReportSigner.SignReportRequest(&request); err != nil {
		appendOutcomeDetail(outcome, "incident report request could not be signed: "+err.Error())
		_ = s.completeWorkflow(ctx, key)
		return
	}
	if err := request.ValidateSigned(); err != nil {
		appendOutcomeDetail(outcome, "incident report request was invalid: "+err.Error())
		_ = s.completeWorkflow(ctx, key)
		return
	}
	expectedReportID, err := request.DeterministicReportID()
	if err != nil {
		appendOutcomeDetail(outcome, "incident report identity could not be derived: "+err.Error())
		_ = s.completeWorkflow(ctx, key)
		return
	}
	envelope, err := model.NewEnvelope(
		s.IDs.NewID(), outcome.Incident.ID, correlationID, causationID,
		model.AgentMonitor, model.AgentOperator, model.MessageIncidentReportRequest,
		s.Clock.Now(), request,
	)
	if err != nil {
		appendOutcomeDetail(outcome, "incident report request could not be created: "+err.Error())
		_ = s.completeWorkflow(ctx, key)
		return
	}
	checkpoint := pendingReport{
		Outcome: *outcome, Target: target, Request: request,
		Envelope: envelope, ExpectedReportID: expectedReportID,
	}
	if s.StateStore != nil {
		if err := s.storeReport(ctx, key, checkpoint); err != nil {
			appendOutcomeDetail(outcome, "incident report request could not be checkpointed: "+err.Error())
			return
		}
	}
	result, err := s.deliverReport(ctx, checkpoint)
	if err != nil {
		appendOutcomeDetail(outcome, err.Error())
		return
	}
	outcome.Report = &result
	if err := s.completeWorkflow(ctx, key); err != nil {
		appendOutcomeDetail(outcome, "incident report acknowledgement could not be checkpointed: "+err.Error())
	}
}

func (s *Service) deliverReport(ctx context.Context, checkpoint pendingReport) (model.IncidentReportResult, error) {
	var response model.Envelope
	if err := s.Peers.Send(ctx, s.OperatorURL, checkpoint.Envelope, &response); err != nil {
		return model.IncidentReportResult{}, fmt.Errorf("incident report delivery request failed: %w", err)
	}
	if err := validateResponse(
		response, checkpoint.Outcome.Incident.ID, checkpoint.Request.CorrelationID, checkpoint.Envelope.MessageID,
		model.AgentOperator, model.AgentMonitor, model.MessageIncidentReport,
	); err != nil {
		return model.IncidentReportResult{}, fmt.Errorf("incident report response was rejected: %w", err)
	}
	var result model.IncidentReportResult
	if err := response.DecodePayload(&result); err != nil {
		return model.IncidentReportResult{}, fmt.Errorf("incident report response could not be decoded: %w", err)
	}
	if err := result.Validate(); err != nil ||
		result.Report.ReportID != checkpoint.ExpectedReportID ||
		result.Report.RequestID != checkpoint.Request.RequestID ||
		result.Report.IncidentID != checkpoint.Request.IncidentID ||
		result.Report.CorrelationID != checkpoint.Request.CorrelationID ||
		result.Report.DiagnosisReportID != checkpoint.Request.DiagnosisReportID ||
		!result.Report.Target.Equal(checkpoint.Request.Target) ||
		result.Report.FinalState != checkpoint.Request.FinalState || result.Report.Reason != checkpoint.Request.Reason ||
		!result.Report.CreatedAt.Equal(checkpoint.Request.ReportCreatedAt) ||
		!reportExecutionMatchesRequest(result.Report.Execution, checkpoint.Request, checkpoint.Outcome.Receipt) {
		if err == nil {
			err = model.NewError(model.CodeInvalidInput, "incident report result differs from the Monitor request")
		}
		return model.IncidentReportResult{}, fmt.Errorf("incident report response was rejected: %w", err)
	}
	return result, nil
}

func (s *Service) resumeReport(ctx context.Context, key string) (IncidentOutcome, bool, error) {
	s.mu.Lock()
	item := s.tracker[key]
	if item == nil || item.Report == nil {
		s.mu.Unlock()
		return IncidentOutcome{}, false, nil
	}
	checkpoint := *item.Report
	s.mu.Unlock()
	outcome := checkpoint.Outcome
	result, err := s.deliverReport(ctx, checkpoint)
	code, coded := model.ErrorCodeOf(err)
	locallyExpired := !s.Clock.Now().UTC().Before(checkpoint.Request.ExpiresAt.UTC())
	if coded && (code == model.CodeGrantExpired || (code == model.CodeInvalidSignature && locallyExpired)) {
		refreshed, refreshErr := s.refreshExpiredReport(ctx, key, checkpoint)
		if refreshErr != nil {
			outcome.Status = "report_delivery_expired"
			appendOutcomeDetail(&outcome, refreshErr.Error())
			return outcome, true, nil
		}
		checkpoint = refreshed
		outcome = checkpoint.Outcome
		result, err = s.deliverReport(ctx, checkpoint)
	}
	if err != nil {
		outcome.Status = "report_delivery_pending"
		appendOutcomeDetail(&outcome, err.Error())
		return outcome, true, nil
	}
	outcome.Report = &result
	if err := s.completeWorkflow(ctx, key); err != nil {
		appendOutcomeDetail(&outcome, "incident report acknowledgement could not be checkpointed: "+err.Error())
		return outcome, true, err
	}
	return outcome, true, nil
}

func (s *Service) refreshExpiredReport(ctx context.Context, key string, checkpoint pendingReport) (pendingReport, error) {
	if s.ReportSigner == nil {
		return pendingReport{}, errors.New("incident report request cannot be renewed: Monitor report signing key is unavailable")
	}
	requestedAt := s.Clock.Now().UTC()
	request := checkpoint.Request
	request.RequestedAt = requestedAt
	request.ExpiresAt = requestedAt.Add(model.MaxIncidentReportRequestTTL)
	request.Signature = model.ReportRequestSignature{}
	if err := s.ReportSigner.SignReportRequest(&request); err != nil {
		return pendingReport{}, fmt.Errorf("renew expired incident report request signature: %w", err)
	}
	if err := request.ValidateSigned(); err != nil {
		return pendingReport{}, fmt.Errorf("renewed incident report request is invalid: %w", err)
	}
	expectedReportID, err := request.DeterministicReportID()
	if err != nil {
		return pendingReport{}, fmt.Errorf("derive renewed incident report identity: %w", err)
	}
	envelope, err := model.NewEnvelope(
		s.IDs.NewID(), checkpoint.Outcome.Incident.ID, request.CorrelationID, checkpoint.Envelope.MessageID,
		model.AgentMonitor, model.AgentOperator, model.MessageIncidentReportRequest,
		requestedAt, request,
	)
	if err != nil {
		return pendingReport{}, fmt.Errorf("create renewed incident report request: %w", err)
	}
	checkpoint.Request = request
	checkpoint.Envelope = envelope
	checkpoint.ExpectedReportID = expectedReportID
	if err := s.storeReport(ctx, key, checkpoint); err != nil {
		return pendingReport{}, fmt.Errorf("checkpoint renewed incident report request: %w", err)
	}
	return checkpoint, nil
}

func (s *Service) storeReport(ctx context.Context, key string, report pendingReport) error {
	s.mu.Lock()
	if s.tracker == nil {
		s.tracker = make(map[string]*observation)
	}
	item := s.tracker[key]
	if item == nil {
		item = &observation{WorkloadKey: key}
		s.tracker[key] = item
	}
	item.Dispatch = nil
	item.Pending = nil
	item.Report = &report
	s.mu.Unlock()
	return s.persistCheckpoint(ctx)
}

func (s *Service) completeWorkflow(ctx context.Context, key string) error {
	s.mu.Lock()
	item := s.tracker[key]
	if item == nil {
		item = &observation{WorkloadKey: key}
		s.tracker[key] = item
	}
	item.Dispatch = nil
	item.Pending = nil
	item.Report = nil
	item.Dispatched = s.Clock.Now().UTC()
	item.LastSeen = item.Dispatched
	item.Consecutive = 0
	for _, candidate := range s.tracker {
		if candidate != nil && candidate.WorkloadKey == key {
			candidate.Consecutive = 0
		}
	}
	s.mu.Unlock()
	return s.persistCheckpoint(ctx)
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
	if receipt.Outcome != model.ActionRejected && (receipt.DryRun != grant.DryRun ||
		(grant.DryRun && receipt.Outcome != model.ActionDryRun) ||
		(!grant.DryRun && receipt.Outcome == model.ActionDryRun)) {
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
		outcome.Incident = pending.Incident
		outcome.Status = "resolved"
		outcome.Detail = "follow-up observation meets availability criteria"
		s.attachIncidentReport(ctx, &outcome, pending.Target, pending.CorrelationID, pending.CausationID, model.ReportReasonRecoveryVerified)
		if s.StateStore == nil {
			s.clearPending(key, pending.Grant.GrantID, now)
		}
		return outcome, true
	}
	if !now.Before(pending.StartedAt) && now.Sub(pending.StartedAt) >= s.cooldown() {
		if transitionErr := pending.Incident.Transition(model.IncidentEscalated, s.Clock.Now()); transitionErr != nil {
			outcome.Status = "failed"
			outcome.Detail = transitionErr.Error()
			return outcome, true
		}
		outcome.Incident = pending.Incident
		outcome.Status = "escalated"
		outcome.Detail = "post-action verification window elapsed without recovery"
		if err != nil {
			outcome.Detail += ": " + err.Error()
		}
		s.attachIncidentReport(ctx, &outcome, pending.Target, pending.CorrelationID, pending.CausationID, model.ReportReasonVerificationTimedOut)
		if s.StateStore == nil {
			s.clearPending(key, pending.Grant.GrantID, now)
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
		if workload.Pending != nil || workload.Dispatch != nil || workload.Report != nil ||
			(!workload.Dispatched.IsZero() && now.Sub(workload.Dispatched) < s.cooldown()) {
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
		if item.Pending == nil && item.Dispatch == nil && item.Report == nil {
			item.Consecutive = 0
			item.LastSeen = now
		}
	}
}

func (s *Service) resetMissing(seen map[string]struct{}, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, item := range s.tracker {
		if item.Pending != nil || item.Dispatch != nil || item.Report != nil {
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
