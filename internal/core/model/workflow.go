package model

import (
	"strings"
	"time"
	"unicode"
)

// IncidentReportReason is a closed, machine-generated explanation for why a
// terminal incident report was requested. It deliberately excludes arbitrary
// prose so untrusted evidence cannot become notification content.
type IncidentReportReason string

const (
	ReportReasonRecoveryVerified        IncidentReportReason = "recovery_verified"
	ReportReasonAuthorityExceeded       IncidentReportReason = "authority_exceeded"
	ReportReasonDiagnosisInconclusive   IncidentReportReason = "diagnosis_inconclusive"
	ReportReasonPolicyDenied            IncidentReportReason = "policy_denied"
	ReportReasonDryRunCompleted         IncidentReportReason = "dry_run_completed"
	ReportReasonActionRejected          IncidentReportReason = "action_rejected"
	ReportReasonActionFailed            IncidentReportReason = "action_failed"
	ReportReasonActionOutcomeUnverified IncidentReportReason = "action_outcome_unverified"
	ReportReasonVerificationTimedOut    IncidentReportReason = "verification_timed_out"
)

func (r IncidentReportReason) Valid() bool {
	switch r {
	case ReportReasonRecoveryVerified, ReportReasonAuthorityExceeded,
		ReportReasonDiagnosisInconclusive, ReportReasonPolicyDenied,
		ReportReasonDryRunCompleted, ReportReasonActionRejected,
		ReportReasonActionFailed, ReportReasonActionOutcomeUnverified,
		ReportReasonVerificationTimedOut:
		return true
	default:
		return false
	}
}

// Summary returns operator-owned text for external notification templates.
// Request payloads cannot supply notification prose.
func (r IncidentReportReason) Summary() string {
	switch r {
	case ReportReasonRecoveryVerified:
		return "Monitor independently verified workload recovery."
	case ReportReasonAuthorityExceeded:
		return "The incident requires action outside AegisSRE's delegated authority."
	case ReportReasonDiagnosisInconclusive:
		return "The investigation did not identify a safely automatable remediation."
	case ReportReasonPolicyDenied:
		return "The proposed remediation was denied by the configured safety policy."
	case ReportReasonDryRunCompleted:
		return "The delegated dry-run completed without changing the workload."
	case ReportReasonActionRejected:
		return "The delegated action was rejected before a workload change was accepted."
	case ReportReasonActionFailed:
		return "The delegated action returned a validated failure result and requires operator review."
	case ReportReasonActionOutcomeUnverified:
		return "The delegated action outcome could not be verified; operator review is required."
	case ReportReasonVerificationTimedOut:
		return "Recovery was not verified before the bounded verification window elapsed."
	default:
		return ""
	}
}

// IncidentReportRequest is a sanitized Monitor request for Operator to create
// and deliver a terminal report. It is informational and grants no Kubernetes
// authority. GrantID and ReceiptID, when present, must be supplied together
// and are matched against a receipt previously produced by Operator.
type IncidentReportRequest struct {
	SchemaVersion     string                 `json:"schema_version"`
	RequestID         string                 `json:"request_id"`
	Issuer            AgentID                `json:"issuer"`
	Audience          AgentID                `json:"audience"`
	IncidentID        string                 `json:"incident_id"`
	CorrelationID     string                 `json:"correlation_id"`
	DiagnosisReportID string                 `json:"diagnosis_report_id"`
	GrantID           string                 `json:"grant_id,omitempty"`
	ReceiptID         string                 `json:"receipt_id,omitempty"`
	Target            ResourceTarget         `json:"target"`
	FinalState        IncidentState          `json:"final_state"`
	Reason            IncidentReportReason   `json:"reason"`
	RequestedAt       time.Time              `json:"requested_at"`
	ExpiresAt         time.Time              `json:"expires_at"`
	Signature         ReportRequestSignature `json:"signature"`
}

const MaxIncidentReportRequestTTL = 5 * time.Minute

// ReportRequestSignature is intentionally a distinct protocol type from a
// delegation-grant signature. The security package also uses a separate
// signature domain, so a valid grant signature cannot authorize a report.
type ReportRequestSignature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

func (s ReportRequestSignature) Empty() bool {
	return s.Algorithm == "" && s.KeyID == "" && s.Value == ""
}

func (s ReportRequestSignature) Validate() error {
	if s.Algorithm != SignatureAlgorithmEd25519 {
		return NewError(CodeInvalidSignature, "incident report request signature algorithm must be Ed25519")
	}
	if err := requireSafeReportText("report_request.signature.key_id", s.KeyID); err != nil {
		return err
	}
	return requireSafeReportText("report_request.signature.value", s.Value)
}

func (r IncidentReportRequest) Validate() error {
	if r.SchemaVersion != SchemaVersionV1 {
		return NewError(CodeInvalidInput, "unsupported incident report request schema version")
	}
	if r.Issuer != AgentMonitor {
		return NewError(CodeDelegationRequired, "incident report request issuer is not aegissre-monitor")
	}
	if r.Audience != AgentOperator {
		return NewError(CodeDelegationRequired, "incident report request audience is not aegissre-operator")
	}
	for field, value := range map[string]string{
		"report_request.id": r.RequestID, "report_request.incident_id": r.IncidentID,
		"report_request.correlation_id":      r.CorrelationID,
		"report_request.diagnosis_report_id": r.DiagnosisReportID,
	} {
		if err := requireSafeReportText(field, value); err != nil {
			return err
		}
	}
	if (r.GrantID == "") != (r.ReceiptID == "") {
		return NewError(CodeInvalidInput, "report request grant and receipt IDs must be supplied together")
	}
	hasExecutionReference := r.GrantID != ""
	switch r.Reason {
	case ReportReasonDryRunCompleted, ReportReasonActionRejected, ReportReasonActionFailed, ReportReasonVerificationTimedOut:
		if !hasExecutionReference {
			return NewError(CodeInvalidInput, "incident report reason requires an exact action receipt reference")
		}
	case ReportReasonDiagnosisInconclusive, ReportReasonPolicyDenied, ReportReasonActionOutcomeUnverified:
		if hasExecutionReference {
			return NewError(CodeInvalidInput, "incident report reason cannot reference an action receipt")
		}
	}
	for field, value := range map[string]string{
		"report_request.grant_id": r.GrantID, "report_request.receipt_id": r.ReceiptID,
	} {
		if value != "" {
			if err := requireSafeReportText(field, value); err != nil {
				return err
			}
		}
	}
	if err := validateSafeReportTarget(r.Target); err != nil {
		return err
	}
	if !r.Reason.Valid() {
		return NewError(CodeInvalidInput, "incident report reason is invalid")
	}
	if err := validateReportState(r.FinalState, r.Reason); err != nil {
		return err
	}
	if err := requireTime("report_request.requested_at", r.RequestedAt); err != nil {
		return err
	}
	if err := requireTime("report_request.expires_at", r.ExpiresAt); err != nil {
		return err
	}
	if !r.ExpiresAt.After(r.RequestedAt) {
		return NewError(CodeInvalidInput, "incident report request expires_at must follow requested_at")
	}
	if r.ExpiresAt.Sub(r.RequestedAt) > MaxIncidentReportRequestTTL {
		return NewError(CodeInvalidInput, "incident report request lifetime exceeds the maximum")
	}
	if !r.Signature.Empty() {
		return r.Signature.Validate()
	}
	return nil
}

func (r IncidentReportRequest) ValidateSigned() error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.Signature.Empty() {
		return NewError(CodeDelegationRequired, "incident report request is unsigned")
	}
	return r.Signature.Validate()
}

func (r IncidentReportRequest) ComputeDigest() (string, error) {
	r.Signature = ReportRequestSignature{}
	if err := r.Validate(); err != nil {
		return "", err
	}
	r.RequestedAt = utc(r.RequestedAt)
	r.ExpiresAt = utc(r.ExpiresAt)
	return digestJSON(r)
}

// DeterministicReportID derives the only report identifier valid for this
// request. Both Operator and Monitor use it so an unkeyed report digest cannot
// be recomputed around an attacker-chosen identifier.
func (r IncidentReportRequest) DeterministicReportID() (string, error) {
	digest, err := r.ComputeDigest()
	if err != nil {
		return "", err
	}
	return "report-" + digest[:32], nil
}

func validateReportState(state IncidentState, reason IncidentReportReason) error {
	switch state {
	case IncidentResolved:
		if reason != ReportReasonRecoveryVerified {
			return NewError(CodeInvalidInput, "resolved report requires a recovery-verified reason")
		}
	case IncidentEscalated:
		switch reason {
		case ReportReasonAuthorityExceeded, ReportReasonDiagnosisInconclusive,
			ReportReasonPolicyDenied, ReportReasonDryRunCompleted,
			ReportReasonActionOutcomeUnverified, ReportReasonVerificationTimedOut:
		default:
			return NewError(CodeInvalidInput, "escalated report reason does not match escalated state")
		}
	case IncidentFailed:
		if reason != ReportReasonActionFailed && reason != ReportReasonActionRejected {
			return NewError(CodeInvalidInput, "failed report requires an action failure or rejection reason")
		}
	default:
		return NewError(CodeInvalidInput, "incident report requires a terminal resolved, escalated, or failed state")
	}
	return nil
}

type IncidentReportExecution struct {
	GrantID     string        `json:"grant_id"`
	ReceiptID   string        `json:"receipt_id"`
	Action      ActionSpec    `json:"action"`
	Outcome     ActionOutcome `json:"outcome"`
	DryRun      bool          `json:"dry_run"`
	CompletedAt time.Time     `json:"completed_at"`
}

func (e IncidentReportExecution) Validate() error {
	if err := requireSafeReportText("report.execution.grant_id", e.GrantID); err != nil {
		return err
	}
	if err := requireSafeReportText("report.execution.receipt_id", e.ReceiptID); err != nil {
		return err
	}
	if err := e.Action.Validate(); err != nil {
		return err
	}
	if !e.Outcome.Valid() {
		return NewError(CodeInvalidInput, "report execution outcome is invalid")
	}
	if e.DryRun != (e.Outcome == ActionDryRun) {
		return NewError(CodeInvalidInput, "report execution dry_run must exactly match a dry-run outcome")
	}
	return requireTime("report.execution.completed_at", e.CompletedAt)
}

// IncidentReport is deterministic, sanitized output assembled by Operator.
// Digest seals the report independently of notification delivery state.
type IncidentReport struct {
	SchemaVersion     string                   `json:"schema_version"`
	ReportID          string                   `json:"report_id"`
	RequestID         string                   `json:"request_id"`
	IncidentID        string                   `json:"incident_id"`
	CorrelationID     string                   `json:"correlation_id"`
	DiagnosisReportID string                   `json:"diagnosis_report_id"`
	Target            ResourceTarget           `json:"target"`
	FinalState        IncidentState            `json:"final_state"`
	Reason            IncidentReportReason     `json:"reason"`
	Summary           string                   `json:"summary"`
	Execution         *IncidentReportExecution `json:"execution,omitempty"`
	CreatedAt         time.Time                `json:"created_at"`
	Digest            string                   `json:"digest"`
}

func (r IncidentReport) Validate() error {
	if r.SchemaVersion != SchemaVersionV1 {
		return NewError(CodeInvalidInput, "unsupported incident report schema version")
	}
	for field, value := range map[string]string{
		"report.id": r.ReportID, "report.request_id": r.RequestID,
		"report.incident_id": r.IncidentID, "report.correlation_id": r.CorrelationID,
		"report.diagnosis_report_id": r.DiagnosisReportID, "report.summary": r.Summary,
	} {
		if err := requireSafeReportText(field, value); err != nil {
			return err
		}
	}
	if err := validateSafeReportTarget(r.Target); err != nil {
		return err
	}
	if !r.Reason.Valid() || r.Summary != r.Reason.Summary() {
		return NewError(CodeInvalidInput, "incident report summary is not the canonical reason summary")
	}
	if err := validateReportState(r.FinalState, r.Reason); err != nil {
		return err
	}
	if r.Execution != nil {
		if err := r.Execution.Validate(); err != nil {
			return err
		}
		if !r.Execution.Action.Target.Equal(r.Target) {
			return NewError(CodeInvalidInput, "report execution target differs from report target")
		}
	}
	if err := validateReportExecution(r.Reason, r.Execution); err != nil {
		return err
	}
	if err := requireTime("report.created_at", r.CreatedAt); err != nil {
		return err
	}
	if r.Digest != "" {
		return validateDigest("report.digest", r.Digest)
	}
	return nil
}

func validateReportExecution(reason IncidentReportReason, execution *IncidentReportExecution) error {
	switch reason {
	case ReportReasonRecoveryVerified:
		if execution != nil && (execution.Outcome != ActionSucceeded || execution.DryRun) {
			return NewError(CodeInvalidInput, "recovery report execution must be a successful live action")
		}
	case ReportReasonAuthorityExceeded:
		if execution != nil && execution.Outcome != ActionEscalated {
			return NewError(CodeInvalidInput, "authority report execution must have an escalated outcome")
		}
	case ReportReasonDiagnosisInconclusive, ReportReasonPolicyDenied, ReportReasonActionOutcomeUnverified:
		if execution != nil {
			return NewError(CodeInvalidInput, "incident report reason cannot contain execution evidence")
		}
	case ReportReasonDryRunCompleted:
		if execution == nil || execution.Outcome != ActionDryRun || !execution.DryRun {
			return NewError(CodeInvalidInput, "dry-run report requires exact dry-run execution evidence")
		}
	case ReportReasonActionRejected:
		if execution == nil || execution.Outcome != ActionRejected {
			return NewError(CodeInvalidInput, "action rejection report requires rejected execution evidence")
		}
	case ReportReasonActionFailed:
		if execution == nil || (execution.Outcome != ActionFailed && execution.Outcome != ActionRolledBack) {
			return NewError(CodeInvalidInput, "action failure report requires failed or rolled-back execution evidence")
		}
	case ReportReasonVerificationTimedOut:
		if execution == nil || execution.Outcome != ActionSucceeded || execution.DryRun {
			return NewError(CodeInvalidInput, "verification-timeout report requires successful live execution evidence")
		}
	}
	return nil
}

func (r IncidentReport) ComputeDigest() (string, error) {
	r.Digest = ""
	r.CreatedAt = utc(r.CreatedAt)
	if r.Execution != nil {
		execution := *r.Execution
		execution.CompletedAt = utc(execution.CompletedAt)
		r.Execution = &execution
	}
	if err := r.Validate(); err != nil {
		return "", err
	}
	return digestJSON(r)
}

func (r *IncidentReport) Seal() error {
	if r == nil {
		return NewError(CodeInvalidInput, "incident report is required")
	}
	digest, err := r.ComputeDigest()
	if err != nil {
		return err
	}
	r.Digest = digest
	return nil
}

func (r IncidentReport) VerifyDigest() error {
	if err := validateDigest("report.digest", r.Digest); err != nil {
		return err
	}
	expected, err := r.ComputeDigest()
	if err != nil {
		return err
	}
	if !digestEqual(expected, r.Digest) {
		return NewError(CodeInvalidInput, "incident report digest does not match its contents")
	}
	return nil
}

type NotificationChannel string

const NotificationChannelWhatsApp NotificationChannel = "whatsapp"

func (c NotificationChannel) Valid() bool { return c == NotificationChannelWhatsApp }

// NotificationDelivery is the narrow success value returned by a notifier.
type NotificationDelivery struct {
	Channel           NotificationChannel `json:"channel"`
	ProviderMessageID string              `json:"provider_message_id"`
}

func (d NotificationDelivery) Validate() error {
	if !d.Channel.Valid() {
		return NewError(CodeInvalidInput, "notification channel is invalid")
	}
	return requireSafeReportText("notification.provider_message_id", d.ProviderMessageID)
}

type NotificationStatus string

const (
	NotificationDelivered NotificationStatus = "delivered"
	NotificationFailed    NotificationStatus = "failed"
)

func (s NotificationStatus) Valid() bool {
	return s == NotificationDelivered || s == NotificationFailed
}

// NotificationReceipt is deliberately separate from IncidentReport so a
// delivery failure cannot change or invalidate the terminal incident result.
type NotificationReceipt struct {
	ReportID          string              `json:"report_id"`
	IdempotencyKey    string              `json:"idempotency_key"`
	Channel           NotificationChannel `json:"channel"`
	Status            NotificationStatus  `json:"status"`
	ProviderMessageID string              `json:"provider_message_id,omitempty"`
	AttemptedAt       time.Time           `json:"attempted_at"`
	ErrorCode         ErrorCode           `json:"error_code,omitempty"`
	ErrorMessage      string              `json:"error_message,omitempty"`
}

func (r NotificationReceipt) Validate() error {
	if err := requireSafeReportText("notification.report_id", r.ReportID); err != nil {
		return err
	}
	if err := requireSafeReportText("notification.idempotency_key", r.IdempotencyKey); err != nil {
		return err
	}
	if !r.Channel.Valid() || !r.Status.Valid() {
		return NewError(CodeInvalidInput, "notification receipt channel or status is invalid")
	}
	if err := requireTime("notification.attempted_at", r.AttemptedAt); err != nil {
		return err
	}
	switch r.Status {
	case NotificationDelivered:
		if err := requireSafeReportText("notification.provider_message_id", r.ProviderMessageID); err != nil {
			return err
		}
		if r.ErrorCode != "" || r.ErrorMessage != "" {
			return NewError(CodeInvalidInput, "delivered notification must not contain an error")
		}
	case NotificationFailed:
		if r.ProviderMessageID != "" || r.ErrorCode == "" {
			return NewError(CodeInvalidInput, "failed notification requires an error and no provider message ID")
		}
		if err := requireSafeReportText("notification.error_message", r.ErrorMessage); err != nil {
			return err
		}
	}
	return nil
}

type IncidentReportResult struct {
	Report       IncidentReport      `json:"report"`
	Notification NotificationReceipt `json:"notification"`
}

func (r IncidentReportResult) Validate() error {
	if err := r.Report.VerifyDigest(); err != nil {
		return err
	}
	if err := r.Notification.Validate(); err != nil {
		return err
	}
	if r.Notification.ReportID != r.Report.ReportID || r.Notification.IdempotencyKey != r.Report.RequestID {
		return NewError(CodeInvalidInput, "notification receipt is not bound to the incident report")
	}
	return nil
}

func validateSafeReportTarget(target ResourceTarget) error {
	if err := target.Validate(); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"report.target.api_version": target.APIVersion, "report.target.kind": target.Kind,
		"report.target.namespace": target.Namespace, "report.target.name": target.Name,
	} {
		if err := requireSafeReportText(field, value); err != nil {
			return err
		}
	}
	return nil
}

func requireSafeReportText(field, value string) error {
	if err := requireText(field, value); err != nil {
		return err
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return NewError(CodeInvalidInput, field+" contains control characters")
	}
	return nil
}
