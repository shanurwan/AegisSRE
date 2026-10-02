package model

import "time"

const SignatureAlgorithmEd25519 = "Ed25519"

type GrantSignature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

func (s GrantSignature) Empty() bool {
	return s.Algorithm == "" && s.KeyID == "" && s.Value == ""
}

func (s GrantSignature) Validate() error {
	if s.Algorithm != SignatureAlgorithmEd25519 {
		return NewError(CodeInvalidSignature, "grant signature algorithm must be Ed25519")
	}
	if err := requireText("signature.key_id", s.KeyID); err != nil {
		return err
	}
	return requireText("signature.value", s.Value)
}

type ActionPreconditions struct {
	ResourceVersion  string `json:"resource_version,omitempty"`
	ExpectedReplicas *int32 `json:"expected_replicas,omitempty"`
}

type DelegationGrant struct {
	SchemaVersion       string              `json:"schema_version"`
	GrantID             string              `json:"grant_id"`
	Issuer              AgentID             `json:"issuer"`
	Audiences           []AgentID           `json:"audiences"`
	IncidentID          string              `json:"incident_id"`
	DiagnosisReportID   string              `json:"diagnosis_report_id"`
	DiagnosisDigest     string              `json:"diagnosis_digest"`
	PolicyDigest        string              `json:"policy_digest,omitempty"`
	DiagnosisConfidence float64             `json:"diagnosis_confidence"`
	EvidenceIDs         []string            `json:"evidence_ids"`
	ProposalID          string              `json:"proposal_id"`
	Action              ActionSpec          `json:"action"`
	Preconditions       ActionPreconditions `json:"preconditions"`
	DryRun              bool                `json:"dry_run"`
	IdempotencyKey      string              `json:"idempotency_key"`
	IssuedAt            time.Time           `json:"issued_at"`
	NotBefore           time.Time           `json:"not_before"`
	ExpiresAt           time.Time           `json:"expires_at"`
	Signature           GrantSignature      `json:"signature"`
}

func (g DelegationGrant) Validate() error {
	if g.SchemaVersion != SchemaVersionV1 {
		return NewError(CodeInvalidInput, "unsupported delegation grant schema version")
	}
	for field, value := range map[string]string{
		"grant.id": g.GrantID, "grant.incident_id": g.IncidentID,
		"grant.diagnosis_report_id": g.DiagnosisReportID,
		"grant.proposal_id":         g.ProposalID, "grant.idempotency_key": g.IdempotencyKey,
	} {
		if err := requireText(field, value); err != nil {
			return err
		}
	}
	if g.Issuer != AgentMonitor {
		return NewError(CodeDelegationRequired, "delegation grant issuer is not aegissre-monitor")
	}
	if err := validateGrantAudiences(g.Audiences); err != nil {
		return err
	}
	if err := validateDigest("grant.diagnosis_digest", g.DiagnosisDigest); err != nil {
		return err
	}
	if g.PolicyDigest != "" {
		if err := validateDigest("grant.policy_digest", g.PolicyDigest); err != nil {
			return err
		}
	}
	if err := validateConfidence(g.DiagnosisConfidence); err != nil {
		return err
	}
	if err := validateUniqueStrings("grant.evidence_ids", g.EvidenceIDs, true); err != nil {
		return err
	}
	if err := g.Action.Validate(); err != nil {
		return err
	}
	if g.Preconditions.ExpectedReplicas != nil && *g.Preconditions.ExpectedReplicas < 0 {
		return NewError(CodeInvalidInput, "expected replicas must be non-negative")
	}
	if err := requireTime("grant.issued_at", g.IssuedAt); err != nil {
		return err
	}
	if err := requireTime("grant.not_before", g.NotBefore); err != nil {
		return err
	}
	if err := requireTime("grant.expires_at", g.ExpiresAt); err != nil {
		return err
	}
	if g.NotBefore.Before(g.IssuedAt) {
		return NewError(CodeInvalidInput, "grant not_before precedes issued_at")
	}
	if !g.ExpiresAt.After(g.NotBefore) {
		return NewError(CodeInvalidInput, "grant expires_at must follow not_before")
	}
	if !g.Signature.Empty() {
		return g.Signature.Validate()
	}
	return nil
}

func (g DelegationGrant) ValidateSigned() error {
	if err := g.Validate(); err != nil {
		return err
	}
	if g.Signature.Empty() {
		return NewError(CodeDelegationRequired, "delegation grant is unsigned")
	}
	return g.Signature.Validate()
}

func (g DelegationGrant) HasAudience(audience AgentID) bool {
	for _, candidate := range g.Audiences {
		if candidate == audience {
			return true
		}
	}
	return false
}

func validateGrantAudiences(audiences []AgentID) error {
	if len(audiences) != 2 {
		return NewError(CodeDelegationRequired, "grant requires exactly operator and MCP action audiences")
	}
	seen := make(map[AgentID]struct{}, len(audiences))
	for _, audience := range audiences {
		if audience != AgentOperator && audience != AgentMCPAction {
			return NewError(CodeDelegationRequired, "grant contains an unauthorized audience")
		}
		if _, ok := seen[audience]; ok {
			return NewError(CodeDelegationRequired, "grant contains a duplicate audience")
		}
		seen[audience] = struct{}{}
	}
	if _, ok := seen[AgentOperator]; !ok {
		return NewError(CodeDelegationRequired, "operator audience is required")
	}
	if _, ok := seen[AgentMCPAction]; !ok {
		return NewError(CodeDelegationRequired, "MCP action audience is required")
	}
	return nil
}

type ActionOutcome string

const (
	ActionRejected   ActionOutcome = "rejected"
	ActionDryRun     ActionOutcome = "dry_run"
	ActionSucceeded  ActionOutcome = "succeeded"
	ActionFailed     ActionOutcome = "failed"
	ActionRolledBack ActionOutcome = "rolled_back"
	ActionEscalated  ActionOutcome = "escalated"
)

func (o ActionOutcome) Valid() bool {
	switch o {
	case ActionRejected, ActionDryRun, ActionSucceeded, ActionFailed, ActionRolledBack, ActionEscalated:
		return true
	default:
		return false
	}
}

type ResourceSnapshot struct {
	ResourceVersion   string `json:"resource_version,omitempty"`
	DesiredReplicas   int32  `json:"desired_replicas"`
	ReadyReplicas     int32  `json:"ready_replicas"`
	AvailableReplicas int32  `json:"available_replicas"`
}

type ActionReceipt struct {
	SchemaVersion string            `json:"schema_version"`
	ReceiptID     string            `json:"receipt_id"`
	GrantID       string            `json:"grant_id"`
	IncidentID    string            `json:"incident_id"`
	Action        ActionSpec        `json:"action"`
	Outcome       ActionOutcome     `json:"outcome"`
	DryRun        bool              `json:"dry_run"`
	StartedAt     time.Time         `json:"started_at"`
	CompletedAt   time.Time         `json:"completed_at"`
	Before        *ResourceSnapshot `json:"before,omitempty"`
	After         *ResourceSnapshot `json:"after,omitempty"`
	ErrorCode     ErrorCode         `json:"error_code,omitempty"`
	ErrorMessage  string            `json:"error_message,omitempty"`
	AuditRef      string            `json:"audit_ref"`
}

func (r ActionReceipt) Validate() error {
	if r.SchemaVersion != SchemaVersionV1 {
		return NewError(CodeInvalidInput, "unsupported action receipt schema version")
	}
	for field, value := range map[string]string{
		"receipt.id": r.ReceiptID, "receipt.grant_id": r.GrantID,
		"receipt.incident_id": r.IncidentID, "receipt.audit_ref": r.AuditRef,
	} {
		if err := requireText(field, value); err != nil {
			return err
		}
	}
	if err := r.Action.Validate(); err != nil {
		return err
	}
	if !r.Outcome.Valid() {
		return NewError(CodeInvalidInput, "action outcome is invalid")
	}
	if err := requireTime("receipt.started_at", r.StartedAt); err != nil {
		return err
	}
	if err := requireTime("receipt.completed_at", r.CompletedAt); err != nil {
		return err
	}
	if r.CompletedAt.Before(r.StartedAt) {
		return NewError(CodeInvalidInput, "receipt completed_at precedes started_at")
	}
	if r.DryRun != (r.Outcome == ActionDryRun) {
		return NewError(CodeInvalidInput, "receipt dry_run must exactly match a dry-run outcome")
	}
	if r.Outcome == ActionFailed || r.Outcome == ActionRejected {
		if r.ErrorCode == "" || r.ErrorMessage == "" {
			return NewError(CodeInvalidInput, "failed or rejected receipt requires error details")
		}
	}
	return nil
}
