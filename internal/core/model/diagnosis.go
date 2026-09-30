package model

import "time"

type DiagnosisStatus string

const (
	DiagnosisConfirmed    DiagnosisStatus = "confirmed"
	DiagnosisInconclusive DiagnosisStatus = "inconclusive"
)

func (s DiagnosisStatus) Valid() bool {
	return s == DiagnosisConfirmed || s == DiagnosisInconclusive
}

type Hypothesis struct {
	Summary                  string   `json:"summary"`
	Confidence               float64  `json:"confidence"`
	SupportingEvidenceIDs    []string `json:"supporting_evidence_ids,omitempty"`
	ContradictingEvidenceIDs []string `json:"contradicting_evidence_ids,omitempty"`
}

func (h Hypothesis) Validate() error {
	if err := requireText("hypothesis.summary", h.Summary); err != nil {
		return err
	}
	if err := validateConfidence(h.Confidence); err != nil {
		return err
	}
	if err := validateUniqueStrings("hypothesis.supporting_evidence_ids", h.SupportingEvidenceIDs, false); err != nil {
		return err
	}
	return validateUniqueStrings("hypothesis.contradicting_evidence_ids", h.ContradictingEvidenceIDs, false)
}

type ActionKind string

const (
	ActionRestartDeployment ActionKind = "restart_deployment"
	ActionScaleDeployment   ActionKind = "scale_deployment"
)

func (a ActionKind) Valid() bool {
	return a == ActionRestartDeployment || a == ActionScaleDeployment
}

type ActionParameters struct {
	Replicas *int32 `json:"replicas,omitempty"`
}

type ActionSpec struct {
	Kind       ActionKind       `json:"kind"`
	Target     ResourceTarget   `json:"target"`
	Parameters ActionParameters `json:"parameters"`
}

func (a ActionSpec) Validate() error {
	if !a.Kind.Valid() {
		return NewError(CodeInvalidInput, "action kind is invalid")
	}
	if err := a.Target.Validate(); err != nil {
		return err
	}
	if a.Target.APIVersion != "apps/v1" || a.Target.Kind != "Deployment" {
		return NewError(CodeOutOfScope, "v1 remediation actions target apps/v1 Deployments only")
	}
	switch a.Kind {
	case ActionRestartDeployment:
		if a.Parameters.Replicas != nil {
			return NewError(CodeInvalidInput, "restart_deployment does not accept replicas")
		}
	case ActionScaleDeployment:
		if a.Parameters.Replicas == nil || *a.Parameters.Replicas < 0 {
			return NewError(CodeInvalidInput, "scale_deployment requires non-negative replicas")
		}
	}
	return nil
}

func (a ActionSpec) Equal(other ActionSpec) bool {
	if a.Kind != other.Kind || !a.Target.Equal(other.Target) {
		return false
	}
	if a.Parameters.Replicas == nil || other.Parameters.Replicas == nil {
		return a.Parameters.Replicas == nil && other.Parameters.Replicas == nil
	}
	return *a.Parameters.Replicas == *other.Parameters.Replicas
}

type ActionProposal struct {
	ID              string      `json:"id"`
	Action          ActionSpec  `json:"action"`
	Rationale       string      `json:"rationale"`
	Confidence      float64     `json:"confidence"`
	EvidenceIDs     []string    `json:"evidence_ids"`
	SuccessCriteria []string    `json:"success_criteria"`
	Rollback        *ActionSpec `json:"rollback,omitempty"`
}

func (p ActionProposal) Validate() error {
	if err := requireText("proposal.id", p.ID); err != nil {
		return err
	}
	if err := p.Action.Validate(); err != nil {
		return err
	}
	if err := requireText("proposal.rationale", p.Rationale); err != nil {
		return err
	}
	if err := validateConfidence(p.Confidence); err != nil {
		return err
	}
	if err := validateUniqueStrings("proposal.evidence_ids", p.EvidenceIDs, true); err != nil {
		return err
	}
	if err := validateUniqueStrings("proposal.success_criteria", p.SuccessCriteria, true); err != nil {
		return err
	}
	if p.Rollback != nil {
		if err := p.Rollback.Validate(); err != nil {
			return err
		}
		if !p.Rollback.Target.Equal(p.Action.Target) {
			return NewError(CodeInvalidInput, "rollback must target the same resource")
		}
	}
	return nil
}

type DiagnosisReport struct {
	SchemaVersion string           `json:"schema_version"`
	ID            string           `json:"id"`
	IncidentID    string           `json:"incident_id"`
	Status        DiagnosisStatus  `json:"status"`
	RootCause     string           `json:"root_cause,omitempty"`
	Confidence    float64          `json:"confidence"`
	Hypotheses    []Hypothesis     `json:"hypotheses,omitempty"`
	EvidenceIDs   []string         `json:"evidence_ids"`
	Proposals     []ActionProposal `json:"proposals,omitempty"`
	CreatedAt     time.Time        `json:"created_at"`
	Digest        string           `json:"digest"`
}

func (r DiagnosisReport) Validate() error {
	if r.SchemaVersion != SchemaVersionV1 {
		return NewError(CodeInvalidInput, "unsupported diagnosis schema version")
	}
	if err := requireText("diagnosis.id", r.ID); err != nil {
		return err
	}
	if err := requireText("diagnosis.incident_id", r.IncidentID); err != nil {
		return err
	}
	if !r.Status.Valid() {
		return NewError(CodeInvalidInput, "diagnosis status is invalid")
	}
	if err := validateConfidence(r.Confidence); err != nil {
		return err
	}
	if err := requireTime("diagnosis.created_at", r.CreatedAt); err != nil {
		return err
	}
	if err := validateUniqueStrings("diagnosis.evidence_ids", r.EvidenceIDs, true); err != nil {
		return err
	}
	evidenceSet := make(map[string]struct{}, len(r.EvidenceIDs))
	for _, id := range r.EvidenceIDs {
		evidenceSet[id] = struct{}{}
	}
	for _, hypothesis := range r.Hypotheses {
		if err := hypothesis.Validate(); err != nil {
			return err
		}
		for _, id := range append(append([]string{}, hypothesis.SupportingEvidenceIDs...), hypothesis.ContradictingEvidenceIDs...) {
			if _, ok := evidenceSet[id]; !ok {
				return NewError(CodeInvalidInput, "hypothesis references evidence outside the report")
			}
		}
	}
	proposalIDs := make(map[string]struct{}, len(r.Proposals))
	for _, proposal := range r.Proposals {
		if err := proposal.Validate(); err != nil {
			return err
		}
		if _, ok := proposalIDs[proposal.ID]; ok {
			return NewError(CodeInvalidInput, "diagnosis has duplicate proposal IDs")
		}
		proposalIDs[proposal.ID] = struct{}{}
		for _, id := range proposal.EvidenceIDs {
			if _, ok := evidenceSet[id]; !ok {
				return NewError(CodeInvalidInput, "proposal references evidence outside the report")
			}
		}
	}
	if r.Status == DiagnosisConfirmed {
		if err := requireText("diagnosis.root_cause", r.RootCause); err != nil {
			return err
		}
	} else if len(r.Proposals) != 0 {
		return NewError(CodeInconclusiveDiagnosis, "inconclusive diagnosis must not propose a mutation")
	}
	if r.Digest != "" {
		return validateDigest("diagnosis.digest", r.Digest)
	}
	return nil
}

func (r DiagnosisReport) ComputeDigest() (string, error) {
	copy := r
	copy.Digest = ""
	copy.CreatedAt = utc(copy.CreatedAt)
	if err := copy.Validate(); err != nil {
		return "", err
	}
	return digestJSON(copy)
}

func (r *DiagnosisReport) Seal() error {
	if r == nil {
		return NewError(CodeInvalidInput, "diagnosis report is required")
	}
	digest, err := r.ComputeDigest()
	if err != nil {
		return err
	}
	r.Digest = digest
	return nil
}

func (r DiagnosisReport) VerifyDigest() error {
	if err := validateDigest("diagnosis.digest", r.Digest); err != nil {
		return err
	}
	expected, err := r.ComputeDigest()
	if err != nil {
		return err
	}
	if !digestEqual(expected, r.Digest) {
		return NewError(CodeInvalidInput, "diagnosis digest does not match its contents")
	}
	return nil
}

func (r DiagnosisReport) Proposal(id string) (ActionProposal, bool) {
	for _, proposal := range r.Proposals {
		if proposal.ID == id {
			return proposal, true
		}
	}
	return ActionProposal{}, false
}

type InvestigationScope struct {
	Namespaces []string         `json:"namespaces"`
	Targets    []ResourceTarget `json:"targets,omitempty"`
}

func (s InvestigationScope) Validate() error {
	if err := validateUniqueStrings("investigation.namespaces", s.Namespaces, true); err != nil {
		return err
	}
	for _, target := range s.Targets {
		if err := target.Validate(); err != nil {
			return err
		}
	}
	return nil
}

type InvestigationBudget struct {
	MaxToolCalls int           `json:"max_tool_calls"`
	MaxEvidence  int           `json:"max_evidence"`
	Timeout      time.Duration `json:"timeout"`
}

func (b InvestigationBudget) Validate() error {
	if b.MaxToolCalls < 1 || b.MaxToolCalls > 32 || b.MaxEvidence < 1 || b.MaxEvidence > 32 {
		return NewError(CodeInvalidInput, "investigation budget is outside safe bounds")
	}
	if b.Timeout <= 0 || b.Timeout > 10*time.Minute {
		return NewError(CodeInvalidInput, "investigation timeout is outside safe bounds")
	}
	return nil
}

type InvestigationRequest struct {
	SchemaVersion      string              `json:"schema_version"`
	Incident           Incident            `json:"incident"`
	InitialEvidenceIDs []string            `json:"initial_evidence_ids,omitempty"`
	Scope              InvestigationScope  `json:"scope"`
	Budget             InvestigationBudget `json:"budget"`
	RequestedAt        time.Time           `json:"requested_at"`
}

func (r InvestigationRequest) Validate() error {
	if r.SchemaVersion != SchemaVersionV1 {
		return NewError(CodeInvalidInput, "unsupported investigation schema version")
	}
	if err := r.Incident.Validate(); err != nil {
		return err
	}
	if err := validateUniqueStrings("investigation.initial_evidence_ids", r.InitialEvidenceIDs, false); err != nil {
		return err
	}
	if err := r.Scope.Validate(); err != nil {
		return err
	}
	if err := r.Budget.Validate(); err != nil {
		return err
	}
	return requireTime("investigation.requested_at", r.RequestedAt)
}
