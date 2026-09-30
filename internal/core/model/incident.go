package model

import "time"

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityWarning, SeverityCritical:
		return true
	default:
		return false
	}
}

type IncidentState string

const (
	IncidentNew                IncidentState = "new"
	IncidentVerifying          IncidentState = "verifying"
	IncidentVerified           IncidentState = "verified"
	IncidentInvestigating      IncidentState = "investigating"
	IncidentDiagnosed          IncidentState = "diagnosed"
	IncidentRemediationPending IncidentState = "remediation_pending"
	IncidentRemediating        IncidentState = "remediating"
	IncidentResolved           IncidentState = "resolved"
	IncidentSuppressed         IncidentState = "suppressed"
	IncidentEscalated          IncidentState = "escalated"
	IncidentFailed             IncidentState = "failed"
)

func (s IncidentState) Valid() bool {
	switch s {
	case IncidentNew, IncidentVerifying, IncidentVerified, IncidentInvestigating,
		IncidentDiagnosed, IncidentRemediationPending, IncidentRemediating,
		IncidentResolved, IncidentSuppressed, IncidentEscalated, IncidentFailed:
		return true
	default:
		return false
	}
}

func (s IncidentState) Terminal() bool {
	switch s {
	case IncidentResolved, IncidentSuppressed, IncidentEscalated, IncidentFailed:
		return true
	default:
		return false
	}
}

var incidentTransitions = map[IncidentState]map[IncidentState]struct{}{
	IncidentNew:                states(IncidentVerifying, IncidentSuppressed, IncidentFailed),
	IncidentVerifying:          states(IncidentVerified, IncidentSuppressed, IncidentEscalated, IncidentFailed),
	IncidentVerified:           states(IncidentInvestigating, IncidentEscalated, IncidentFailed),
	IncidentInvestigating:      states(IncidentDiagnosed, IncidentEscalated, IncidentFailed),
	IncidentDiagnosed:          states(IncidentRemediationPending, IncidentResolved, IncidentEscalated, IncidentFailed),
	IncidentRemediationPending: states(IncidentRemediating, IncidentEscalated, IncidentFailed),
	IncidentRemediating:        states(IncidentResolved, IncidentEscalated, IncidentFailed),
}

func states(values ...IncidentState) map[IncidentState]struct{} {
	result := make(map[IncidentState]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func CanTransitionIncident(from, to IncidentState) bool {
	allowed, ok := incidentTransitions[from]
	if !ok {
		return false
	}
	_, ok = allowed[to]
	return ok
}

func ValidateIncidentTransition(from, to IncidentState) error {
	if !from.Valid() || !to.Valid() {
		return NewError(CodeInvalidStateTransition, "incident state is unknown")
	}
	if !CanTransitionIncident(from, to) {
		return NewError(CodeInvalidStateTransition, "incident transition is not allowed")
	}
	return nil
}

type IncidentSignal struct {
	ID          string            `json:"id"`
	Source      string            `json:"source"`
	RuleID      string            `json:"rule_id"`
	Fingerprint string            `json:"fingerprint"`
	Summary     string            `json:"summary"`
	Severity    Severity          `json:"severity"`
	ObservedAt  time.Time         `json:"observed_at"`
	Labels      map[string]string `json:"labels,omitempty"`
}

func (s IncidentSignal) Validate() error {
	for field, value := range map[string]string{
		"signal.id": s.ID, "signal.source": s.Source, "signal.rule_id": s.RuleID,
		"signal.fingerprint": s.Fingerprint, "signal.summary": s.Summary,
	} {
		if err := requireText(field, value); err != nil {
			return err
		}
	}
	if !s.Severity.Valid() {
		return NewError(CodeInvalidInput, "signal severity is invalid")
	}
	return requireTime("signal.observed_at", s.ObservedAt)
}

type Incident struct {
	ID                string         `json:"id"`
	Signal            IncidentSignal `json:"signal"`
	State             IncidentState  `json:"state"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
	ResolvedAt        *time.Time     `json:"resolved_at,omitempty"`
	EvidenceIDs       []string       `json:"evidence_ids,omitempty"`
	DiagnosisReportID string         `json:"diagnosis_report_id,omitempty"`
}

func NewIncident(id string, signal IncidentSignal, now time.Time) (Incident, error) {
	incident := Incident{
		ID: id, Signal: signal, State: IncidentNew,
		CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}
	if err := incident.Validate(); err != nil {
		return Incident{}, err
	}
	return incident, nil
}

func (i Incident) Validate() error {
	if err := requireText("incident.id", i.ID); err != nil {
		return err
	}
	if err := i.Signal.Validate(); err != nil {
		return err
	}
	if !i.State.Valid() {
		return NewError(CodeInvalidInput, "incident state is invalid")
	}
	if err := requireTime("incident.created_at", i.CreatedAt); err != nil {
		return err
	}
	if err := requireTime("incident.updated_at", i.UpdatedAt); err != nil {
		return err
	}
	if i.UpdatedAt.Before(i.CreatedAt) {
		return NewError(CodeInvalidInput, "incident updated_at precedes created_at")
	}
	if err := validateUniqueStrings("incident.evidence_ids", i.EvidenceIDs, false); err != nil {
		return err
	}
	if i.State == IncidentResolved {
		if i.ResolvedAt == nil || i.ResolvedAt.IsZero() {
			return NewError(CodeInvalidInput, "resolved incident requires resolved_at")
		}
		if i.ResolvedAt.Before(i.CreatedAt) {
			return NewError(CodeInvalidInput, "incident resolved_at precedes created_at")
		}
	} else if i.ResolvedAt != nil {
		return NewError(CodeInvalidInput, "only a resolved incident may set resolved_at")
	}
	return nil
}

// Transition changes state only after validation, leaving the receiver intact
// on failure.
func (i *Incident) Transition(to IncidentState, at time.Time) error {
	if i == nil {
		return NewError(CodeInvalidInput, "incident is required")
	}
	if err := ValidateIncidentTransition(i.State, to); err != nil {
		return err
	}
	if err := requireTime("transition time", at); err != nil {
		return err
	}
	at = at.UTC()
	if at.Before(i.UpdatedAt) {
		return NewError(CodeInvalidStateTransition, "transition time precedes current incident state")
	}
	i.State = to
	i.UpdatedAt = at
	if to == IncidentResolved {
		resolvedAt := at
		i.ResolvedAt = &resolvedAt
	}
	return nil
}
