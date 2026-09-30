package model

import (
	"encoding/json"
	"time"
)

type EvidenceSource string

const (
	EvidenceMetrics    EvidenceSource = "metrics"
	EvidenceLogs       EvidenceSource = "logs"
	EvidenceKubernetes EvidenceSource = "kubernetes"
	EvidenceTraces     EvidenceSource = "traces"
)

func (s EvidenceSource) Valid() bool {
	switch s {
	case EvidenceMetrics, EvidenceLogs, EvidenceKubernetes, EvidenceTraces:
		return true
	default:
		return false
	}
}

// EvidenceItem preserves the provenance and exact result bytes used for a
// diagnosis. Digest is a SHA-256 seal over every field except Digest itself.
type EvidenceItem struct {
	ID          string          `json:"id"`
	IncidentID  string          `json:"incident_id"`
	Source      EvidenceSource  `json:"source"`
	Tool        string          `json:"tool"`
	Query       string          `json:"query,omitempty"`
	Summary     string          `json:"summary"`
	ObservedAt  time.Time       `json:"observed_at"`
	WindowStart *time.Time      `json:"window_start,omitempty"`
	WindowEnd   *time.Time      `json:"window_end,omitempty"`
	Payload     json.RawMessage `json:"payload"`
	Digest      string          `json:"digest"`
}

func (e EvidenceItem) Validate() error {
	for field, value := range map[string]string{
		"evidence.id": e.ID, "evidence.incident_id": e.IncidentID,
		"evidence.tool": e.Tool, "evidence.summary": e.Summary,
	} {
		if err := requireText(field, value); err != nil {
			return err
		}
	}
	if !e.Source.Valid() {
		return NewError(CodeInvalidInput, "evidence source is invalid")
	}
	if err := requireTime("evidence.observed_at", e.ObservedAt); err != nil {
		return err
	}
	if len(e.Payload) == 0 || !json.Valid(e.Payload) {
		return NewError(CodeInvalidInput, "evidence payload must be valid JSON")
	}
	if (e.WindowStart == nil) != (e.WindowEnd == nil) {
		return NewError(CodeInvalidInput, "evidence window requires both start and end")
	}
	if e.WindowStart != nil {
		if e.WindowStart.IsZero() || e.WindowEnd.IsZero() || !e.WindowEnd.After(*e.WindowStart) {
			return NewError(CodeInvalidInput, "evidence window is invalid")
		}
	}
	if e.Digest != "" {
		return validateDigest("evidence.digest", e.Digest)
	}
	return nil
}

func (e EvidenceItem) canonicalForDigest() EvidenceItem {
	copy := e
	copy.Digest = ""
	copy.ObservedAt = utc(copy.ObservedAt)
	if copy.WindowStart != nil {
		value := utc(*copy.WindowStart)
		copy.WindowStart = &value
	}
	if copy.WindowEnd != nil {
		value := utc(*copy.WindowEnd)
		copy.WindowEnd = &value
	}
	return copy
}

func (e EvidenceItem) ComputeDigest() (string, error) {
	copy := e
	copy.Digest = ""
	if err := copy.Validate(); err != nil {
		return "", err
	}
	return digestJSON(copy.canonicalForDigest())
}

func (e *EvidenceItem) Seal() error {
	if e == nil {
		return NewError(CodeInvalidInput, "evidence is required")
	}
	digest, err := e.ComputeDigest()
	if err != nil {
		return err
	}
	e.Digest = digest
	return nil
}

func (e EvidenceItem) VerifyDigest() error {
	if err := validateDigest("evidence.digest", e.Digest); err != nil {
		return err
	}
	expected, err := e.ComputeDigest()
	if err != nil {
		return err
	}
	if !digestEqual(expected, e.Digest) {
		return NewError(CodeInvalidInput, "evidence digest does not match its contents")
	}
	return nil
}
