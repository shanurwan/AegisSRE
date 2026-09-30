package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type AgentID string

const (
	AgentMonitor      AgentID = "aegissre-monitor"
	AgentInvestigator AgentID = "aegissre-investigator"
	AgentOperator     AgentID = "aegissre-operator"
	AgentMCPObserve   AgentID = "aegissre-mcp-observe"
	AgentMCPAction    AgentID = "aegissre-mcp-action"
)

type MessageKind string

const (
	MessageIncidentSignal       MessageKind = "incident.signal"
	MessageInvestigationRequest MessageKind = "incident.investigate"
	MessageDiagnosisReport      MessageKind = "diagnosis.report"
	MessageRemediationRequest   MessageKind = "remediation.execute"
	MessageActionReceipt        MessageKind = "action.receipt"
)

// Envelope is the stable wire envelope carried in an A2A structured-data
// Part. Payload remains raw JSON so transport code can route before decoding.
type Envelope struct {
	SchemaVersion string          `json:"schema_version"`
	MessageID     string          `json:"message_id"`
	IncidentID    string          `json:"incident_id"`
	CorrelationID string          `json:"correlation_id"`
	CausationID   string          `json:"causation_id,omitempty"`
	Sender        AgentID         `json:"sender"`
	Recipient     AgentID         `json:"recipient"`
	Kind          MessageKind     `json:"kind"`
	SentAt        time.Time       `json:"sent_at"`
	Payload       json.RawMessage `json:"payload"`
}

func NewEnvelope(messageID, incidentID, correlationID, causationID string, sender, recipient AgentID, kind MessageKind, sentAt time.Time, payload any) (Envelope, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, fmt.Errorf("marshal envelope payload: %w", err)
	}
	envelope := Envelope{
		SchemaVersion: SchemaVersionV1,
		MessageID:     messageID,
		IncidentID:    incidentID,
		CorrelationID: correlationID,
		CausationID:   causationID,
		Sender:        sender,
		Recipient:     recipient,
		Kind:          kind,
		SentAt:        sentAt.UTC(),
		Payload:       raw,
	}
	if err := envelope.Validate(); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

func (e Envelope) Validate() error {
	if e.SchemaVersion != SchemaVersionV1 {
		return NewError(CodeInvalidInput, "unsupported envelope schema version")
	}
	for field, value := range map[string]string{
		"message_id": string(e.MessageID), "incident_id": e.IncidentID,
		"correlation_id": e.CorrelationID, "sender": string(e.Sender),
		"recipient": string(e.Recipient), "kind": string(e.Kind),
	} {
		if err := requireText(field, value); err != nil {
			return err
		}
	}
	if err := requireTime("sent_at", e.SentAt); err != nil {
		return err
	}
	if len(e.Payload) == 0 || !json.Valid(e.Payload) {
		return NewError(CodeInvalidInput, "payload must be valid JSON")
	}
	return nil
}

// DecodePayload rejects unknown fields and trailing JSON so role-specific A2A
// handlers fail closed when a peer sends a newer or malformed contract.
func (e Envelope) DecodePayload(destination any) error {
	if destination == nil {
		return NewError(CodeInvalidInput, "payload destination is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(e.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return WrapError(CodeInvalidInput, "decode envelope payload", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return NewError(CodeInvalidInput, "unexpected trailing JSON value")
		}
		return WrapError(CodeInvalidInput, "invalid trailing JSON", err)
	}
	return nil
}
