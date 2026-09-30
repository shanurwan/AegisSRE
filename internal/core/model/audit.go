package model

import "time"

type AuditEvent struct {
	ID         string    `json:"id"`
	IncidentID string    `json:"incident_id"`
	Actor      AgentID   `json:"actor"`
	Operation  string    `json:"operation"`
	Decision   string    `json:"decision"`
	Reason     string    `json:"reason,omitempty"`
	SideEffect bool      `json:"side_effect"`
	OccurredAt time.Time `json:"occurred_at"`
}

func (e AuditEvent) Validate() error {
	for field, value := range map[string]string{
		"audit.id": e.ID, "audit.incident_id": e.IncidentID,
		"audit.actor": string(e.Actor), "audit.operation": e.Operation,
		"audit.decision": e.Decision,
	} {
		if err := requireText(field, value); err != nil {
			return err
		}
	}
	return requireTime("audit.occurred_at", e.OccurredAt)
}

type PolicyDecision struct {
	Allowed bool      `json:"allowed"`
	Code    ErrorCode `json:"code,omitempty"`
	Reason  string    `json:"reason,omitempty"`
}

func Allow() PolicyDecision {
	return PolicyDecision{Allowed: true}
}

func Deny(code ErrorCode, reason string) PolicyDecision {
	return PolicyDecision{Allowed: false, Code: code, Reason: reason}
}
