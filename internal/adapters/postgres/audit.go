package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
)

// Auditor is an append-only PostgreSQL implementation of ports.Auditor.
// Re-recording the exact same event is idempotent; reusing an event ID with
// different contents fails closed and never updates the original row.
type Auditor struct {
	db DB
}

var _ ports.Auditor = (*Auditor)(nil)

func NewAuditor(db DB) (*Auditor, error) {
	if db == nil {
		return nil, fmt.Errorf("postgres audit database is required")
	}
	return &Auditor{db: db}, nil
}

func (a *Auditor) Record(ctx context.Context, event model.AuditEvent) error {
	if a == nil || a.db == nil {
		return fmt.Errorf("postgres auditor is unavailable")
	}
	if err := event.Validate(); err != nil {
		return err
	}
	payload, err := marshalBounded(event)
	if err != nil {
		return err
	}
	fingerprint := sha256.Sum256(payload)
	command, err := a.db.Exec(ctx, `
INSERT INTO aegis_audit_events (
    id, incident_id, actor, operation, decision, side_effect,
    occurred_at, event_json, event_fingerprint
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (id) DO NOTHING`,
		event.ID, event.IncidentID, string(event.Actor), event.Operation, event.Decision,
		event.SideEffect, event.OccurredAt.UTC(), payload, fingerprint[:],
	)
	if err != nil {
		return fmt.Errorf("append durable audit event: %w", err)
	}
	if command.RowsAffected() == 1 {
		return nil
	}
	var stored []byte
	if err := a.db.QueryRow(ctx,
		"SELECT event_fingerprint FROM aegis_audit_events WHERE id = $1", event.ID,
	).Scan(&stored); err != nil {
		return fmt.Errorf("read duplicate durable audit event: %w", err)
	}
	if len(stored) != sha256.Size || subtle.ConstantTimeCompare(stored, fingerprint[:]) != 1 {
		return model.NewError(model.CodeInvalidInput, "audit event ID was reused with different contents")
	}
	return nil
}
