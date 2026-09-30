package audit

import (
	"context"
	"log/slog"

	"github.com/shanurwan/AegisSRE/internal/core/model"
)

type Logger struct {
	Log *slog.Logger
}

func (l Logger) Record(ctx context.Context, event model.AuditEvent) error {
	logger := l.Log
	if logger == nil {
		logger = slog.Default()
	}
	logger.InfoContext(ctx, "audit",
		"event_id", event.ID,
		"incident_id", event.IncidentID,
		"actor", event.Actor,
		"operation", event.Operation,
		"decision", event.Decision,
		"reason", event.Reason,
		"side_effect", event.SideEffect,
		"occurred_at", event.OccurredAt,
	)
	return nil
}
