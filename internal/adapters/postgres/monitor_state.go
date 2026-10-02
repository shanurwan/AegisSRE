package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
)

const maxMonitorCheckpointBytes = 4 << 20

type MonitorState struct {
	db DB
}

func NewMonitorState(db DB) (*MonitorState, error) {
	if db == nil {
		return nil, fmt.Errorf("postgres monitor state database is required")
	}
	return &MonitorState{db: db}, nil
}

func (s *MonitorState) AcquireMonitorLease(
	ctx context.Context,
	namespace, owner string,
	lease time.Duration,
) (ports.MonitorLease, bool, error) {
	if err := validateMonitorIdentity(namespace, owner); err != nil {
		return ports.MonitorLease{}, false, err
	}
	if err := validateLease(lease); err != nil {
		return ports.MonitorLease{}, false, err
	}
	token, err := randomToken()
	if err != nil {
		return ports.MonitorLease{}, false, err
	}
	var result ports.MonitorLease
	err = s.db.QueryRow(ctx, `
INSERT INTO aegis_monitor_leases (
    namespace, lease_owner, lease_token, fencing_token, lease_until
) VALUES ($1, $2, $3, 1, CURRENT_TIMESTAMP + ($4 * interval '1 microsecond'))
ON CONFLICT (namespace) DO UPDATE SET
    lease_owner = EXCLUDED.lease_owner,
    lease_token = EXCLUDED.lease_token,
    fencing_token = aegis_monitor_leases.fencing_token + 1,
    lease_until = EXCLUDED.lease_until,
    updated_at = CURRENT_TIMESTAMP
WHERE aegis_monitor_leases.lease_owner = EXCLUDED.lease_owner
   OR aegis_monitor_leases.lease_until <= CURRENT_TIMESTAMP
RETURNING namespace, lease_owner, lease_token, fencing_token, lease_until`,
		namespace, owner, token, lease.Microseconds(),
	).Scan(&result.Namespace, &result.Owner, &result.Token, &result.FencingToken, &result.LeaseUntil)
	if noRows(err) {
		return ports.MonitorLease{}, false, nil
	}
	if err != nil {
		return ports.MonitorLease{}, false, fmt.Errorf("acquire monitor lease: %w", err)
	}
	return result, true, nil
}

func (s *MonitorState) RenewMonitorLease(
	ctx context.Context,
	lease ports.MonitorLease,
	duration time.Duration,
) (ports.MonitorLease, error) {
	if err := validateMonitorLease(lease); err != nil {
		return ports.MonitorLease{}, err
	}
	if err := validateLease(duration); err != nil {
		return ports.MonitorLease{}, err
	}
	var result ports.MonitorLease
	err := s.db.QueryRow(ctx, `
UPDATE aegis_monitor_leases
SET lease_until = CURRENT_TIMESTAMP + ($5 * interval '1 microsecond'),
    updated_at = CURRENT_TIMESTAMP
WHERE namespace = $1 AND lease_owner = $2 AND lease_token = $3
  AND fencing_token = $4 AND lease_until > CURRENT_TIMESTAMP
RETURNING namespace, lease_owner, lease_token, fencing_token, lease_until`,
		lease.Namespace, lease.Owner, lease.Token, lease.FencingToken, duration.Microseconds(),
	).Scan(&result.Namespace, &result.Owner, &result.Token, &result.FencingToken, &result.LeaseUntil)
	if noRows(err) {
		return ports.MonitorLease{}, monitorLeaseLost()
	}
	if err != nil {
		return ports.MonitorLease{}, fmt.Errorf("renew monitor lease: %w", err)
	}
	return result, nil
}

func (s *MonitorState) LoadMonitorCheckpoint(
	ctx context.Context,
	lease ports.MonitorLease,
) (ports.MonitorCheckpoint, bool, error) {
	if err := validateMonitorLease(lease); err != nil {
		return ports.MonitorCheckpoint{}, false, err
	}
	var checkpoint ports.MonitorCheckpoint
	err := s.db.QueryRow(ctx, `
SELECT c.checkpoint_json, c.version, c.fencing_token, c.updated_at
FROM aegis_monitor_checkpoints c
JOIN aegis_monitor_leases l ON l.namespace = c.namespace
WHERE c.namespace = $1 AND l.lease_owner = $2 AND l.lease_token = $3
  AND l.fencing_token = $4 AND l.lease_until > CURRENT_TIMESTAMP`,
		lease.Namespace, lease.Owner, lease.Token, lease.FencingToken,
	).Scan(&checkpoint.Payload, &checkpoint.Version, &checkpoint.FencingToken, &checkpoint.UpdatedAt)
	if noRows(err) {
		var current bool
		checkErr := s.db.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1 FROM aegis_monitor_leases
    WHERE namespace = $1 AND lease_owner = $2 AND lease_token = $3
      AND fencing_token = $4 AND lease_until > CURRENT_TIMESTAMP
)`, lease.Namespace, lease.Owner, lease.Token, lease.FencingToken).Scan(&current)
		if checkErr != nil {
			return ports.MonitorCheckpoint{}, false, fmt.Errorf("check monitor lease while loading checkpoint: %w", checkErr)
		}
		if !current {
			return ports.MonitorCheckpoint{}, false, monitorLeaseLost()
		}
		return ports.MonitorCheckpoint{}, false, nil
	}
	if err != nil {
		return ports.MonitorCheckpoint{}, false, fmt.Errorf("load monitor checkpoint: %w", err)
	}
	checkpoint.Payload = bytes.Clone(checkpoint.Payload)
	return checkpoint, true, nil
}

func (s *MonitorState) SaveMonitorCheckpoint(
	ctx context.Context,
	lease ports.MonitorLease,
	payload []byte,
) (ports.MonitorCheckpoint, error) {
	if err := validateMonitorLease(lease); err != nil {
		return ports.MonitorCheckpoint{}, err
	}
	if len(payload) == 0 || len(payload) > maxMonitorCheckpointBytes || !json.Valid(payload) {
		return ports.MonitorCheckpoint{}, model.NewError(model.CodeInvalidInput, "monitor checkpoint is not valid bounded JSON")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return ports.MonitorCheckpoint{}, fmt.Errorf("begin monitor checkpoint transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var current bool
	err = tx.QueryRow(ctx, `
SELECT true FROM aegis_monitor_leases
WHERE namespace = $1 AND lease_owner = $2 AND lease_token = $3
  AND fencing_token = $4 AND lease_until > CURRENT_TIMESTAMP
FOR UPDATE`, lease.Namespace, lease.Owner, lease.Token, lease.FencingToken).Scan(&current)
	if noRows(err) {
		return ports.MonitorCheckpoint{}, monitorLeaseLost()
	}
	if err != nil {
		return ports.MonitorCheckpoint{}, fmt.Errorf("fence monitor checkpoint writer: %w", err)
	}
	if !current {
		return ports.MonitorCheckpoint{}, monitorLeaseLost()
	}
	var checkpoint ports.MonitorCheckpoint
	err = tx.QueryRow(ctx, `
INSERT INTO aegis_monitor_checkpoints (
    namespace, checkpoint_json, version, fencing_token, updated_at
) VALUES ($1, $2::jsonb, 1, $3, CURRENT_TIMESTAMP)
ON CONFLICT (namespace) DO UPDATE SET
    checkpoint_json = EXCLUDED.checkpoint_json,
    version = aegis_monitor_checkpoints.version + 1,
    fencing_token = EXCLUDED.fencing_token,
    updated_at = CURRENT_TIMESTAMP
RETURNING checkpoint_json, version, fencing_token, updated_at`,
		lease.Namespace, payload, lease.FencingToken,
	).Scan(&checkpoint.Payload, &checkpoint.Version, &checkpoint.FencingToken, &checkpoint.UpdatedAt)
	if err != nil {
		return ports.MonitorCheckpoint{}, fmt.Errorf("save monitor checkpoint: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return ports.MonitorCheckpoint{}, fmt.Errorf("commit monitor checkpoint: %w", err)
	}
	checkpoint.Payload = bytes.Clone(checkpoint.Payload)
	return checkpoint, nil
}

func validateMonitorIdentity(namespace, owner string) error {
	if strings.TrimSpace(namespace) == "" || strings.TrimSpace(namespace) != namespace || len(namespace) > 253 {
		return model.NewError(model.CodeInvalidInput, "monitor lease namespace is invalid")
	}
	return validateOwner(owner)
}

func validateMonitorLease(lease ports.MonitorLease) error {
	if err := validateMonitorIdentity(lease.Namespace, lease.Owner); err != nil {
		return err
	}
	if strings.TrimSpace(lease.Token) == "" || strings.TrimSpace(lease.Token) != lease.Token || len(lease.Token) > 128 || lease.FencingToken < 1 {
		return model.NewError(model.CodeInvalidInput, "monitor lease token is invalid")
	}
	return nil
}

func monitorLeaseLost() error {
	return model.NewError(model.CodeExecutionFailed, "monitor leadership lease was lost")
}

var _ ports.MonitorStateStore = (*MonitorState)(nil)
