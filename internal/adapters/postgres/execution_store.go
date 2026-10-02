package postgres

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
)

type ExecutionLedger struct {
	db        DB
	retention time.Duration
}

var _ ports.ActionExecutionStore = (*ExecutionLedger)(nil)

func NewExecutionLedger(db DB, retention time.Duration) (*ExecutionLedger, error) {
	if db == nil {
		return nil, fmt.Errorf("postgres execution ledger database is required")
	}
	if retention == 0 {
		retention = defaultRetention
	}
	if retention < 24*time.Hour || retention > 10*365*24*time.Hour {
		return nil, model.NewError(model.CodeInvalidInput, "execution retention must be between one day and ten years")
	}
	return &ExecutionLedger{db: db, retention: retention}, nil
}

func (s *ExecutionLedger) ReserveExecution(
	ctx context.Context,
	scope ports.ExecutionScope,
	grant model.DelegationGrant,
	owner string,
	lease time.Duration,
) (ports.ExecutionRecord, error) {
	if s == nil || s.db == nil {
		return ports.ExecutionRecord{}, fmt.Errorf("postgres execution ledger is unavailable")
	}
	if !scope.Valid() {
		return ports.ExecutionRecord{}, model.NewError(model.CodeInvalidInput, "execution scope is invalid")
	}
	if err := validateOwner(owner); err != nil {
		return ports.ExecutionRecord{}, err
	}
	if err := validateLease(lease); err != nil {
		return ports.ExecutionRecord{}, err
	}
	fingerprint, err := signedGrantFingerprint(grant)
	if err != nil {
		return ports.ExecutionRecord{}, err
	}
	grantJSON, err := marshalBounded(grant)
	if err != nil {
		return ports.ExecutionRecord{}, err
	}
	token, err := randomToken()
	if err != nil {
		return ports.ExecutionRecord{}, err
	}

	transaction, err := s.db.Begin(ctx)
	if err != nil {
		return ports.ExecutionRecord{}, fmt.Errorf("begin execution reservation: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if err := lockExecutionKey(ctx, transaction, scope, grant.GrantID); err != nil {
		return ports.ExecutionRecord{}, err
	}

	// Exact terminal records remain recoverable even when a terminal-report
	// fence coexists with them. The fence blocks only a new reservation or an
	// expired reserved lease from being acquired after Monitor closed the
	// post-delegation ambiguity.
	record, storedFingerprint, err := getExecutionForUpdate(ctx, transaction, scope, grant.GrantID)
	if err == nil {
		if !sameFingerprint(storedFingerprint, fingerprint[:]) || record.Grant.IdempotencyKey != grant.IdempotencyKey {
			return ports.ExecutionRecord{}, model.NewError(model.CodeInvalidInput, "grant ID was reused with different signed contents")
		}
		if record.Status != ports.ExecutionReserved {
			if err := transaction.Commit(ctx); err != nil {
				return ports.ExecutionRecord{}, fmt.Errorf("commit terminal execution lookup: %w", err)
			}
			return record, nil
		}
		fenced, err := executionKeyFenced(ctx, transaction, scope, grant.GrantID)
		if err != nil {
			return ports.ExecutionRecord{}, err
		}
		if fenced {
			return ports.ExecutionRecord{}, model.NewError(model.CodeExecutionFailed, "execution was closed by a terminal incident report")
		}

		var recovered ports.ExecutionRecord
		var recoveredFingerprint []byte
		err = scanExecution(transaction.QueryRow(ctx, `
UPDATE aegis_execution_ledger
SET lease_owner = $3,
    lease_token = $4,
    lease_until = CURRENT_TIMESTAMP + ($5 * INTERVAL '1 second'),
    version = version + 1
WHERE scope = $1 AND grant_id = $2
  AND status = 'reserved' AND lease_until <= CURRENT_TIMESTAMP
RETURNING `+executionColumns,
			string(scope), grant.GrantID, owner, token, leaseSeconds(lease),
		), &recovered, &recoveredFingerprint)
		switch {
		case err == nil:
			recovered.Owner = true
			recovered.RecoveredLease = true
			if err := transaction.Commit(ctx); err != nil {
				return ports.ExecutionRecord{}, fmt.Errorf("commit recovered execution lease: %w", err)
			}
			return recovered, nil
		case !noRows(err):
			return ports.ExecutionRecord{}, fmt.Errorf("recover execution lease: %w", err)
		}
		if err := transaction.Commit(ctx); err != nil {
			return ports.ExecutionRecord{}, fmt.Errorf("commit live execution lookup: %w", err)
		}
		return record, nil
	}
	if !noRows(err) {
		return ports.ExecutionRecord{}, err
	}
	fenced, err := executionKeyFenced(ctx, transaction, scope, grant.GrantID)
	if err != nil {
		return ports.ExecutionRecord{}, err
	}
	if fenced {
		return ports.ExecutionRecord{}, model.NewError(model.CodeExecutionFailed, "execution was closed by a terminal incident report")
	}

	command, err := transaction.Exec(ctx, `
INSERT INTO aegis_execution_ledger (
    scope, grant_id, idempotency_key, signed_fingerprint, incident_id,
    grant_json, status, lease_owner, lease_token, lease_until, retention_until
) VALUES (
    $1, $2, $3, $4, $5, $6, 'reserved', $7, $8,
    CURRENT_TIMESTAMP + ($9 * INTERVAL '1 second'),
    GREATEST($10::timestamptz, CURRENT_TIMESTAMP + ($11 * INTERVAL '1 second'))
)
ON CONFLICT DO NOTHING`,
		string(scope), grant.GrantID, grant.IdempotencyKey, fingerprint[:], grant.IncidentID,
		grantJSON, owner, token, leaseSeconds(lease), grant.ExpiresAt.UTC(), leaseSeconds(s.retention),
	)
	if err != nil {
		return ports.ExecutionRecord{}, fmt.Errorf("reserve execution: %w", err)
	}

	if command.RowsAffected() == 1 {
		record, storedFingerprint, err = getExecutionForUpdate(ctx, transaction, scope, grant.GrantID)
		if err != nil {
			return ports.ExecutionRecord{}, err
		}
		if !sameFingerprint(storedFingerprint, fingerprint[:]) {
			return ports.ExecutionRecord{}, model.NewError(model.CodeInvalidInput, "stored grant fingerprint differs after reservation")
		}
		record.Owner = true
		if err := transaction.Commit(ctx); err != nil {
			return ports.ExecutionRecord{}, fmt.Errorf("commit execution reservation: %w", err)
		}
		return record, nil
	}

	record, storedFingerprint, err = getExecutionForUpdate(ctx, transaction, scope, grant.GrantID)
	if noRows(err) {
		var conflictingGrantID string
		err = transaction.QueryRow(ctx, `
SELECT grant_id
FROM aegis_execution_ledger
WHERE scope = $1 AND idempotency_key = $2
FOR UPDATE`, string(scope), grant.IdempotencyKey).Scan(&conflictingGrantID)
		if err != nil {
			return ports.ExecutionRecord{}, fmt.Errorf("locate conflicting execution idempotency key: %w", err)
		}
		return ports.ExecutionRecord{}, model.NewError(
			model.CodeInvalidInput,
			"execution idempotency key was already bound to a different grant",
		)
	}
	if err != nil {
		return ports.ExecutionRecord{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return ports.ExecutionRecord{}, fmt.Errorf("commit duplicate execution lookup: %w", err)
	}
	return record, nil
}

func (s *ExecutionLedger) GetExecution(
	ctx context.Context,
	scope ports.ExecutionScope,
	grant model.DelegationGrant,
) (ports.ExecutionRecord, bool, error) {
	if s == nil || s.db == nil {
		return ports.ExecutionRecord{}, false, fmt.Errorf("postgres execution ledger is unavailable")
	}
	if !scope.Valid() {
		return ports.ExecutionRecord{}, false, model.NewError(model.CodeInvalidInput, "execution scope is invalid")
	}
	fingerprint, err := signedGrantFingerprint(grant)
	if err != nil {
		return ports.ExecutionRecord{}, false, err
	}
	var record ports.ExecutionRecord
	var storedFingerprint []byte
	err = scanExecution(s.db.QueryRow(ctx,
		"SELECT "+executionColumns+" FROM aegis_execution_ledger WHERE scope = $1 AND grant_id = $2",
		string(scope), grant.GrantID,
	), &record, &storedFingerprint)
	if noRows(err) {
		return ports.ExecutionRecord{}, false, nil
	}
	if err != nil {
		return ports.ExecutionRecord{}, false, fmt.Errorf("get execution: %w", err)
	}
	if !sameFingerprint(storedFingerprint, fingerprint[:]) || record.Grant.IdempotencyKey != grant.IdempotencyKey {
		return ports.ExecutionRecord{}, false, model.NewError(model.CodeInvalidInput, "grant ID was reused with different signed contents")
	}
	return record, true, nil
}

func (s *ExecutionLedger) GetExecutionByID(
	ctx context.Context,
	scope ports.ExecutionScope,
	grantID string,
) (ports.ExecutionRecord, bool, error) {
	if s == nil || s.db == nil {
		return ports.ExecutionRecord{}, false, fmt.Errorf("postgres execution ledger is unavailable")
	}
	if !scope.Valid() || grantID == "" {
		return ports.ExecutionRecord{}, false, model.NewError(model.CodeInvalidInput, "execution scope and grant ID are required")
	}
	var record ports.ExecutionRecord
	var storedFingerprint []byte
	err := scanExecution(s.db.QueryRow(ctx,
		"SELECT "+executionColumns+" FROM aegis_execution_ledger WHERE scope = $1 AND grant_id = $2",
		string(scope), grantID,
	), &record, &storedFingerprint)
	if noRows(err) {
		return ports.ExecutionRecord{}, false, nil
	}
	if err != nil {
		return ports.ExecutionRecord{}, false, fmt.Errorf("get execution by ID: %w", err)
	}
	// scanExecution validates the stored signed grant and receipt. This method
	// intentionally does not return ownership or change the row.
	return record, true, nil
}

func (s *ExecutionLedger) CompleteExecution(
	ctx context.Context,
	scope ports.ExecutionScope,
	grantID, leaseToken string,
	receipt model.ActionReceipt,
) (ports.ExecutionRecord, error) {
	if s == nil || s.db == nil {
		return ports.ExecutionRecord{}, fmt.Errorf("postgres execution ledger is unavailable")
	}
	if !scope.Valid() || grantID == "" || leaseToken == "" {
		return ports.ExecutionRecord{}, model.NewError(model.CodeInvalidInput, "execution scope, grant ID, and lease token are required")
	}
	if err := receipt.Validate(); err != nil {
		return ports.ExecutionRecord{}, err
	}
	if receipt.GrantID != grantID {
		return ports.ExecutionRecord{}, model.NewError(model.CodeInvalidInput, "action receipt grant ID differs from the execution reservation")
	}
	receiptJSON, err := marshalBounded(receipt)
	if err != nil {
		return ports.ExecutionRecord{}, err
	}

	transaction, err := s.db.Begin(ctx)
	if err != nil {
		return ports.ExecutionRecord{}, fmt.Errorf("begin execution completion: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	record, _, err := getExecutionForUpdate(ctx, transaction, scope, grantID)
	if err != nil {
		if noRows(err) {
			return ports.ExecutionRecord{}, model.NewError(model.CodeReplayedGrant, "execution reservation does not exist")
		}
		return ports.ExecutionRecord{}, err
	}
	if record.Status == ports.ExecutionCompleted {
		existingJSON, marshalErr := marshalBounded(record.Receipt)
		if marshalErr == nil && bytes.Equal(existingJSON, receiptJSON) {
			if err := transaction.Commit(ctx); err != nil {
				return ports.ExecutionRecord{}, fmt.Errorf("commit idempotent execution completion: %w", err)
			}
			return record, nil
		}
		return ports.ExecutionRecord{}, model.NewError(model.CodeInvalidInput, "execution already completed with a different receipt")
	}
	if record.Status != ports.ExecutionReserved || record.LeaseToken != leaseToken {
		return ports.ExecutionRecord{}, model.NewError(model.CodeReplayedGrant, "execution lease is no longer owned by this caller")
	}
	if err := validateReceiptForGrant(receipt, record.Grant); err != nil {
		return ports.ExecutionRecord{}, err
	}

	var completed ports.ExecutionRecord
	var completedFingerprint []byte
	err = scanExecution(transaction.QueryRow(ctx, `
UPDATE aegis_execution_ledger
SET status = 'completed', receipt_id = $4, receipt_json = $5,
    completed_at = $6, lease_owner = NULL, lease_token = NULL,
    lease_until = NULL, safe_error_code = NULL,
    retention_until = GREATEST($6::timestamptz, CURRENT_TIMESTAMP) + ($7 * INTERVAL '1 second'),
    version = version + 1
WHERE scope = $1 AND grant_id = $2 AND status = 'reserved' AND lease_token = $3
RETURNING `+executionColumns,
		string(scope), grantID, leaseToken, receipt.ReceiptID, receiptJSON, receipt.CompletedAt.UTC(),
		leaseSeconds(s.retention),
	), &completed, &completedFingerprint)
	if noRows(err) {
		return ports.ExecutionRecord{}, model.NewError(model.CodeReplayedGrant, "execution lease changed before completion")
	}
	if err != nil {
		return ports.ExecutionRecord{}, fmt.Errorf("complete execution: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return ports.ExecutionRecord{}, fmt.Errorf("commit execution completion: %w", err)
	}
	return completed, nil
}

func (s *ExecutionLedger) MarkExecutionUncertain(
	ctx context.Context,
	scope ports.ExecutionScope,
	grantID, leaseToken string,
	code model.ErrorCode,
) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("postgres execution ledger is unavailable")
	}
	if !scope.Valid() || grantID == "" || leaseToken == "" || !validSafeCode(code) {
		return model.NewError(model.CodeInvalidInput, "uncertain execution update is invalid")
	}
	command, err := s.db.Exec(ctx, `
UPDATE aegis_execution_ledger
SET status = 'uncertain', safe_error_code = $4, completed_at = CURRENT_TIMESTAMP,
    lease_owner = NULL, lease_token = NULL, lease_until = NULL,
    retention_until = CURRENT_TIMESTAMP + ($5 * INTERVAL '1 second'),
    version = version + 1
WHERE scope = $1 AND grant_id = $2 AND status = 'reserved' AND lease_token = $3`,
		string(scope), grantID, leaseToken, string(code), leaseSeconds(s.retention),
	)
	if err != nil {
		return fmt.Errorf("mark execution uncertain: %w", err)
	}
	if command.RowsAffected() != 1 {
		return model.NewError(model.CodeReplayedGrant, "execution lease changed before it was marked uncertain")
	}
	return nil
}

func (s *ExecutionLedger) PurgeExecutions(ctx context.Context, before time.Time, limit int) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("postgres execution ledger is unavailable")
	}
	if before.IsZero() {
		return 0, model.NewError(model.CodeInvalidInput, "execution purge cutoff is required")
	}
	if err := validateBatch(limit); err != nil {
		return 0, err
	}
	// Candidate discovery takes no row lock. Each grant advisory lock is then
	// acquired before its ledger rows, matching report acceptance and execution
	// reservation order across concurrent cleanup workers.
	ledgerTx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin execution retention purge: %w", err)
	}
	defer func() { _ = ledgerTx.Rollback(ctx) }()
	grantRows, err := ledgerTx.Query(ctx, `
SELECT DISTINCT grant_id
FROM aegis_execution_ledger
WHERE status IN ('completed', 'uncertain')
  AND retention_until < LEAST($1::timestamptz, CURRENT_TIMESTAMP)
  AND (status = 'uncertain' OR reported_at IS NOT NULL)
ORDER BY grant_id
LIMIT $2`, before.UTC(), limit)
	if err != nil {
		return 0, fmt.Errorf("select retained terminal execution grants: %w", err)
	}
	grantIDs := make([]string, 0, limit)
	for grantRows.Next() {
		var grantID string
		if err := grantRows.Scan(&grantID); err != nil {
			grantRows.Close()
			return 0, fmt.Errorf("scan retained terminal execution grant: %w", err)
		}
		grantIDs = append(grantIDs, grantID)
	}
	if err := grantRows.Err(); err != nil {
		grantRows.Close()
		return 0, fmt.Errorf("read retained terminal execution grants: %w", err)
	}
	grantRows.Close()
	var purged int64
	for _, grantID := range grantIDs {
		if purged >= int64(limit) {
			break
		}
		if err := lockExecutionKey(ctx, ledgerTx, ports.ExecutionScopeOperator, grantID); err != nil {
			return 0, err
		}
		command, err := ledgerTx.Exec(ctx, `
WITH expired AS (
    SELECT ctid
    FROM aegis_execution_ledger
    WHERE grant_id = $1
	  AND status IN ('completed', 'uncertain')
	  AND retention_until < LEAST($2::timestamptz, CURRENT_TIMESTAMP)
      AND (status = 'uncertain' OR reported_at IS NOT NULL)
    ORDER BY CASE scope WHEN 'operator' THEN 0 ELSE 1 END, retention_until
    LIMIT $3
    FOR UPDATE
)
DELETE FROM aegis_execution_ledger ledger
USING expired
WHERE ledger.ctid = expired.ctid`, grantID, before.UTC(), int64(limit)-purged)
		if err != nil {
			return 0, fmt.Errorf("purge retained terminal execution: %w", err)
		}
		purged += command.RowsAffected()
	}
	if err := ledgerTx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit execution retention purge: %w", err)
	}
	remaining := int64(limit) - purged
	if remaining <= 0 {
		return purged, nil
	}

	// Fence cleanup runs in a separate transaction after ledger row locks have
	// been released. Report acceptance always takes the grant advisory lock
	// before ledger row locks; mixing that order here would create a deadlock.
	transaction, err := s.db.Begin(ctx)
	if err != nil {
		return purged, fmt.Errorf("begin execution fence retention purge: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	var fencePurged int64
	{
		rows, err := transaction.Query(ctx, `
SELECT DISTINCT grant_id
FROM aegis_execution_report_fences
WHERE retention_until < LEAST($1::timestamptz, CURRENT_TIMESTAMP)
ORDER BY grant_id
LIMIT $2`, before.UTC(), remaining)
		if err != nil {
			return purged, fmt.Errorf("select expired execution report fences: %w", err)
		}
		keys := make([]string, 0, remaining)
		for rows.Next() {
			var grantID string
			if err := rows.Scan(&grantID); err != nil {
				rows.Close()
				return purged, fmt.Errorf("scan expired execution report fence: %w", err)
			}
			keys = append(keys, grantID)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return purged, fmt.Errorf("read expired execution report fences: %w", err)
		}
		rows.Close()
		for _, grantID := range keys {
			if purged+fencePurged >= int64(limit) {
				break
			}
			// Fence deletion uses the exact lock taken by reservation and report
			// acceptance, so an old grant can never slip between a fence check and
			// its removal. The retention horizon is also later than grant expiry.
			if err := lockExecutionKey(ctx, transaction, ports.ExecutionScopeOperator, grantID); err != nil {
				return purged, err
			}
			deleted, err := transaction.Exec(ctx, `
WITH expired AS (
    SELECT ctid
    FROM aegis_execution_report_fences
	WHERE grant_id = $1
	  AND retention_until < LEAST($2::timestamptz, CURRENT_TIMESTAMP)
    ORDER BY CASE scope WHEN 'operator' THEN 0 ELSE 1 END
    LIMIT $3
    FOR UPDATE
)
DELETE FROM aegis_execution_report_fences fence
USING expired
WHERE fence.ctid = expired.ctid`, grantID, before.UTC(), int64(limit)-purged-fencePurged,
			)
			if err != nil {
				return purged, fmt.Errorf("purge execution report fence: %w", err)
			}
			fencePurged += deleted.RowsAffected()
		}
	}
	if err := transaction.Commit(ctx); err != nil {
		return purged, fmt.Errorf("commit execution fence retention purge: %w", err)
	}
	return purged + fencePurged, nil
}

const executionColumns = `
scope, grant_json, signed_fingerprint, status,
lease_owner, lease_token, lease_until, receipt_json, safe_error_code,
started_at, completed_at, reported_at, retention_until, version`

type rowScanner interface {
	Scan(...any) error
}

func getExecutionForUpdate(
	ctx context.Context,
	transaction pgx.Tx,
	scope ports.ExecutionScope,
	grantID string,
) (ports.ExecutionRecord, []byte, error) {
	var record ports.ExecutionRecord
	var fingerprint []byte
	err := scanExecution(transaction.QueryRow(ctx,
		"SELECT "+executionColumns+" FROM aegis_execution_ledger WHERE scope = $1 AND grant_id = $2 FOR UPDATE",
		string(scope), grantID,
	), &record, &fingerprint)
	return record, fingerprint, err
}

// lockExecutionKey serializes creation, takeover, terminal reporting, and
// fence retention across both durable execution scopes for one grant. Scope
// remains an argument so callers cannot accidentally lock an invalid ledger
// namespace, but is intentionally not part of the advisory key: a terminal
// report must close the Operator and action-MCP races as one grant-level unit.
func lockExecutionKey(ctx context.Context, transaction pgx.Tx, scope ports.ExecutionScope, grantID string) error {
	if !scope.Valid() || grantID == "" {
		return model.NewError(model.CodeInvalidInput, "execution lock scope and grant ID are required")
	}
	if _, err := transaction.Exec(
		ctx,
		"SELECT pg_advisory_xact_lock(hashtext('aegissre-execution-grant'), hashtext($1))",
		grantID,
	); err != nil {
		return fmt.Errorf("lock durable execution key: %w", err)
	}
	return nil
}

func executionKeyFenced(
	ctx context.Context,
	transaction pgx.Tx,
	scope ports.ExecutionScope,
	grantID string,
) (bool, error) {
	var fenced bool
	if err := transaction.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1 FROM aegis_execution_report_fences
    WHERE scope = $1 AND grant_id = $2
)`, string(scope), grantID).Scan(&fenced); err != nil {
		return false, fmt.Errorf("check durable execution report fence: %w", err)
	}
	return fenced, nil
}

func scanExecution(row rowScanner, record *ports.ExecutionRecord, fingerprint *[]byte) error {
	var (
		scope, status           string
		grantJSON, receiptJSON  []byte
		leaseOwner, leaseToken  *string
		leaseUntil              *time.Time
		errorCode               *string
		completedAt, reportedAt *time.Time
	)
	if err := row.Scan(
		&scope, &grantJSON, fingerprint, &status,
		&leaseOwner, &leaseToken, &leaseUntil, &receiptJSON, &errorCode,
		&record.StartedAt, &completedAt, &reportedAt, &record.RetentionUntil, &record.Version,
	); err != nil {
		return err
	}
	if err := json.Unmarshal(grantJSON, &record.Grant); err != nil {
		return fmt.Errorf("decode stored delegation grant: %w", err)
	}
	if err := record.Grant.ValidateSigned(); err != nil {
		return fmt.Errorf("validate stored delegation grant: %w", err)
	}
	record.Scope = ports.ExecutionScope(scope)
	record.Status = ports.ExecutionStatus(status)
	if !record.Scope.Valid() || !record.Status.Valid() || len(*fingerprint) != 32 {
		return fmt.Errorf("stored execution ledger row is invalid")
	}
	if leaseOwner != nil {
		record.LeaseOwner = *leaseOwner
	}
	if leaseToken != nil {
		record.LeaseToken = *leaseToken
	}
	if leaseUntil != nil {
		record.LeaseUntil = leaseUntil.UTC()
	}
	if errorCode != nil {
		record.ErrorCode = model.ErrorCode(*errorCode)
	}
	if completedAt != nil {
		value := completedAt.UTC()
		record.CompletedAt = &value
	}
	if reportedAt != nil {
		value := reportedAt.UTC()
		record.ReportedAt = &value
	}
	if len(receiptJSON) != 0 {
		var receipt model.ActionReceipt
		if err := json.Unmarshal(receiptJSON, &receipt); err != nil {
			return fmt.Errorf("decode stored action receipt: %w", err)
		}
		if err := receipt.Validate(); err != nil {
			return fmt.Errorf("validate stored action receipt: %w", err)
		}
		record.Receipt = &receipt
	}
	record.StartedAt = record.StartedAt.UTC()
	record.RetentionUntil = record.RetentionUntil.UTC()
	return nil
}

func validateReceiptForGrant(receipt model.ActionReceipt, grant model.DelegationGrant) error {
	if receipt.GrantID != grant.GrantID || receipt.IncidentID != grant.IncidentID || !receipt.Action.Equal(grant.Action) {
		return model.NewError(model.CodeInvalidInput, "action receipt does not match its durable delegation grant")
	}
	if receipt.Outcome != model.ActionRejected && (receipt.DryRun != grant.DryRun ||
		(grant.DryRun && receipt.Outcome != model.ActionDryRun) ||
		(!grant.DryRun && receipt.Outcome == model.ActionDryRun)) {
		return model.NewError(model.CodeInvalidInput, "action receipt dry-run semantics differ from its durable delegation grant")
	}
	return nil
}

func sameFingerprint(left, right []byte) bool {
	return len(left) == 32 && len(right) == 32 && subtle.ConstantTimeCompare(left, right) == 1
}

func leaseSeconds(duration time.Duration) int64 {
	seconds := int64(duration / time.Second)
	if duration%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		return 1
	}
	return seconds
}
