package postgres

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
)

type ReportOutbox struct {
	db DB
}

var _ ports.ReportOutboxStore = (*ReportOutbox)(nil)

func NewReportOutbox(db DB) (*ReportOutbox, error) {
	if db == nil {
		return nil, fmt.Errorf("postgres report outbox database is required")
	}
	return &ReportOutbox{db: db}, nil
}

// AcceptReport validates all request/report bindings, then inserts the signed
// request, sealed report, and optional notification intent in the same
// database transaction. It performs no network I/O.
func (s *ReportOutbox) AcceptReport(
	ctx context.Context,
	request model.IncidentReportRequest,
	report model.IncidentReport,
	intent *ports.ReportNotificationIntent,
) (ports.StoredReport, error) {
	if s == nil || s.db == nil {
		return ports.StoredReport{}, fmt.Errorf("postgres report outbox is unavailable")
	}
	if intent != nil && (intent.Channel != model.NotificationChannelWhatsApp || intent.AvailableAt.IsZero()) {
		return ports.StoredReport{}, model.NewError(model.CodeInvalidInput, "notification intent is invalid")
	}
	if err := validateReportBinding(request, report); err != nil {
		return ports.StoredReport{}, err
	}
	fingerprint, err := signedReportFingerprint(request)
	if err != nil {
		return ports.StoredReport{}, err
	}
	requestDigest, err := request.ComputeDigest()
	if err != nil {
		return ports.StoredReport{}, err
	}
	requestJSON, err := marshalBounded(request)
	if err != nil {
		return ports.StoredReport{}, err
	}
	reportJSON, err := marshalBounded(report)
	if err != nil {
		return ports.StoredReport{}, err
	}

	transaction, err := s.db.Begin(ctx)
	if err != nil {
		return ports.StoredReport{}, fmt.Errorf("begin report acceptance: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if request.GrantID != "" {
		// ReserveExecution takes the same per-scope locks. Holding both in a
		// fixed order closes the missing-row race in which a terminal report
		// could otherwise commit immediately before a late action request.
		if err := lockExecutionKey(ctx, transaction, ports.ExecutionScopeOperator, request.GrantID); err != nil {
			return ports.StoredReport{}, err
		}
	}

	command, err := transaction.Exec(ctx, `
INSERT INTO aegis_incident_reports (
    request_id, signed_fingerprint, request_digest, report_id, incident_id,
    request_json, report_json, notification_requested
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT DO NOTHING`,
		request.RequestID, fingerprint[:], requestDigest, report.ReportID, request.IncidentID,
		requestJSON, reportJSON, intent != nil,
	)
	if err != nil {
		return ports.StoredReport{}, fmt.Errorf("insert durable incident report: %w", err)
	}
	if command.RowsAffected() == 0 {
		existing, _, _, err := getReportForUpdate(ctx, transaction, request.RequestID)
		if noRows(err) {
			var existingRequestID string
			err = transaction.QueryRow(ctx,
				"SELECT request_id FROM aegis_incident_reports WHERE incident_id = $1 FOR UPDATE",
				request.IncidentID,
			).Scan(&existingRequestID)
			if err != nil {
				return ports.StoredReport{}, fmt.Errorf("locate conflicting terminal incident report: %w", err)
			}
			return ports.StoredReport{}, model.NewError(model.CodeInvalidInput, "incident already has a different terminal report request")
		}
		if err != nil {
			return ports.StoredReport{}, err
		}
		if !sameReportRequestSemantics(existing.Request, request) ||
			existing.Report.ReportID != report.ReportID || existing.Report.Digest != report.Digest ||
			existing.HasNotificationIntent != (intent != nil) {
			return ports.StoredReport{}, model.NewError(model.CodeInvalidInput, "incident report request ID was reused with different semantic contents")
		}
		existing.Created = false
		if err := transaction.Commit(ctx); err != nil {
			return ports.StoredReport{}, fmt.Errorf("commit duplicate report lookup: %w", err)
		}
		return existing, nil
	}

	if request.GrantID != "" {
		if err := bindReportToExecution(ctx, transaction, request, report); err != nil {
			return ports.StoredReport{}, err
		}
	}
	if intent != nil {
		if _, err := transaction.Exec(ctx, `
INSERT INTO aegis_notification_outbox (
    report_id, channel, idempotency_key, report_json, status, available_at
) VALUES ($1, $2, $3, $4, 'pending', $5)`,
			report.ReportID, string(intent.Channel), request.RequestID,
			reportJSON, intent.AvailableAt.UTC(),
		); err != nil {
			return ports.StoredReport{}, fmt.Errorf("enqueue incident report notification: %w", err)
		}
	}

	stored, _, _, err := getReportForUpdate(ctx, transaction, request.RequestID)
	if err != nil {
		return ports.StoredReport{}, err
	}
	stored.Created = true
	if err := transaction.Commit(ctx); err != nil {
		return ports.StoredReport{}, fmt.Errorf("commit incident report acceptance: %w", err)
	}
	return stored, nil
}

func sameReportRequestSemantics(left, right model.IncidentReportRequest) bool {
	return left.SchemaVersion == right.SchemaVersion && left.RequestID == right.RequestID &&
		left.Issuer == right.Issuer && left.Audience == right.Audience &&
		left.IncidentID == right.IncidentID && left.CorrelationID == right.CorrelationID &&
		left.DiagnosisReportID == right.DiagnosisReportID && left.GrantID == right.GrantID &&
		left.ReceiptID == right.ReceiptID && left.Target.Equal(right.Target) &&
		left.FinalState == right.FinalState && left.Reason == right.Reason &&
		left.ReportCreatedAt.Equal(right.ReportCreatedAt)
}

func (s *ReportOutbox) GetReport(ctx context.Context, requestID string) (ports.StoredReport, bool, error) {
	if s == nil || s.db == nil {
		return ports.StoredReport{}, false, fmt.Errorf("postgres report outbox is unavailable")
	}
	if requestID == "" {
		return ports.StoredReport{}, false, model.NewError(model.CodeInvalidInput, "incident report request ID is required")
	}
	var record ports.StoredReport
	var fingerprint []byte
	var digest string
	err := scanReport(s.db.QueryRow(ctx, `
SELECT reports.request_json, reports.report_json, reports.signed_fingerprint,
       reports.request_digest, reports.created_at, reports.updated_at,
       reports.notification_requested
FROM aegis_incident_reports reports WHERE reports.request_id = $1`, requestID), &record, &fingerprint, &digest)
	if noRows(err) {
		return ports.StoredReport{}, false, nil
	}
	if err != nil {
		return ports.StoredReport{}, false, fmt.Errorf("get durable incident report: %w", err)
	}
	return record, true, nil
}

func (s *ReportOutbox) ClaimOutbox(
	ctx context.Context,
	owner string,
	limit int,
	lease time.Duration,
) ([]ports.OutboxMessage, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("postgres report outbox is unavailable")
	}
	if err := validateOwner(owner); err != nil {
		return nil, err
	}
	if err := validateBatch(limit); err != nil {
		return nil, err
	}
	if err := validateLease(lease); err != nil {
		return nil, err
	}
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `
WITH due AS (
    SELECT id
    FROM aegis_notification_outbox
    WHERE (status IN ('pending', 'retry_wait') AND available_at <= CURRENT_TIMESTAMP)
       OR (status = 'sending' AND lease_until <= CURRENT_TIMESTAMP)
    ORDER BY COALESCE(lease_until, available_at), id
    LIMIT $1
    FOR UPDATE SKIP LOCKED
)
UPDATE aegis_notification_outbox outbox
SET status = 'sending', attempts = attempts + 1,
    lease_owner = $2, lease_token = $3,
    lease_until = CURRENT_TIMESTAMP + ($4 * INTERVAL '1 second'),
    updated_at = CURRENT_TIMESTAMP
FROM due
WHERE outbox.id = due.id
RETURNING `+outboxReturningColumns,
		limit, owner, token, leaseSeconds(lease),
	)
	if err != nil {
		return nil, fmt.Errorf("claim notification outbox: %w", err)
	}
	defer rows.Close()
	messages := make([]ports.OutboxMessage, 0, limit)
	for rows.Next() {
		var message ports.OutboxMessage
		if err := scanOutbox(rows, &message); err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read claimed notification outbox rows: %w", err)
	}
	return messages, nil
}

func (s *ReportOutbox) MarkOutboxDelivered(
	ctx context.Context,
	id int64,
	leaseToken, providerMessageID string,
	deliveredAt time.Time,
) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("postgres report outbox is unavailable")
	}
	delivery := model.NotificationDelivery{
		Channel: model.NotificationChannelWhatsApp, ProviderMessageID: providerMessageID,
	}
	if id < 1 || leaseToken == "" || deliveredAt.IsZero() {
		return model.NewError(model.CodeInvalidInput, "delivered outbox update is invalid")
	}
	if err := delivery.Validate(); err != nil {
		return err
	}
	command, err := s.db.Exec(ctx, `
UPDATE aegis_notification_outbox
SET status = 'delivered', provider_message_id = $3, delivered_at = $4,
    safe_error_code = NULL, lease_owner = NULL, lease_token = NULL,
    lease_until = NULL, updated_at = $4
WHERE id = $1 AND status = 'sending' AND lease_token = $2`,
		id, leaseToken, providerMessageID, deliveredAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("mark outbox message delivered: %w", err)
	}
	if command.RowsAffected() != 1 {
		return model.NewError(model.CodeReplayedGrant, "notification outbox lease changed before delivery was recorded")
	}
	return nil
}

func (s *ReportOutbox) RetryOutbox(
	ctx context.Context,
	id int64,
	leaseToken string,
	code model.ErrorCode,
	availableAt time.Time,
) error {
	if availableAt.IsZero() {
		return model.NewError(model.CodeInvalidInput, "notification retry time is required")
	}
	return s.finishOutboxAttempt(ctx, id, leaseToken, ports.OutboxRetryWait, code, availableAt)
}

func (s *ReportOutbox) DeadLetterOutbox(
	ctx context.Context,
	id int64,
	leaseToken string,
	code model.ErrorCode,
	at time.Time,
) error {
	if at.IsZero() {
		return model.NewError(model.CodeInvalidInput, "notification dead-letter time is required")
	}
	return s.finishOutboxAttempt(ctx, id, leaseToken, ports.OutboxDeadLetter, code, at)
}

func (s *ReportOutbox) finishOutboxAttempt(
	ctx context.Context,
	id int64,
	leaseToken string,
	status ports.OutboxStatus,
	code model.ErrorCode,
	at time.Time,
) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("postgres report outbox is unavailable")
	}
	if id < 1 || leaseToken == "" ||
		(status != ports.OutboxRetryWait && status != ports.OutboxDeadLetter) || !validSafeCode(code) {
		return model.NewError(model.CodeInvalidInput, "failed outbox attempt update is invalid")
	}
	command, err := s.db.Exec(ctx, `
UPDATE aegis_notification_outbox
SET status = $3, safe_error_code = $4, available_at = $5,
    lease_owner = NULL, lease_token = NULL, lease_until = NULL,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND status = 'sending' AND lease_token = $2`,
		id, leaseToken, string(status), string(code), at.UTC(),
	)
	if err != nil {
		return fmt.Errorf("finish notification outbox attempt: %w", err)
	}
	if command.RowsAffected() != 1 {
		return model.NewError(model.CodeReplayedGrant, "notification outbox lease changed before the attempt was recorded")
	}
	return nil
}

func (s *ReportOutbox) GetOutbox(ctx context.Context, reportID string) (ports.OutboxMessage, bool, error) {
	if s == nil || s.db == nil {
		return ports.OutboxMessage{}, false, fmt.Errorf("postgres report outbox is unavailable")
	}
	if reportID == "" {
		return ports.OutboxMessage{}, false, model.NewError(model.CodeInvalidInput, "incident report ID is required")
	}
	var message ports.OutboxMessage
	err := scanOutbox(s.db.QueryRow(ctx,
		"SELECT "+outboxColumns+" FROM aegis_notification_outbox WHERE report_id = $1", reportID,
	), &message)
	if noRows(err) {
		return ports.OutboxMessage{}, false, nil
	}
	if err != nil {
		return ports.OutboxMessage{}, false, fmt.Errorf("get notification outbox message: %w", err)
	}
	return message, true, nil
}

func (s *ReportOutbox) PurgeDeliveredOutbox(ctx context.Context, before time.Time, limit int) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("postgres report outbox is unavailable")
	}
	if before.IsZero() {
		return 0, model.NewError(model.CodeInvalidInput, "outbox purge cutoff is required")
	}
	if err := validateBatch(limit); err != nil {
		return 0, err
	}
	command, err := s.db.Exec(ctx, `
WITH expired AS (
    SELECT id
    FROM aegis_notification_outbox
    WHERE status = 'delivered' AND delivered_at < $1
    ORDER BY delivered_at, id
    LIMIT $2
    FOR UPDATE SKIP LOCKED
)
DELETE FROM aegis_notification_outbox outbox
USING expired
WHERE outbox.id = expired.id`, before.UTC(), limit)
	if err != nil {
		return 0, fmt.Errorf("purge delivered notification outbox rows: %w", err)
	}
	return command.RowsAffected(), nil
}

func validateReportBinding(request model.IncidentReportRequest, report model.IncidentReport) error {
	if err := request.ValidateSigned(); err != nil {
		return err
	}
	if err := report.VerifyDigest(); err != nil {
		return err
	}
	expectedReportID, err := request.DeterministicReportID()
	if err != nil {
		return err
	}
	if report.ReportID != expectedReportID || report.RequestID != request.RequestID ||
		report.IncidentID != request.IncidentID || report.CorrelationID != request.CorrelationID ||
		report.DiagnosisReportID != request.DiagnosisReportID || !report.Target.Equal(request.Target) ||
		report.FinalState != request.FinalState || report.Reason != request.Reason ||
		!report.CreatedAt.Equal(request.ReportCreatedAt) {
		return model.NewError(model.CodeInvalidInput, "incident report differs from its signed request")
	}
	if request.GrantID == "" {
		if report.Execution != nil {
			return model.NewError(model.CodeInvalidInput, "receipt-free report request cannot contain execution evidence")
		}
		return nil
	}
	if request.ReceiptID == "" {
		if report.Execution != nil {
			return model.NewError(model.CodeInvalidInput, "grant-only report request cannot contain execution evidence")
		}
		return nil
	}
	if report.Execution == nil || report.Execution.GrantID != request.GrantID || report.Execution.ReceiptID != request.ReceiptID {
		return model.NewError(model.CodeInvalidInput, "incident report execution differs from its signed receipt reference")
	}
	return nil
}

func bindReportToExecution(
	ctx context.Context,
	transaction pgx.Tx,
	request model.IncidentReportRequest,
	report model.IncidentReport,
) error {
	type executionEvidence struct {
		record      ports.ExecutionRecord
		fingerprint []byte
	}
	var records = make(map[ports.ExecutionScope]executionEvidence, 2)
	for _, scope := range []ports.ExecutionScope{ports.ExecutionScopeOperator, ports.ExecutionScopeMCPAction} {
		record, fingerprint, err := getExecutionForUpdate(ctx, transaction, scope, request.GrantID)
		if err != nil && !noRows(err) {
			return err
		}
		if err == nil {
			if err := validateExecutionReportGrant(record.Grant, request); err != nil {
				return err
			}
			records[scope] = executionEvidence{record: record, fingerprint: fingerprint}
		}
	}

	operatorEvidence, operatorFound := records[ports.ExecutionScopeOperator]
	actionEvidence, actionFound := records[ports.ExecutionScopeMCPAction]
	if actionFound && !operatorFound {
		return model.NewError(model.CodeInvalidInput, "action-MCP execution exists without its required Operator execution")
	}
	if operatorFound && actionFound && !sameFingerprint(operatorEvidence.fingerprint, actionEvidence.fingerprint) {
		return model.NewError(model.CodeInvalidInput, "Operator and action-MCP executions do not share the exact signed grant")
	}
	if request.ReceiptID != "" {
		if !operatorFound || operatorEvidence.record.Status != ports.ExecutionCompleted ||
			operatorEvidence.record.Receipt == nil || report.Execution == nil {
			return model.NewError(model.CodeInvalidInput, "incident report references an incomplete Operator execution")
		}
		receipt := operatorEvidence.record.Receipt
		execution := report.Execution
		if receipt.ReceiptID != request.ReceiptID || receipt.IncidentID != request.IncidentID ||
			execution.GrantID != receipt.GrantID || execution.ReceiptID != receipt.ReceiptID ||
			!execution.Action.Equal(receipt.Action) || execution.Outcome != receipt.Outcome ||
			execution.DryRun != receipt.DryRun || !execution.CompletedAt.Equal(receipt.CompletedAt) {
			return model.NewError(model.CodeInvalidInput, "incident report does not exactly project the durable action receipt")
		}
		if actionFound {
			if actionEvidence.record.Status != ports.ExecutionCompleted || actionEvidence.record.Receipt == nil {
				return model.NewError(model.CodeExecutionPending, "action-MCP durable outcome is not complete for a receipt-backed report")
			}
			operatorReceiptJSON, operatorErr := marshalBounded(receipt)
			actionReceiptJSON, actionErr := marshalBounded(actionEvidence.record.Receipt)
			if operatorErr != nil || actionErr != nil || subtle.ConstantTimeCompare(operatorReceiptJSON, actionReceiptJSON) != 1 {
				return model.NewError(model.CodeInvalidInput, "Operator receipt differs from action-MCP durable truth")
			}
		} else if receipt.Outcome != model.ActionRejected {
			return model.NewError(model.CodeInvalidInput, "receipt-backed report lacks action-MCP durable truth")
		}
	}

	// A live reservation may still be executing outside PostgreSQL. Reporting
	// it as terminal would race that owner, so the entire report transaction is
	// retried. Once DB time says the lease expired, uncertainty is the only safe
	// terminal classification.
	for _, scope := range []ports.ExecutionScope{ports.ExecutionScopeOperator, ports.ExecutionScopeMCPAction} {
		evidence, found := records[scope]
		if !found || evidence.record.Status != ports.ExecutionReserved {
			continue
		}
		if request.ReceiptID != "" {
			return model.NewError(model.CodeExecutionPending, "receipt-backed report is waiting for action-MCP reconciliation")
		}
		command, err := transaction.Exec(ctx, `
UPDATE aegis_execution_ledger
SET status = 'uncertain', safe_error_code = $3, completed_at = CURRENT_TIMESTAMP,
    lease_owner = NULL, lease_token = NULL, lease_until = NULL,
    retention_until = CURRENT_TIMESTAMP + ($4 * INTERVAL '1 second'),
	    reported_at = CURRENT_TIMESTAMP,
    version = version + 1
WHERE scope = $1 AND grant_id = $2 AND status = 'reserved'
  AND lease_until <= CURRENT_TIMESTAMP`,
			string(scope), request.GrantID, string(model.CodeExecutionFailed), leaseSeconds(defaultRetention),
		)
		if err != nil {
			return fmt.Errorf("terminalize expired %s execution for report: %w", scope, err)
		}
		if command.RowsAffected() != 1 {
			return model.NewError(model.CodeExecutionPending, "durable execution is still live while terminal reporting is pending")
		}
	}

	for scope, evidence := range records {
		if evidence.record.Status == ports.ExecutionReserved {
			continue
		}
		command, err := transaction.Exec(ctx, `
UPDATE aegis_execution_ledger
SET reported_at = COALESCE(reported_at, CURRENT_TIMESTAMP), version = version + 1
	WHERE scope = $1 AND grant_id = $2 AND status IN ('completed', 'uncertain')`, string(scope), request.GrantID)
		if err != nil {
			return fmt.Errorf("mark %s execution reported: %w", scope, err)
		}
		if command.RowsAffected() != 1 {
			return model.NewError(model.CodeInvalidInput, "durable execution changed before report acceptance")
		}
	}

	for _, scope := range []ports.ExecutionScope{ports.ExecutionScopeOperator, ports.ExecutionScopeMCPAction} {
		if err := installExecutionReportFence(ctx, transaction, scope, request); err != nil {
			return err
		}
	}
	return nil
}

func validateExecutionReportGrant(grant model.DelegationGrant, request model.IncidentReportRequest) error {
	if grant.GrantID != request.GrantID || grant.IncidentID != request.IncidentID ||
		grant.DiagnosisReportID != request.DiagnosisReportID || !grant.Action.Target.Equal(request.Target) {
		return model.NewError(model.CodeInvalidInput, "terminal report does not match the durable execution grant")
	}
	return nil
}

func installExecutionReportFence(
	ctx context.Context,
	transaction pgx.Tx,
	scope ports.ExecutionScope,
	request model.IncidentReportRequest,
) error {
	targetJSON, err := json.Marshal(request.Target)
	if err != nil {
		return fmt.Errorf("marshal execution report fence target: %w", err)
	}
	if len(targetJSON) == 0 || len(targetJSON) > 16<<10 {
		return model.NewError(model.CodeInvalidInput, "execution report fence target exceeds its size limit")
	}
	command, err := transaction.Exec(ctx, `
INSERT INTO aegis_execution_report_fences (
    scope, grant_id, incident_id, diagnosis_report_id, target_json,
    report_request_id, retention_until
) VALUES (
    $1, $2, $3, $4, $5, $6,
    GREATEST($7::timestamptz, CURRENT_TIMESTAMP) + ($8 * INTERVAL '1 second')
)
ON CONFLICT DO NOTHING`,
		string(scope), request.GrantID, request.IncidentID, request.DiagnosisReportID,
		targetJSON, request.RequestID, request.ExpiresAt.UTC(), leaseSeconds(defaultRetention),
	)
	if err != nil {
		return fmt.Errorf("install %s terminal execution fence: %w", scope, err)
	}
	if command.RowsAffected() == 1 {
		return nil
	}
	var incidentID, diagnosisID, reportRequestID string
	var storedTargetJSON []byte
	if err := transaction.QueryRow(ctx, `
SELECT incident_id, diagnosis_report_id, target_json, report_request_id
FROM aegis_execution_report_fences
WHERE scope = $1 AND grant_id = $2
FOR UPDATE`, string(scope), request.GrantID).Scan(
		&incidentID, &diagnosisID, &storedTargetJSON, &reportRequestID,
	); err != nil {
		if noRows(err) {
			return model.NewError(model.CodeInvalidInput, "incident report fence conflicts with another grant")
		}
		return fmt.Errorf("load existing %s terminal execution fence: %w", scope, err)
	}
	var target model.ResourceTarget
	if err := json.Unmarshal(storedTargetJSON, &target); err != nil {
		return fmt.Errorf("decode stored terminal execution fence target: %w", err)
	}
	if incidentID != request.IncidentID || diagnosisID != request.DiagnosisReportID ||
		reportRequestID != request.RequestID || !target.Equal(request.Target) {
		return model.NewError(model.CodeInvalidInput, "terminal execution fence conflicts with the signed incident report")
	}
	return nil
}

func getReportForUpdate(
	ctx context.Context,
	transaction pgx.Tx,
	requestID string,
) (ports.StoredReport, []byte, string, error) {
	var record ports.StoredReport
	var fingerprint []byte
	var digest string
	err := scanReport(transaction.QueryRow(ctx, `
SELECT reports.request_json, reports.report_json, reports.signed_fingerprint,
       reports.request_digest, reports.created_at, reports.updated_at,
       reports.notification_requested
FROM aegis_incident_reports reports
WHERE reports.request_id = $1
FOR UPDATE OF reports`, requestID), &record, &fingerprint, &digest)
	return record, fingerprint, digest, err
}

func scanReport(row rowScanner, record *ports.StoredReport, fingerprint *[]byte, digest *string) error {
	var requestJSON, reportJSON []byte
	if err := row.Scan(
		&requestJSON, &reportJSON, fingerprint, digest, &record.CreatedAt,
		&record.UpdatedAt, &record.HasNotificationIntent,
	); err != nil {
		return err
	}
	if len(*fingerprint) != 32 || len(*digest) != 64 {
		return fmt.Errorf("stored incident report authorization metadata is invalid")
	}
	if err := json.Unmarshal(requestJSON, &record.Request); err != nil {
		return fmt.Errorf("decode stored incident report request: %w", err)
	}
	if err := json.Unmarshal(reportJSON, &record.Report); err != nil {
		return fmt.Errorf("decode stored incident report: %w", err)
	}
	if err := validateReportBinding(record.Request, record.Report); err != nil {
		return fmt.Errorf("validate stored incident report: %w", err)
	}
	fingerprintExpected, err := signedReportFingerprint(record.Request)
	if err != nil || subtle.ConstantTimeCompare(*fingerprint, fingerprintExpected[:]) != 1 {
		return fmt.Errorf("stored incident report signed fingerprint is invalid")
	}
	digestExpected, err := record.Request.ComputeDigest()
	if err != nil || digestExpected != *digest {
		return fmt.Errorf("stored incident report request digest is invalid")
	}
	record.CreatedAt = record.CreatedAt.UTC()
	record.UpdatedAt = record.UpdatedAt.UTC()
	return nil
}

const outboxColumns = `
id, report_json, channel, idempotency_key, status, attempts, available_at,
lease_owner, lease_token, lease_until, provider_message_id, safe_error_code,
created_at, updated_at, delivered_at`

const outboxReturningColumns = `
outbox.id, outbox.report_json, outbox.channel, outbox.idempotency_key,
outbox.status, outbox.attempts, outbox.available_at, outbox.lease_owner,
outbox.lease_token, outbox.lease_until, outbox.provider_message_id,
outbox.safe_error_code, outbox.created_at, outbox.updated_at,
outbox.delivered_at`

func scanOutbox(row rowScanner, message *ports.OutboxMessage) error {
	var (
		reportJSON                         []byte
		channel, status                    string
		leaseOwner, leaseToken, providerID *string
		errorCode                          *string
		leaseUntil, deliveredAt            *time.Time
	)
	if err := row.Scan(
		&message.ID, &reportJSON, &channel, &message.IdempotencyKey, &status,
		&message.Attempts, &message.AvailableAt, &leaseOwner, &leaseToken,
		&leaseUntil, &providerID, &errorCode, &message.CreatedAt,
		&message.UpdatedAt, &deliveredAt,
	); err != nil {
		return err
	}
	if err := json.Unmarshal(reportJSON, &message.Report); err != nil {
		return fmt.Errorf("decode outbox incident report: %w", err)
	}
	if err := message.Report.VerifyDigest(); err != nil {
		return fmt.Errorf("validate outbox incident report: %w", err)
	}
	message.Channel = model.NotificationChannel(channel)
	message.Status = ports.OutboxStatus(status)
	if message.ID < 1 || !message.Channel.Valid() || !message.Status.Valid() || message.Attempts < 0 {
		return fmt.Errorf("stored notification outbox row is invalid")
	}
	if leaseOwner != nil {
		message.LeaseOwner = *leaseOwner
	}
	if leaseToken != nil {
		message.LeaseToken = *leaseToken
	}
	if leaseUntil != nil {
		message.LeaseUntil = leaseUntil.UTC()
	}
	if providerID != nil {
		message.ProviderMessageID = *providerID
	}
	if errorCode != nil {
		message.LastErrorCode = model.ErrorCode(*errorCode)
	}
	if deliveredAt != nil {
		value := deliveredAt.UTC()
		message.DeliveredAt = &value
	}
	message.AvailableAt = message.AvailableAt.UTC()
	message.CreatedAt = message.CreatedAt.UTC()
	message.UpdatedAt = message.UpdatedAt.UTC()
	return nil
}
