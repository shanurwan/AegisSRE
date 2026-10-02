package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
	"github.com/shanurwan/AegisSRE/internal/security"
)

// TestPostgresDurableControlState uses an isolated schema in an explicitly
// configured test database. CI should provide AEGIS_TEST_DATABASE_URL.
func TestPostgresDurableControlState(t *testing.T) {
	databaseURL := os.Getenv("AEGIS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("AEGIS_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect test postgres admin pool: %v", err)
	}
	defer admin.Close()
	token, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	schema := "aegis_test_" + token[:16]
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatalf("create isolated test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE")
	})

	configuration, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse test postgres URL: %v", err)
	}
	configuration.ConnConfig.RuntimeParams["search_path"] = schema
	configuration.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, configuration)
	if err != nil {
		t.Fatalf("connect isolated test postgres pool: %v", err)
	}
	defer pool.Close()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate isolated test schema: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("repeat migration idempotently: %v", err)
	}
	if err := CheckSchema(ctx, pool); err != nil {
		t.Fatalf("check isolated test schema: %v", err)
	}
	requireSchemaRejection := func(reason, fragment string) {
		t.Helper()
		err := CheckSchema(ctx, pool)
		if err == nil {
			t.Fatalf("schema readiness accepted %s", reason)
		}
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("schema readiness rejected %s for the wrong reason: %v", reason, err)
		}
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO aegis_schema_migrations(version, checksum)
VALUES ('999999_unknown', $1)`, make([]byte, 32)); err != nil {
		t.Fatalf("insert unknown migration ledger version: %v", err)
	}
	requireSchemaRejection("an unknown migration ledger version", "unknown migration version")
	if _, err := pool.Exec(ctx, "DELETE FROM aegis_schema_migrations WHERE version = '999999_unknown'"); err != nil {
		t.Fatalf("remove unknown migration ledger version: %v", err)
	}

	if _, err := pool.Exec(ctx, "ALTER TABLE aegis_audit_events SET UNLOGGED"); err != nil {
		t.Fatalf("make managed table unlogged for schema contract test: %v", err)
	}
	requireSchemaRejection("an unlogged managed table", "ordinary permanent PostgreSQL table")
	if _, err := pool.Exec(ctx, "ALTER TABLE aegis_audit_events SET LOGGED"); err != nil {
		t.Fatalf("restore managed table persistence: %v", err)
	}
	if _, err := pool.Exec(ctx, "ALTER TABLE aegis_audit_events ENABLE ROW LEVEL SECURITY"); err != nil {
		t.Fatalf("enable row-level security for schema contract test: %v", err)
	}
	requireSchemaRejection("row-level security", "must not enable or force row-level security")
	if _, err := pool.Exec(ctx, "ALTER TABLE aegis_audit_events DISABLE ROW LEVEL SECURITY"); err != nil {
		t.Fatalf("disable row-level security after schema contract test: %v", err)
	}
	if _, err := pool.Exec(ctx, "ALTER TABLE aegis_audit_events FORCE ROW LEVEL SECURITY"); err != nil {
		t.Fatalf("force row-level security for schema contract test: %v", err)
	}
	requireSchemaRejection("forced row-level security", "must not enable or force row-level security")
	if _, err := pool.Exec(ctx, "ALTER TABLE aegis_audit_events NO FORCE ROW LEVEL SECURITY"); err != nil {
		t.Fatalf("remove forced row-level security after schema contract test: %v", err)
	}
	if _, err := pool.Exec(ctx, `
CREATE FUNCTION aegis_schema_contract_trigger() RETURNS trigger
LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';
CREATE TRIGGER aegis_schema_contract_user_trigger
BEFORE INSERT ON aegis_audit_events
FOR EACH ROW EXECUTE FUNCTION aegis_schema_contract_trigger()`); err != nil {
		t.Fatalf("create user trigger for schema contract test: %v", err)
	}
	requireSchemaRejection("a user-defined table trigger", "must not have user-defined triggers")
	if _, err := pool.Exec(ctx, `
DROP TRIGGER aegis_schema_contract_user_trigger ON aegis_audit_events;
DROP FUNCTION aegis_schema_contract_trigger()`); err != nil {
		t.Fatalf("remove user trigger after schema contract test: %v", err)
	}
	if _, err := pool.Exec(ctx, `
CREATE RULE aegis_schema_contract_drop_insert AS
ON INSERT TO aegis_audit_events DO INSTEAD NOTHING`); err != nil {
		t.Fatalf("create write-dropping rewrite rule for schema contract test: %v", err)
	}
	requireSchemaRejection("a write-dropping rewrite rule", "must not have rewrite rules")
	if _, err := pool.Exec(ctx, `
DROP RULE aegis_schema_contract_drop_insert ON aegis_audit_events`); err != nil {
		t.Fatalf("remove rewrite rule after schema contract test: %v", err)
	}
	// PostgreSQL keeps relhasrules set after the final DROP RULE until VACUUM
	// refreshes the catalog hint. The readiness contract intentionally remains
	// fail-closed until both signals are clean.
	if _, err := pool.Exec(ctx, "VACUUM aegis_audit_events"); err != nil {
		t.Fatalf("clear stale rewrite-rule catalog hint: %v", err)
	}
	if _, err := pool.Exec(ctx, `
CREATE UNIQUE INDEX aegis_schema_contract_shadow_unique
ON aegis_audit_events (incident_id, occurred_at)`); err != nil {
		t.Fatalf("create standalone unique index for schema contract test: %v", err)
	}
	requireSchemaRejection("an unexpected standalone unique index", "unexpected behavior-changing index")
	if _, err := pool.Exec(ctx, "DROP INDEX aegis_schema_contract_shadow_unique"); err != nil {
		t.Fatalf("remove standalone unique index after schema contract test: %v", err)
	}
	if _, err := pool.Exec(ctx, `
CREATE INDEX aegis_schema_contract_expression
ON aegis_audit_events ((actor::integer))`); err != nil {
		t.Fatalf("create expression index for schema contract test: %v", err)
	}
	requireSchemaRejection("an unexpected expression index", "unexpected behavior-changing index")
	if _, err := pool.Exec(ctx, "DROP INDEX aegis_schema_contract_expression"); err != nil {
		t.Fatalf("remove expression index after schema contract test: %v", err)
	}
	if _, err := pool.Exec(ctx, `
CREATE INDEX aegis_schema_contract_partial
ON aegis_audit_events (id) WHERE actor = 'operator'`); err != nil {
		t.Fatalf("create partial index for schema contract test: %v", err)
	}
	requireSchemaRejection("an unexpected partial index", "unexpected behavior-changing index")
	if _, err := pool.Exec(ctx, "DROP INDEX aegis_schema_contract_partial"); err != nil {
		t.Fatalf("remove partial index after schema contract test: %v", err)
	}
	if _, err := pool.Exec(ctx, `
ALTER TABLE aegis_audit_events
ADD CONSTRAINT aegis_schema_contract_exclusion
EXCLUDE USING gist (tstzrange(occurred_at, occurred_at, '[]') WITH &&)`); err != nil {
		t.Fatalf("create exclusion constraint for schema contract test: %v", err)
	}
	requireSchemaRejection("an unexpected exclusion constraint", "constraint set")
	if _, err := pool.Exec(ctx, `
ALTER TABLE aegis_audit_events
DROP CONSTRAINT aegis_schema_contract_exclusion`); err != nil {
		t.Fatalf("remove exclusion constraint after schema contract test: %v", err)
	}
	if _, err := pool.Exec(ctx, `
ALTER TABLE aegis_audit_events
ALTER COLUMN actor TYPE text COLLATE "C"`); err != nil {
		t.Fatalf("set explicit non-default column collation for schema contract test: %v", err)
	}
	requireSchemaRejection("a non-default text collation", "collation policy")
	if _, err := pool.Exec(ctx, `
ALTER TABLE aegis_audit_events
ALTER COLUMN actor TYPE text COLLATE "default"`); err != nil {
		t.Fatalf("restore default column collation after schema contract test: %v", err)
	}
	if _, err := pool.Exec(ctx, `
ALTER TABLE aegis_audit_events RENAME TO aegis_audit_events_contract_backup;
CREATE TABLE aegis_audit_events_contract_parent (occurred_at timestamptz NOT NULL)
PARTITION BY RANGE (occurred_at);
CREATE TABLE aegis_audit_events
PARTITION OF aegis_audit_events_contract_parent
FOR VALUES FROM (MINVALUE) TO (MAXVALUE)`); err != nil {
		t.Fatalf("replace managed table with partition leaf for schema contract test: %v", err)
	}
	requireSchemaRejection("a managed partition leaf", "ordinary permanent PostgreSQL table")
	if _, err := pool.Exec(ctx, `
DROP TABLE aegis_audit_events_contract_parent CASCADE;
ALTER TABLE aegis_audit_events_contract_backup RENAME TO aegis_audit_events`); err != nil {
		t.Fatalf("restore ordinary table after partition contract test: %v", err)
	}
	if err := CheckSchema(ctx, pool); err != nil {
		t.Fatalf("schema contract remained unhealthy after table-property restoration: %v", err)
	}
	if _, err := pool.Exec(ctx, `
ALTER TABLE aegis_monitor_checkpoints
ALTER COLUMN checkpoint_json DROP NOT NULL`); err != nil {
		t.Fatalf("weaken column nullability for schema contract test: %v", err)
	}
	if err := CheckSchema(ctx, pool); err == nil {
		t.Fatal("schema readiness accepted weakened column nullability")
	}
	if _, err := pool.Exec(ctx, `
ALTER TABLE aegis_monitor_checkpoints
ALTER COLUMN checkpoint_json SET NOT NULL`); err != nil {
		t.Fatalf("restore column nullability after schema contract test: %v", err)
	}
	if _, err := pool.Exec(ctx, "DROP INDEX aegis_monitor_lease_expiry_idx"); err != nil {
		t.Fatalf("drop required index for schema contract test: %v", err)
	}
	if err := CheckSchema(ctx, pool); err == nil {
		t.Fatal("schema readiness accepted a missing operational index")
	}
	if _, err := pool.Exec(ctx, `
CREATE INDEX aegis_monitor_lease_expiry_idx
ON aegis_monitor_leases (lease_until)`); err != nil {
		t.Fatalf("restore required index after schema contract test: %v", err)
	}
	if _, err := pool.Exec(ctx, `
ALTER TABLE aegis_monitor_checkpoints
DROP CONSTRAINT aegis_monitor_checkpoints_namespace_fkey`); err != nil {
		t.Fatalf("drop required foreign key for schema contract test: %v", err)
	}
	if err := CheckSchema(ctx, pool); err == nil {
		t.Fatal("schema readiness accepted a missing foreign key")
	}
	if _, err := pool.Exec(ctx, `
ALTER TABLE aegis_monitor_checkpoints
ADD CONSTRAINT aegis_monitor_checkpoints_namespace_fkey
FOREIGN KEY (namespace) REFERENCES aegis_monitor_leases(namespace) ON DELETE RESTRICT`); err != nil {
		t.Fatalf("restore required foreign key after schema contract test: %v", err)
	}
	if err := CheckSchema(ctx, pool); err != nil {
		t.Fatalf("schema contract remained unhealthy after restoration: %v", err)
	}
	monitorState, err := NewMonitorState(pool)
	if err != nil {
		t.Fatal(err)
	}
	monitorLeaseA, acquired, err := monitorState.AcquireMonitorLease(ctx, "outage-arena", "monitor-a", 30*time.Second)
	if err != nil || !acquired {
		t.Fatalf("acquire first Monitor lease: lease=%#v acquired=%v err=%v", monitorLeaseA, acquired, err)
	}
	if _, acquired, err := monitorState.AcquireMonitorLease(ctx, "outage-arena", "monitor-b", 30*time.Second); err != nil || acquired {
		t.Fatalf("concurrent Monitor acquired live lease: acquired=%v err=%v", acquired, err)
	}
	checkpointPayload := []byte(`{"schema_version":"test","tracker":{}}`)
	checkpoint, err := monitorState.SaveMonitorCheckpoint(ctx, monitorLeaseA, checkpointPayload)
	if err != nil || checkpoint.Version != 1 {
		t.Fatalf("save first Monitor checkpoint: checkpoint=%#v err=%v", checkpoint, err)
	}
	if _, err := pool.Exec(ctx, `
UPDATE aegis_monitor_leases SET lease_until = CURRENT_TIMESTAMP - interval '1 second'
WHERE namespace = $1`, "outage-arena"); err != nil {
		t.Fatalf("expire Monitor lease for takeover: %v", err)
	}
	monitorLeaseB, acquired, err := monitorState.AcquireMonitorLease(ctx, "outage-arena", "monitor-b", 30*time.Second)
	if err != nil || !acquired || monitorLeaseB.FencingToken <= monitorLeaseA.FencingToken {
		t.Fatalf("take over expired Monitor lease: lease=%#v acquired=%v err=%v", monitorLeaseB, acquired, err)
	}
	loadedCheckpoint, ok, err := monitorState.LoadMonitorCheckpoint(ctx, monitorLeaseB)
	if err != nil || !ok {
		t.Fatalf("load Monitor checkpoint after takeover: checkpoint=%#v ok=%v err=%v", loadedCheckpoint, ok, err)
	}
	var wantCheckpoint, gotCheckpoint any
	if decodeErr := json.Unmarshal(checkpointPayload, &wantCheckpoint); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if decodeErr := json.Unmarshal(loadedCheckpoint.Payload, &gotCheckpoint); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if !reflect.DeepEqual(gotCheckpoint, wantCheckpoint) {
		t.Fatalf("load Monitor checkpoint after takeover: checkpoint=%#v ok=%v err=%v", loadedCheckpoint, ok, err)
	}
	if _, err := monitorState.SaveMonitorCheckpoint(ctx, monitorLeaseA, checkpointPayload); err == nil {
		t.Fatal("stale Monitor leader overwrote checkpoint after fenced takeover")
	}

	ledger, err := NewExecutionLedger(pool, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = publicKey
	signer, err := security.NewSigner(privateKey, "postgres-test-key")
	if err != nil {
		t.Fatal(err)
	}
	grant := signedTestGrant(t, signer, now)

	operatorReservation, err := ledger.ReserveExecution(
		ctx, ports.ExecutionScopeOperator, grant, "operator-a", 30*time.Second,
	)
	if err != nil {
		t.Fatalf("reserve Operator execution: %v", err)
	}
	if !operatorReservation.Owner || operatorReservation.Status != ports.ExecutionReserved || operatorReservation.LeaseToken == "" {
		t.Fatalf("unexpected Operator reservation: %#v", operatorReservation)
	}
	duplicate, err := ledger.ReserveExecution(
		ctx, ports.ExecutionScopeOperator, grant, "operator-b", 30*time.Second,
	)
	if err != nil {
		t.Fatalf("read concurrent Operator reservation: %v", err)
	}
	if duplicate.Owner || duplicate.Status != ports.ExecutionReserved {
		t.Fatalf("live lease was concurrently acquired: %#v", duplicate)
	}
	if _, err := pool.Exec(ctx, `
UPDATE aegis_execution_ledger SET retention_until = $3
WHERE scope = $1 AND grant_id = $2`,
		string(ports.ExecutionScopeOperator), grant.GrantID, now.Add(-time.Hour),
	); err != nil {
		t.Fatalf("age Operator reservation retention for terminal reset test: %v", err)
	}

	receipt := model.ActionReceipt{
		SchemaVersion: model.SchemaVersionV1,
		ReceiptID:     "receipt-postgres-1",
		GrantID:       grant.GrantID,
		IncidentID:    grant.IncidentID,
		Action:        grant.Action,
		Outcome:       model.ActionDryRun,
		DryRun:        true,
		StartedAt:     now.Add(time.Second),
		CompletedAt:   now.Add(2 * time.Second),
		AuditRef:      "audit-postgres-action-1",
	}
	completed, err := ledger.CompleteExecution(
		ctx, ports.ExecutionScopeOperator, grant.GrantID, operatorReservation.LeaseToken, receipt,
	)
	if err != nil {
		t.Fatalf("complete Operator execution: %v", err)
	}
	if completed.Status != ports.ExecutionCompleted || completed.Receipt == nil || completed.Receipt.ReceiptID != receipt.ReceiptID {
		t.Fatalf("unexpected completed execution: %#v", completed)
	}
	if completed.RetentionUntil.Before(receipt.CompletedAt.Add(ledger.retention)) {
		t.Fatalf("completed execution retention was not reset from terminal time: retention=%s completed=%s", completed.RetentionUntil, receipt.CompletedAt)
	}
	byID, ok, err := ledger.GetExecutionByID(ctx, ports.ExecutionScopeOperator, grant.GrantID)
	if err != nil || !ok || byID.Owner || byID.Receipt == nil || byID.Receipt.ReceiptID != receipt.ReceiptID {
		t.Fatalf("trusted receipt lookup by ID failed: value=%#v ok=%v err=%v", byID, ok, err)
	}
	replayed, err := ledger.ReserveExecution(
		ctx, ports.ExecutionScopeOperator, grant, "operator-after-restart", 30*time.Second,
	)
	if err != nil {
		t.Fatalf("load completed execution after replay: %v", err)
	}
	if replayed.Owner || replayed.Status != ports.ExecutionCompleted || replayed.Receipt == nil || replayed.Receipt.ReceiptID != receipt.ReceiptID {
		t.Fatalf("completed replay did not return the durable receipt: %#v", replayed)
	}

	// The same grant is independently consumable by the MCP-action boundary.
	actionReservation, err := ledger.ReserveExecution(
		ctx, ports.ExecutionScopeMCPAction, grant, "mcp-action-a", 30*time.Second,
	)
	if err != nil {
		t.Fatalf("reserve MCP-action execution: %v", err)
	}
	if !actionReservation.Owner {
		t.Fatalf("Operator scope incorrectly consumed MCP-action scope: %#v", actionReservation)
	}
	if _, err := pool.Exec(ctx, `
UPDATE aegis_execution_ledger SET retention_until = $3
WHERE scope = $1 AND grant_id = $2`,
		string(ports.ExecutionScopeMCPAction), grant.GrantID, now.Add(-time.Hour),
	); err != nil {
		t.Fatalf("age MCP-action reservation retention for terminal reset test: %v", err)
	}
	uncertainTerminalStarted := time.Now().UTC()
	if err := ledger.MarkExecutionUncertain(
		ctx, ports.ExecutionScopeMCPAction, grant.GrantID,
		actionReservation.LeaseToken, model.CodeExecutionFailed,
	); err != nil {
		t.Fatalf("mark MCP-action execution uncertain: %v", err)
	}
	uncertain, ok, err := ledger.GetExecution(ctx, ports.ExecutionScopeMCPAction, grant)
	if err != nil || !ok {
		t.Fatalf("get uncertain MCP-action execution: ok=%v err=%v", ok, err)
	}
	if uncertain.Status != ports.ExecutionUncertain || uncertain.ErrorCode != model.CodeExecutionFailed {
		t.Fatalf("unexpected uncertain execution: %#v", uncertain)
	}
	if uncertain.RetentionUntil.Before(uncertainTerminalStarted.Add(ledger.retention)) {
		t.Fatalf("uncertain execution retention was not reset from terminal time: retention=%s terminal-start=%s", uncertain.RetentionUntil, uncertainTerminalStarted)
	}
	if _, err := pool.Exec(ctx, `
UPDATE aegis_execution_ledger SET retention_until = CURRENT_TIMESTAMP - interval '1 hour'
WHERE scope = $1 AND grant_id = $2`, string(ports.ExecutionScopeMCPAction), grant.GrantID); err != nil {
		t.Fatalf("age uncertain MCP-action execution for retention purge: %v", err)
	}

	concurrentGrant := grant
	concurrentGrant.GrantID = "grant-postgres-concurrent"
	concurrentGrant.IdempotencyKey = "action-postgres-concurrent"
	concurrentGrant.Signature = model.GrantSignature{}
	if err := signer.Sign(&concurrentGrant); err != nil {
		t.Fatal(err)
	}
	const contenders = 16
	reservations := make(chan ports.ExecutionRecord, contenders)
	errors := make(chan error, contenders)
	var wait sync.WaitGroup
	for index := 0; index < contenders; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			record, reserveErr := ledger.ReserveExecution(
				ctx, ports.ExecutionScopeOperator, concurrentGrant,
				"operator-contender-"+string(rune('a'+index)), 30*time.Second,
			)
			if reserveErr != nil {
				errors <- reserveErr
				return
			}
			reservations <- record
		}(index)
	}
	wait.Wait()
	close(reservations)
	close(errors)
	for reserveErr := range errors {
		t.Fatalf("concurrent execution reservation: %v", reserveErr)
	}
	owners := 0
	for reservation := range reservations {
		if reservation.Owner {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("concurrent reservation owners = %d, want exactly one", owners)
	}

	// A retention sweep may discard terminal uncertainty, but it must retain
	// an unreported Operator receipt and every active reservation even when the
	// supplied cutoff is beyond their retention timestamp.
	retentionCutoff := now.Add(48 * time.Hour)
	purgedExecutions, err := ledger.PurgeExecutions(ctx, retentionCutoff, 10)
	if err != nil {
		t.Fatalf("purge terminal execution retention: %v", err)
	}
	if purgedExecutions != 1 {
		t.Fatalf("purged execution rows = %d, want only the uncertain row", purgedExecutions)
	}
	if _, found, err := ledger.GetExecution(ctx, ports.ExecutionScopeMCPAction, grant); err != nil || found {
		t.Fatalf("expired uncertain execution survived purge: found=%v err=%v", found, err)
	}
	// Re-establish exact downstream durable truth for the receipt-backed report
	// exercised below. Report acceptance requires Operator and action-MCP to
	// agree byte-for-byte unless the receipt is a locally synthesized rejection.
	actionReservation, err = ledger.ReserveExecution(
		ctx, ports.ExecutionScopeMCPAction, grant, "mcp-action-for-report", 30*time.Second,
	)
	if err != nil || !actionReservation.Owner {
		t.Fatalf("reserve MCP-action execution for report: reservation=%#v err=%v", actionReservation, err)
	}
	if _, err := ledger.CompleteExecution(
		ctx, ports.ExecutionScopeMCPAction, grant.GrantID, actionReservation.LeaseToken, receipt,
	); err != nil {
		t.Fatalf("complete MCP-action execution for report: %v", err)
	}
	preservedOperator, found, err := ledger.GetExecution(ctx, ports.ExecutionScopeOperator, grant)
	if err != nil || !found || preservedOperator.Status != ports.ExecutionCompleted {
		t.Fatalf("unreported Operator completion was not retained: record=%#v found=%v err=%v", preservedOperator, found, err)
	}
	preservedReservation, found, err := ledger.GetExecution(ctx, ports.ExecutionScopeOperator, concurrentGrant)
	if err != nil || !found || preservedReservation.Status != ports.ExecutionReserved {
		t.Fatalf("active execution reservation was not retained: record=%#v found=%v err=%v", preservedReservation, found, err)
	}

	conflicting := grant
	conflicting.Signature = model.GrantSignature{}
	conflicting.ProposalID = "different-proposal"
	if err := signer.Sign(&conflicting); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.ReserveExecution(
		ctx, ports.ExecutionScopeOperator, conflicting, "operator-conflict", 30*time.Second,
	); err == nil {
		t.Fatal("grant ID reuse with different signed contents was accepted")
	}

	reportRequest := model.IncidentReportRequest{
		SchemaVersion:     model.IncidentReportRequestSchemaVersionV2,
		RequestID:         "report-request-postgres-1",
		Issuer:            model.AgentMonitor,
		Audience:          model.AgentOperator,
		IncidentID:        grant.IncidentID,
		CorrelationID:     "correlation-postgres-1",
		DiagnosisReportID: grant.DiagnosisReportID,
		GrantID:           grant.GrantID,
		ReceiptID:         receipt.ReceiptID,
		Target:            grant.Action.Target,
		FinalState:        model.IncidentEscalated,
		Reason:            model.ReportReasonDryRunCompleted,
		ReportCreatedAt:   now.Add(3 * time.Second),
		RequestedAt:       now.Add(3 * time.Second),
		ExpiresAt:         now.Add(2*time.Minute + 3*time.Second),
	}
	if err := signer.SignReportRequest(&reportRequest); err != nil {
		t.Fatalf("sign report request: %v", err)
	}
	reportID, err := reportRequest.DeterministicReportID()
	if err != nil {
		t.Fatal(err)
	}
	report := model.IncidentReport{
		SchemaVersion:     model.SchemaVersionV1,
		ReportID:          reportID,
		RequestID:         reportRequest.RequestID,
		IncidentID:        reportRequest.IncidentID,
		CorrelationID:     reportRequest.CorrelationID,
		DiagnosisReportID: reportRequest.DiagnosisReportID,
		Target:            reportRequest.Target,
		FinalState:        reportRequest.FinalState,
		Reason:            reportRequest.Reason,
		Summary:           reportRequest.Reason.Summary(),
		Execution: &model.IncidentReportExecution{
			GrantID: receipt.GrantID, ReceiptID: receipt.ReceiptID,
			Action: receipt.Action, Outcome: receipt.Outcome,
			DryRun: receipt.DryRun, CompletedAt: receipt.CompletedAt,
		},
		CreatedAt: reportRequest.RequestedAt,
	}
	if err := report.Seal(); err != nil {
		t.Fatalf("seal incident report: %v", err)
	}
	outbox, err := NewReportOutbox(pool)
	if err != nil {
		t.Fatal(err)
	}
	notificationIntent := &ports.ReportNotificationIntent{
		Channel: model.NotificationChannelWhatsApp, AvailableAt: now.Add(-time.Second),
	}
	stored, err := outbox.AcceptReport(ctx, reportRequest, report, notificationIntent)
	if err != nil {
		t.Fatalf("accept report and outbox atomically: %v", err)
	}
	if !stored.Created || stored.Report.ReportID != report.ReportID {
		t.Fatalf("unexpected stored report: %#v", stored)
	}
	retried, err := outbox.AcceptReport(ctx, reportRequest, report, notificationIntent)
	if err != nil {
		t.Fatalf("accept exact duplicate report: %v", err)
	}
	if retried.Created {
		t.Fatal("exact duplicate report created a second durable record")
	}
	if _, err := pool.Exec(ctx, `
UPDATE aegis_execution_ledger SET retention_until = CURRENT_TIMESTAMP - interval '1 hour'
WHERE grant_id = $1 AND status = 'completed'`, grant.GrantID); err != nil {
		t.Fatalf("age reported completed executions for retention purge: %v", err)
	}
	purgedExecutions, err = ledger.PurgeExecutions(ctx, retentionCutoff, 10)
	if err != nil {
		t.Fatalf("purge reported Operator execution: %v", err)
	}
	if purgedExecutions != 2 {
		t.Fatalf("purged execution rows after report = %d, want both reported completions", purgedExecutions)
	}
	if _, found, err := ledger.GetExecutionByID(ctx, ports.ExecutionScopeOperator, grant.GrantID); err != nil || found {
		t.Fatalf("reported Operator completion survived retention purge: found=%v err=%v", found, err)
	}
	if _, found, err := ledger.GetExecutionByID(ctx, ports.ExecutionScopeMCPAction, grant.GrantID); err != nil || found {
		t.Fatalf("reported action-MCP completion survived retention purge: found=%v err=%v", found, err)
	}
	var retainedFenceCount int
	if err := pool.QueryRow(ctx, `
SELECT count(*) FROM aegis_execution_report_fences WHERE grant_id = $1`, grant.GrantID).Scan(&retainedFenceCount); err != nil {
		t.Fatal(err)
	}
	if retainedFenceCount != 2 {
		t.Fatalf("future purge cutoff removed fresh safety fences: got=%d want=2", retainedFenceCount)
	}
	replayedAfterExecutionPurge, err := outbox.AcceptReport(ctx, reportRequest, report, notificationIntent)
	if err != nil || replayedAfterExecutionPurge.Created || replayedAfterExecutionPurge.Report.Digest != report.Digest {
		t.Fatalf("exact report replay after execution purge = %#v err=%v", replayedAfterExecutionPurge, err)
	}
	if _, found, err := ledger.GetExecution(ctx, ports.ExecutionScopeOperator, concurrentGrant); err != nil || !found {
		t.Fatalf("active reservation was removed by terminal retention purge: found=%v err=%v", found, err)
	}

	messages, err := outbox.ClaimOutbox(ctx, "worker-a", 10, 30*time.Second)
	if err != nil {
		t.Fatalf("claim notification outbox: %v", err)
	}
	if len(messages) != 1 || messages[0].Report.ReportID != report.ReportID || messages[0].Attempts != 1 {
		t.Fatalf("unexpected claimed outbox messages: %#v", messages)
	}
	if err := outbox.RetryOutbox(
		ctx, messages[0].ID, messages[0].LeaseToken, model.CodeExecutionFailed, now.Add(-time.Second),
	); err != nil {
		t.Fatalf("schedule notification retry: %v", err)
	}
	messages, err = outbox.ClaimOutbox(ctx, "worker-after-restart", 10, 30*time.Second)
	if err != nil {
		t.Fatalf("reclaim retried notification: %v", err)
	}
	if len(messages) != 1 || messages[0].Attempts != 2 || messages[0].LeaseOwner != "worker-after-restart" {
		t.Fatalf("unexpected retried outbox message: %#v", messages)
	}
	if err := outbox.MarkOutboxDelivered(
		ctx, messages[0].ID, messages[0].LeaseToken, "wamid.postgres-test", now.Add(4*time.Second),
	); err != nil {
		t.Fatalf("mark notification delivered: %v", err)
	}
	delivered, ok, err := outbox.GetOutbox(ctx, report.ReportID)
	if err != nil || !ok {
		t.Fatalf("get delivered notification: ok=%v err=%v", ok, err)
	}
	if delivered.Status != ports.OutboxDelivered || delivered.ProviderMessageID != "wamid.postgres-test" {
		t.Fatalf("unexpected delivered notification: %#v", delivered)
	}
	var reportCount, outboxCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM aegis_incident_reports").Scan(&reportCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM aegis_notification_outbox").Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if reportCount != 1 || outboxCount != 1 {
		t.Fatalf("duplicate report changed durable cardinality: reports=%d outbox=%d", reportCount, outboxCount)
	}

	offlineRequest := model.IncidentReportRequest{
		SchemaVersion:     model.IncidentReportRequestSchemaVersionV2,
		RequestID:         "report-request-postgres-notification-disabled",
		Issuer:            model.AgentMonitor,
		Audience:          model.AgentOperator,
		IncidentID:        "incident-postgres-notification-disabled",
		CorrelationID:     "correlation-postgres-notification-disabled",
		DiagnosisReportID: "diagnosis-postgres-notification-disabled",
		Target:            grant.Action.Target,
		FinalState:        model.IncidentEscalated,
		Reason:            model.ReportReasonDiagnosisInconclusive,
		ReportCreatedAt:   now.Add(5 * time.Second),
		RequestedAt:       now.Add(5 * time.Second),
		ExpiresAt:         now.Add(2*time.Minute + 5*time.Second),
	}
	if err := signer.SignReportRequest(&offlineRequest); err != nil {
		t.Fatalf("sign notification-disabled report request: %v", err)
	}
	offlineReportID, err := offlineRequest.DeterministicReportID()
	if err != nil {
		t.Fatal(err)
	}
	offlineReport := model.IncidentReport{
		SchemaVersion:     model.SchemaVersionV1,
		ReportID:          offlineReportID,
		RequestID:         offlineRequest.RequestID,
		IncidentID:        offlineRequest.IncidentID,
		CorrelationID:     offlineRequest.CorrelationID,
		DiagnosisReportID: offlineRequest.DiagnosisReportID,
		Target:            offlineRequest.Target,
		FinalState:        offlineRequest.FinalState,
		Reason:            offlineRequest.Reason,
		Summary:           offlineRequest.Reason.Summary(),
		CreatedAt:         offlineRequest.RequestedAt,
	}
	if err := offlineReport.Seal(); err != nil {
		t.Fatalf("seal notification-disabled incident report: %v", err)
	}
	offlineStored, err := outbox.AcceptReport(ctx, offlineRequest, offlineReport, nil)
	if err != nil {
		t.Fatalf("accept durable report without notification intent: %v", err)
	}
	if !offlineStored.Created || offlineStored.HasNotificationIntent {
		t.Fatalf("unexpected notification-disabled stored report: %#v", offlineStored)
	}
	if _, found, err := outbox.GetOutbox(ctx, offlineReport.ReportID); err != nil || found {
		t.Fatalf("notification-disabled report created an outbox row: found=%v err=%v", found, err)
	}

	// A newly constructed adapter represents an Operator restart. The exact
	// accepted report remains available and cannot create a duplicate row.
	restartedOutbox, err := NewReportOutbox(pool)
	if err != nil {
		t.Fatal(err)
	}
	recoveredOffline, found, err := restartedOutbox.GetReport(ctx, offlineRequest.RequestID)
	if err != nil || !found || recoveredOffline.Report.Digest != offlineReport.Digest || recoveredOffline.HasNotificationIntent {
		t.Fatalf("recover notification-disabled report after restart: report=%#v found=%v err=%v", recoveredOffline, found, err)
	}
	deduplicatedOffline, err := restartedOutbox.AcceptReport(ctx, offlineRequest, offlineReport, nil)
	if err != nil || deduplicatedOffline.Created || deduplicatedOffline.Report.Digest != offlineReport.Digest {
		t.Fatalf("deduplicate notification-disabled report after restart: report=%#v err=%v", deduplicatedOffline, err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM aegis_incident_reports").Scan(&reportCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM aegis_notification_outbox").Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if reportCount != 2 || outboxCount != 1 {
		t.Fatalf("notification-disabled dedupe changed cardinality: reports=%d outbox=%d", reportCount, outboxCount)
	}

	deadLetterRequest := model.IncidentReportRequest{
		SchemaVersion:     model.IncidentReportRequestSchemaVersionV2,
		RequestID:         "report-request-postgres-dead-letter",
		Issuer:            model.AgentMonitor,
		Audience:          model.AgentOperator,
		IncidentID:        "incident-postgres-dead-letter",
		CorrelationID:     "correlation-postgres-dead-letter",
		DiagnosisReportID: "diagnosis-postgres-dead-letter",
		Target:            grant.Action.Target,
		FinalState:        model.IncidentEscalated,
		Reason:            model.ReportReasonDiagnosisInconclusive,
		ReportCreatedAt:   now.Add(5 * time.Second),
		RequestedAt:       now.Add(5 * time.Second),
		ExpiresAt:         now.Add(2*time.Minute + 5*time.Second),
	}
	if err := signer.SignReportRequest(&deadLetterRequest); err != nil {
		t.Fatalf("sign dead-letter report request: %v", err)
	}
	deadLetterReportID, err := deadLetterRequest.DeterministicReportID()
	if err != nil {
		t.Fatal(err)
	}
	deadLetterReport := model.IncidentReport{
		SchemaVersion:     model.SchemaVersionV1,
		ReportID:          deadLetterReportID,
		RequestID:         deadLetterRequest.RequestID,
		IncidentID:        deadLetterRequest.IncidentID,
		CorrelationID:     deadLetterRequest.CorrelationID,
		DiagnosisReportID: deadLetterRequest.DiagnosisReportID,
		Target:            deadLetterRequest.Target,
		FinalState:        deadLetterRequest.FinalState,
		Reason:            deadLetterRequest.Reason,
		Summary:           deadLetterRequest.Reason.Summary(),
		CreatedAt:         deadLetterRequest.RequestedAt,
	}
	if err := deadLetterReport.Seal(); err != nil {
		t.Fatalf("seal dead-letter report: %v", err)
	}
	deadLetterIntent := &ports.ReportNotificationIntent{
		Channel: model.NotificationChannelWhatsApp, AvailableAt: now.Add(-time.Second),
	}
	if _, err := outbox.AcceptReport(ctx, deadLetterRequest, deadLetterReport, deadLetterIntent); err != nil {
		t.Fatalf("accept dead-letter test report: %v", err)
	}
	messages, err = outbox.ClaimOutbox(ctx, "worker-dead-letter", 10, 30*time.Second)
	if err != nil || len(messages) != 1 {
		t.Fatalf("claim dead-letter test report: messages=%#v err=%v", messages, err)
	}
	if err := outbox.DeadLetterOutbox(
		ctx, messages[0].ID, messages[0].LeaseToken, model.CodeExecutionFailed, now.Add(6*time.Second),
	); err != nil {
		t.Fatalf("dead-letter notification: %v", err)
	}
	deadLettered, ok, err := outbox.GetOutbox(ctx, deadLetterReport.ReportID)
	if err != nil || !ok || deadLettered.Status != ports.OutboxDeadLetter || deadLettered.LastErrorCode != model.CodeExecutionFailed {
		t.Fatalf("unexpected dead-letter notification: value=%#v ok=%v err=%v", deadLettered, ok, err)
	}

	// Seed the other terminal and non-terminal outbox states directly. This
	// keeps the purge assertion focused on its SQL predicate rather than
	// repeating the report-delivery state machine above.
	const (
		retryReportID         = "report-postgres-purge-retry"
		liveDeliveredReportID = "report-postgres-purge-live-delivered"
	)
	if _, err := pool.Exec(ctx, `
INSERT INTO aegis_incident_reports (
    request_id, signed_fingerprint, request_digest, report_id, incident_id,
    request_json, report_json
) VALUES
    ('request-postgres-purge-retry', decode(repeat('00', 32), 'hex'), repeat('0', 64),
     $1, 'incident-postgres-purge-retry', '{}'::jsonb, '{}'::jsonb),
    ('request-postgres-purge-live-delivered', decode(repeat('00', 32), 'hex'), repeat('0', 64),
     $2, 'incident-postgres-purge-live-delivered', '{}'::jsonb, '{}'::jsonb)`,
		retryReportID, liveDeliveredReportID,
	); err != nil {
		t.Fatalf("seed parent reports for outbox purge test: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO aegis_notification_outbox (
    report_id, channel, idempotency_key, report_json, status, available_at,
    safe_error_code, provider_message_id, delivered_at
) VALUES
    ($1, 'whatsapp', 'outbox-purge-pending', '{}'::jsonb, 'pending', $4, NULL, NULL, NULL),
    ($2, 'whatsapp', 'outbox-purge-retry', '{}'::jsonb, 'retry_wait', $4, 'execution_failed', NULL, NULL),
    ($3, 'whatsapp', 'outbox-purge-live-delivered', '{}'::jsonb, 'delivered', $4, NULL,
     'wamid.postgres-live', $5)`,
		offlineReport.ReportID, retryReportID, liveDeliveredReportID,
		now, now.Add(10*time.Second),
	); err != nil {
		t.Fatalf("seed outbox states for purge test: %v", err)
	}
	outboxCutoff := now.Add(5 * time.Second)
	purgedOutbox, err := outbox.PurgeDeliveredOutbox(ctx, outboxCutoff, 10)
	if err != nil {
		t.Fatalf("purge delivered notification retention: %v", err)
	}
	if purgedOutbox != 1 {
		t.Fatalf("purged outbox rows = %d, want only the old delivered row", purgedOutbox)
	}
	if _, found, err := outbox.GetOutbox(ctx, report.ReportID); err != nil || found {
		t.Fatalf("old delivered notification survived purge: found=%v err=%v", found, err)
	}
	replayedAfterPurge, found, err := outbox.GetReport(ctx, reportRequest.RequestID)
	if err != nil || !found || !replayedAfterPurge.HasNotificationIntent {
		t.Fatalf("delivered-outbox purge erased immutable notification intent: report=%#v found=%v err=%v", replayedAfterPurge, found, err)
	}
	remainingStatuses := make(map[string]int)
	statusRows, err := pool.Query(ctx, `
SELECT status, count(*)::integer
FROM aegis_notification_outbox
GROUP BY status`)
	if err != nil {
		t.Fatalf("query outbox states after purge: %v", err)
	}
	for statusRows.Next() {
		var status string
		var count int
		if err := statusRows.Scan(&status, &count); err != nil {
			statusRows.Close()
			t.Fatalf("scan outbox state after purge: %v", err)
		}
		remainingStatuses[status] = count
	}
	if err := statusRows.Err(); err != nil {
		statusRows.Close()
		t.Fatalf("read outbox states after purge: %v", err)
	}
	statusRows.Close()
	wantStatuses := map[string]int{
		"pending": 1, "retry_wait": 1, "delivered": 1, "dead_letter": 1,
	}
	if !reflect.DeepEqual(remainingStatuses, wantStatuses) {
		t.Fatalf("outbox purge changed protected states: got=%v want=%v", remainingStatuses, wantStatuses)
	}

	makeGrant := func(suffix string) model.DelegationGrant {
		t.Helper()
		value := grant
		value.GrantID = "grant-postgres-fence-" + suffix
		value.IncidentID = "incident-postgres-fence-" + suffix
		value.DiagnosisReportID = "diagnosis-postgres-fence-" + suffix
		value.ProposalID = "proposal-postgres-fence-" + suffix
		value.IdempotencyKey = "action-postgres-fence-" + suffix
		value.Signature = model.GrantSignature{}
		if err := signer.Sign(&value); err != nil {
			t.Fatalf("sign %s fence grant: %v", suffix, err)
		}
		return value
	}
	makeUnverifiedReport := func(value model.DelegationGrant, suffix string) (model.IncidentReportRequest, model.IncidentReport) {
		t.Helper()
		requestedAt := now.Add(10 * time.Second)
		request := model.IncidentReportRequest{
			SchemaVersion: model.IncidentReportRequestSchemaVersionV2,
			RequestID:     "report-request-postgres-fence-" + suffix,
			Issuer:        model.AgentMonitor, Audience: model.AgentOperator,
			IncidentID: value.IncidentID, CorrelationID: "correlation-postgres-fence-" + suffix,
			DiagnosisReportID: value.DiagnosisReportID, GrantID: value.GrantID,
			Target: value.Action.Target, FinalState: model.IncidentEscalated,
			Reason:          model.ReportReasonActionOutcomeUnverified,
			ReportCreatedAt: requestedAt, RequestedAt: requestedAt,
			ExpiresAt: requestedAt.Add(2 * time.Minute),
		}
		if err := signer.SignReportRequest(&request); err != nil {
			t.Fatalf("sign %s unverified report request: %v", suffix, err)
		}
		reportID, err := request.DeterministicReportID()
		if err != nil {
			t.Fatalf("derive %s unverified report ID: %v", suffix, err)
		}
		report := model.IncidentReport{
			SchemaVersion: model.SchemaVersionV1, ReportID: reportID, RequestID: request.RequestID,
			IncidentID: request.IncidentID, CorrelationID: request.CorrelationID,
			DiagnosisReportID: request.DiagnosisReportID, Target: request.Target,
			FinalState: request.FinalState, Reason: request.Reason, Summary: request.Reason.Summary(),
			CreatedAt: request.ReportCreatedAt,
		}
		if err := report.Seal(); err != nil {
			t.Fatalf("seal %s unverified report: %v", suffix, err)
		}
		return request, report
	}

	// A signed grant-only terminal report installs both scope fences even when
	// neither execution row exists. A late request cannot reserve after commit.
	missingGrant := makeGrant("missing")
	missingRequest, missingReport := makeUnverifiedReport(missingGrant, "missing")
	if _, err := outbox.AcceptReport(ctx, missingRequest, missingReport, nil); err != nil {
		t.Fatalf("accept missing-ledger unverified report: %v", err)
	}
	var fenceCount int
	if err := pool.QueryRow(ctx, `
SELECT count(*) FROM aegis_execution_report_fences WHERE grant_id = $1`, missingGrant.GrantID).Scan(&fenceCount); err != nil {
		t.Fatal(err)
	}
	if fenceCount != 2 {
		t.Fatalf("missing-ledger report fences = %d, want both scopes", fenceCount)
	}
	for _, scope := range []ports.ExecutionScope{ports.ExecutionScopeOperator, ports.ExecutionScopeMCPAction} {
		if _, err := ledger.ReserveExecution(ctx, scope, missingGrant, "late-owner", 30*time.Second); err == nil {
			t.Fatalf("late %s reservation crossed terminal report fence", scope)
		} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeExecutionFailed {
			t.Fatalf("late %s reservation error = %v, want %s", scope, err, model.CodeExecutionFailed)
		}
	}

	// The shared grant advisory lock makes first reservation and terminal report
	// a true race with only two legal outcomes: a live reservation postpones the
	// report, or the committed report fences the reservation.
	raceGrant := makeGrant("race")
	raceRequest, raceReport := makeUnverifiedReport(raceGrant, "race")
	type reserveRaceResult struct {
		record ports.ExecutionRecord
		err    error
	}
	reserveRace := make(chan reserveRaceResult, 1)
	reportRace := make(chan error, 1)
	startRace := make(chan struct{})
	go func() {
		<-startRace
		record, reserveErr := ledger.ReserveExecution(
			ctx, ports.ExecutionScopeOperator, raceGrant, "race-owner", 30*time.Second,
		)
		reserveRace <- reserveRaceResult{record: record, err: reserveErr}
	}()
	go func() {
		<-startRace
		_, reportErr := outbox.AcceptReport(ctx, raceRequest, raceReport, nil)
		reportRace <- reportErr
	}()
	close(startRace)
	reserveResult := <-reserveRace
	reportErr := <-reportRace
	switch {
	case reserveResult.err == nil && reserveResult.record.Owner:
		if code, ok := model.ErrorCodeOf(reportErr); !ok || code != model.CodeExecutionPending {
			t.Fatalf("reservation-won race report error = %v, want %s", reportErr, model.CodeExecutionPending)
		}
		if _, found, err := outbox.GetReport(ctx, raceRequest.RequestID); err != nil || found {
			t.Fatalf("reservation-won race committed report: found=%v err=%v", found, err)
		}
	case reportErr == nil:
		if code, ok := model.ErrorCodeOf(reserveResult.err); !ok || code != model.CodeExecutionFailed {
			t.Fatalf("report-won race reservation error = %v, want %s", reserveResult.err, model.CodeExecutionFailed)
		}
		if _, found, err := outbox.GetReport(ctx, raceRequest.RequestID); err != nil || !found {
			t.Fatalf("report-won race did not commit report: found=%v err=%v", found, err)
		}
	default:
		t.Fatalf("illegal reserve/report race result: reservation=%#v reserveErr=%v reportErr=%v", reserveResult.record, reserveResult.err, reportErr)
	}

	// Original and renewed freshness envelopes share one stable logical report.
	// Concurrent acceptance must recover the winner rather than reject the
	// loser after a unique-key conflict.
	renewalAt := now.Add(15 * time.Second)
	originalRenewalRequest := model.IncidentReportRequest{
		SchemaVersion: model.IncidentReportRequestSchemaVersionV2,
		RequestID:     "report-request-postgres-renewal-race",
		Issuer:        model.AgentMonitor, Audience: model.AgentOperator,
		IncidentID: "incident-postgres-renewal-race", CorrelationID: "correlation-postgres-renewal-race",
		DiagnosisReportID: "diagnosis-postgres-renewal-race", Target: grant.Action.Target,
		FinalState: model.IncidentEscalated, Reason: model.ReportReasonDiagnosisInconclusive,
		ReportCreatedAt: renewalAt, RequestedAt: renewalAt, ExpiresAt: renewalAt.Add(time.Minute),
	}
	if err := signer.SignReportRequest(&originalRenewalRequest); err != nil {
		t.Fatalf("sign original renewal-race request: %v", err)
	}
	renewedRequest := originalRenewalRequest
	renewedRequest.RequestedAt = renewalAt.Add(time.Minute)
	renewedRequest.ExpiresAt = renewedRequest.RequestedAt.Add(time.Minute)
	renewedRequest.Signature = model.ReportRequestSignature{}
	if err := signer.SignReportRequest(&renewedRequest); err != nil {
		t.Fatalf("sign renewed renewal-race request: %v", err)
	}
	renewalReportID, err := originalRenewalRequest.DeterministicReportID()
	if err != nil {
		t.Fatal(err)
	}
	if renewedID, err := renewedRequest.DeterministicReportID(); err != nil || renewedID != renewalReportID {
		t.Fatalf("renewed logical report ID = %q err=%v, want %q", renewedID, err, renewalReportID)
	}
	renewalReport := model.IncidentReport{
		SchemaVersion: model.SchemaVersionV1, ReportID: renewalReportID,
		RequestID: originalRenewalRequest.RequestID, IncidentID: originalRenewalRequest.IncidentID,
		CorrelationID:     originalRenewalRequest.CorrelationID,
		DiagnosisReportID: originalRenewalRequest.DiagnosisReportID,
		Target:            originalRenewalRequest.Target, FinalState: originalRenewalRequest.FinalState,
		Reason: originalRenewalRequest.Reason, Summary: originalRenewalRequest.Reason.Summary(),
		CreatedAt: originalRenewalRequest.ReportCreatedAt,
	}
	if err := renewalReport.Seal(); err != nil {
		t.Fatalf("seal renewal-race report: %v", err)
	}
	type reportRaceResult struct {
		stored ports.StoredReport
		err    error
	}
	renewalResults := make(chan reportRaceResult, 2)
	renewalStart := make(chan struct{})
	for _, request := range []model.IncidentReportRequest{originalRenewalRequest, renewedRequest} {
		request := request
		go func() {
			<-renewalStart
			stored, acceptErr := outbox.AcceptReport(ctx, request, renewalReport, nil)
			renewalResults <- reportRaceResult{stored: stored, err: acceptErr}
		}()
	}
	close(renewalStart)
	createdReports := 0
	for range 2 {
		result := <-renewalResults
		if result.err != nil {
			t.Fatalf("concurrent semantic report renewal failed: %v", result.err)
		}
		if result.stored.Created {
			createdReports++
		}
	}
	if createdReports != 1 {
		t.Fatalf("concurrent semantic report renewals created %d reports, want one", createdReports)
	}

	// A live owner makes terminal report acceptance retryable and rolls back
	// report/fence insertion. DB-time lease expiry then converges the Operator
	// row to uncertain, marks it reported, and fences both scopes atomically.
	liveGrant := makeGrant("live")
	liveReservation, err := ledger.ReserveExecution(ctx, ports.ExecutionScopeOperator, liveGrant, "live-owner", 30*time.Second)
	if err != nil || !liveReservation.Owner {
		t.Fatalf("reserve live Operator execution: reservation=%#v err=%v", liveReservation, err)
	}
	liveRequest, liveReport := makeUnverifiedReport(liveGrant, "live")
	if _, err := outbox.AcceptReport(ctx, liveRequest, liveReport, nil); err == nil {
		t.Fatal("terminal report stole a live execution lease")
	} else if code, ok := model.ErrorCodeOf(err); !ok || code != model.CodeExecutionPending {
		t.Fatalf("live terminal report error = %v, want %s", err, model.CodeExecutionPending)
	}
	if _, found, err := outbox.GetReport(ctx, liveRequest.RequestID); err != nil || found {
		t.Fatalf("live-lease report transaction did not roll back: found=%v err=%v", found, err)
	}
	if _, err := pool.Exec(ctx, `
UPDATE aegis_execution_ledger SET lease_until = CURRENT_TIMESTAMP - interval '1 second'
WHERE scope = $1 AND grant_id = $2`, string(ports.ExecutionScopeOperator), liveGrant.GrantID); err != nil {
		t.Fatalf("expire live Operator lease: %v", err)
	}
	if _, err := outbox.AcceptReport(ctx, liveRequest, liveReport, nil); err != nil {
		t.Fatalf("accept report after DB-time lease expiry: %v", err)
	}
	liveTerminal, found, err := ledger.GetExecutionByID(ctx, ports.ExecutionScopeOperator, liveGrant.GrantID)
	if err != nil || !found || liveTerminal.Status != ports.ExecutionUncertain || liveTerminal.ReportedAt == nil ||
		liveTerminal.LeaseToken != "" || liveTerminal.LeaseOwner != "" || !liveTerminal.LeaseUntil.IsZero() {
		t.Fatalf("expired execution did not converge to reported uncertainty: record=%#v found=%v err=%v", liveTerminal, found, err)
	}
	replayedTerminal, err := ledger.ReserveExecution(ctx, ports.ExecutionScopeOperator, liveGrant, "late-operator", 30*time.Second)
	if err != nil || replayedTerminal.Owner || replayedTerminal.Status != ports.ExecutionUncertain {
		t.Fatalf("terminal Operator replay did not return exact ledger truth: record=%#v err=%v", replayedTerminal, err)
	}
	if _, err := ledger.ReserveExecution(ctx, ports.ExecutionScopeMCPAction, liveGrant, "late-action", 30*time.Second); err == nil {
		t.Fatal("missing action-MCP scope crossed terminal report fence")
	}

	// Cross-scope rows with the same IDs/target but different signed grant bytes
	// are corruption. The report and both fences must roll back unchanged.
	divergentGrant := makeGrant("divergent")
	if _, err := ledger.ReserveExecution(ctx, ports.ExecutionScopeOperator, divergentGrant, "operator-divergent", 30*time.Second); err != nil {
		t.Fatalf("reserve divergent Operator grant: %v", err)
	}
	actionDivergent := divergentGrant
	actionDivergent.IdempotencyKey += "-different"
	actionDivergent.ProposalID += "-different"
	actionDivergent.Signature = model.GrantSignature{}
	if err := signer.Sign(&actionDivergent); err != nil {
		t.Fatalf("sign divergent action-MCP grant: %v", err)
	}
	if _, err := ledger.ReserveExecution(ctx, ports.ExecutionScopeMCPAction, actionDivergent, "action-divergent", 30*time.Second); err != nil {
		t.Fatalf("reserve divergent action-MCP grant: %v", err)
	}
	divergentRequest, divergentReport := makeUnverifiedReport(divergentGrant, "divergent")
	if _, err := outbox.AcceptReport(ctx, divergentRequest, divergentReport, nil); err == nil {
		t.Fatal("terminal report accepted divergent cross-scope signed grants")
	}
	if _, found, err := outbox.GetReport(ctx, divergentRequest.RequestID); err != nil || found {
		t.Fatalf("divergent report transaction did not roll back: found=%v err=%v", found, err)
	}
	if err := pool.QueryRow(ctx, `
SELECT count(*) FROM aegis_execution_report_fences WHERE grant_id = $1`, divergentGrant.GrantID).Scan(&fenceCount); err != nil {
		t.Fatal(err)
	}
	if fenceCount != 0 {
		t.Fatalf("divergent report installed %d fences", fenceCount)
	}

	// Completed downstream truth must survive retention while its terminal
	// report is unavailable. Once report acceptance marks both scopes reported,
	// the same retention sweep may delete both rows.
	retainedGrant := makeGrant("retained-completion")
	retainedReceipt := model.ActionReceipt{
		SchemaVersion: model.SchemaVersionV1, ReceiptID: "receipt-postgres-retained-completion",
		GrantID: retainedGrant.GrantID, IncidentID: retainedGrant.IncidentID,
		Action: retainedGrant.Action, Outcome: model.ActionDryRun, DryRun: true,
		StartedAt: now, CompletedAt: now.Add(time.Second), AuditRef: "audit-postgres-retained-completion",
	}
	for _, scope := range []ports.ExecutionScope{ports.ExecutionScopeOperator, ports.ExecutionScopeMCPAction} {
		reservation, err := ledger.ReserveExecution(ctx, scope, retainedGrant, "retained-owner", 30*time.Second)
		if err != nil || !reservation.Owner {
			t.Fatalf("reserve retained %s execution: reservation=%#v err=%v", scope, reservation, err)
		}
		if _, err := ledger.CompleteExecution(ctx, scope, retainedGrant.GrantID, reservation.LeaseToken, retainedReceipt); err != nil {
			t.Fatalf("complete retained %s execution: %v", scope, err)
		}
	}
	if _, err := pool.Exec(ctx, `
UPDATE aegis_execution_ledger SET retention_until = $2
WHERE grant_id = $1`, retainedGrant.GrantID, now.Add(-time.Hour)); err != nil {
		t.Fatalf("age unreported completed executions: %v", err)
	}
	if purged, err := ledger.PurgeExecutions(ctx, now, 10); err != nil || purged != 0 {
		t.Fatalf("unreported completions were not retained: purged=%d err=%v", purged, err)
	}
	retainedRequestedAt := now.Add(12 * time.Second)
	retainedRequest := model.IncidentReportRequest{
		SchemaVersion: model.IncidentReportRequestSchemaVersionV2,
		RequestID:     "report-request-postgres-retained-completion",
		Issuer:        model.AgentMonitor, Audience: model.AgentOperator,
		IncidentID: retainedGrant.IncidentID, CorrelationID: "correlation-postgres-retained-completion",
		DiagnosisReportID: retainedGrant.DiagnosisReportID,
		GrantID:           retainedGrant.GrantID, ReceiptID: retainedReceipt.ReceiptID,
		Target: retainedGrant.Action.Target, FinalState: model.IncidentEscalated,
		Reason:          model.ReportReasonDryRunCompleted,
		ReportCreatedAt: retainedRequestedAt, RequestedAt: retainedRequestedAt,
		ExpiresAt: retainedRequestedAt.Add(2 * time.Minute),
	}
	if err := signer.SignReportRequest(&retainedRequest); err != nil {
		t.Fatalf("sign retained-completion report request: %v", err)
	}
	retainedReportID, err := retainedRequest.DeterministicReportID()
	if err != nil {
		t.Fatal(err)
	}
	retainedReport := model.IncidentReport{
		SchemaVersion: model.SchemaVersionV1, ReportID: retainedReportID, RequestID: retainedRequest.RequestID,
		IncidentID: retainedRequest.IncidentID, CorrelationID: retainedRequest.CorrelationID,
		DiagnosisReportID: retainedRequest.DiagnosisReportID, Target: retainedRequest.Target,
		FinalState: retainedRequest.FinalState, Reason: retainedRequest.Reason,
		Summary: retainedRequest.Reason.Summary(), CreatedAt: retainedRequest.ReportCreatedAt,
		Execution: &model.IncidentReportExecution{
			GrantID: retainedReceipt.GrantID, ReceiptID: retainedReceipt.ReceiptID,
			Action: retainedReceipt.Action, Outcome: retainedReceipt.Outcome,
			DryRun: retainedReceipt.DryRun, CompletedAt: retainedReceipt.CompletedAt,
		},
	}
	if err := retainedReport.Seal(); err != nil {
		t.Fatalf("seal retained-completion report: %v", err)
	}
	if _, err := outbox.AcceptReport(ctx, retainedRequest, retainedReport, nil); err != nil {
		t.Fatalf("accept retained-completion report: %v", err)
	}
	if purged, err := ledger.PurgeExecutions(ctx, now, 10); err != nil || purged != 2 {
		t.Fatalf("reported completions were not purged together: purged=%d err=%v", purged, err)
	}

	// Fence retention is bounded and uses the same grant lock as reservation.
	// The returned purge count includes fences so batch-draining jobs cannot
	// stop at zero while more expired fences remain.
	if _, err := pool.Exec(ctx, `
UPDATE aegis_execution_report_fences
SET created_at = CURRENT_TIMESTAMP - interval '4 hours',
    retention_until = CURRENT_TIMESTAMP - interval '3 hours'
WHERE grant_id = $1`, missingGrant.GrantID); err != nil {
		t.Fatalf("age terminal execution fences: %v", err)
	}
	purgedFences, err := ledger.PurgeExecutions(ctx, time.Now().UTC(), 10)
	if err != nil {
		t.Fatalf("purge retained terminal execution fences: %v", err)
	}
	if purgedFences != 2 {
		t.Fatalf("purge count = %d, want two expired fences", purgedFences)
	}
	if err := pool.QueryRow(ctx, `
SELECT count(*) FROM aegis_execution_report_fences WHERE grant_id = $1`, missingGrant.GrantID).Scan(&fenceCount); err != nil {
		t.Fatal(err)
	}
	if fenceCount != 0 {
		t.Fatalf("expired terminal fences survived purge: %d", fenceCount)
	}

	auditor, err := NewAuditor(pool)
	if err != nil {
		t.Fatal(err)
	}
	event := model.AuditEvent{
		ID: "audit-postgres-1", IncidentID: grant.IncidentID,
		Actor: model.AgentOperator, Operation: "durable_test", Decision: "allowed",
		OccurredAt: now,
	}
	if err := auditor.Record(ctx, event); err != nil {
		t.Fatalf("append audit event: %v", err)
	}
	if err := auditor.Record(ctx, event); err != nil {
		t.Fatalf("append exact duplicate audit event: %v", err)
	}
	event.Decision = "different"
	if err := auditor.Record(ctx, event); err == nil {
		t.Fatal("audit event ID reuse with different contents was accepted")
	}

	if _, err := pool.Exec(ctx, "DELETE FROM aegis_schema_migrations WHERE version = $1", "000001_control_state"); err != nil {
		t.Fatalf("remove migration ledger row for schema readiness test: %v", err)
	}
	if err := CheckSchema(ctx, pool); err == nil {
		t.Fatal("schema readiness accepted a missing earlier migration")
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("restore missing migration ledger row: %v", err)
	}
	if _, err := pool.Exec(ctx,
		"UPDATE aegis_schema_migrations SET checksum = $2 WHERE version = $1",
		"000001_control_state", make([]byte, 32),
	); err != nil {
		t.Fatalf("tamper migration checksum for schema readiness test: %v", err)
	}
	if err := CheckSchema(ctx, pool); err == nil {
		t.Fatal("schema readiness accepted a tampered earlier migration checksum")
	}
}

func signedTestGrant(t *testing.T, signer *security.Signer, now time.Time) model.DelegationGrant {
	t.Helper()
	replicas := int32(2)
	expected := int32(1)
	grant := model.DelegationGrant{
		SchemaVersion:       model.SchemaVersionV1,
		GrantID:             "grant-postgres-1",
		Issuer:              model.AgentMonitor,
		Audiences:           []model.AgentID{model.AgentOperator, model.AgentMCPAction},
		IncidentID:          "incident-postgres-1",
		DiagnosisReportID:   "diagnosis-postgres-1",
		DiagnosisDigest:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		DiagnosisConfidence: 0.95,
		EvidenceIDs:         []string{"evidence-postgres-1"},
		ProposalID:          "proposal-postgres-1",
		Action: model.ActionSpec{
			Kind: model.ActionScaleDeployment,
			Target: model.ResourceTarget{
				APIVersion: "apps/v1", Kind: "Deployment",
				Namespace: "outage-arena", Name: "demo-api",
			},
			Parameters: model.ActionParameters{Replicas: &replicas},
		},
		Preconditions: model.ActionPreconditions{
			ResourceVersion: "123", ExpectedReplicas: &expected,
		},
		DryRun: true, IdempotencyKey: "action-postgres-1",
		IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(2 * time.Minute),
	}
	if err := signer.Sign(&grant); err != nil {
		t.Fatalf("sign test delegation grant: %v", err)
	}
	return grant
}
