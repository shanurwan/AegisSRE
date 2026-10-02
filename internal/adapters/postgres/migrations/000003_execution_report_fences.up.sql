ALTER TABLE aegis_incident_reports
    ADD COLUMN IF NOT EXISTS notification_requested boolean NOT NULL DEFAULT false;

UPDATE aegis_incident_reports reports
SET notification_requested = true
WHERE EXISTS (
    SELECT 1 FROM aegis_notification_outbox outbox
    WHERE outbox.report_id = reports.report_id
);

CREATE TABLE IF NOT EXISTS aegis_execution_report_fences (
    scope text NOT NULL CHECK (scope IN ('operator', 'mcp_action')),
    grant_id text NOT NULL CHECK (length(grant_id) BETWEEN 1 AND 512),
    incident_id text NOT NULL CHECK (length(incident_id) BETWEEN 1 AND 512),
    diagnosis_report_id text NOT NULL CHECK (length(diagnosis_report_id) BETWEEN 1 AND 512),
    target_json jsonb NOT NULL CHECK (octet_length(target_json::text) <= 16384),
    report_request_id text NOT NULL REFERENCES aegis_incident_reports(request_id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retention_until timestamptz NOT NULL CHECK (retention_until > created_at),
    PRIMARY KEY (scope, grant_id),
    UNIQUE (report_request_id, scope)
);

CREATE INDEX IF NOT EXISTS aegis_execution_report_fence_incident_idx
    ON aegis_execution_report_fences (incident_id, scope, grant_id);

CREATE INDEX IF NOT EXISTS aegis_execution_report_fence_retention_idx
    ON aegis_execution_report_fences (retention_until, grant_id, scope);
