CREATE TABLE IF NOT EXISTS aegis_execution_ledger (
    scope text NOT NULL CHECK (scope IN ('operator', 'mcp_action')),
    grant_id text NOT NULL CHECK (length(grant_id) BETWEEN 1 AND 512),
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 512),
    signed_fingerprint bytea NOT NULL CHECK (octet_length(signed_fingerprint) = 32),
    incident_id text NOT NULL CHECK (length(incident_id) BETWEEN 1 AND 512),
    grant_json jsonb NOT NULL CHECK (octet_length(grant_json::text) <= 131072),
    status text NOT NULL CHECK (status IN ('reserved', 'completed', 'uncertain')),
    lease_owner text,
    lease_token text,
    lease_until timestamptz,
    receipt_id text,
    receipt_json jsonb CHECK (receipt_json IS NULL OR octet_length(receipt_json::text) <= 131072),
    safe_error_code text,
    started_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamptz,
    reported_at timestamptz,
    retention_until timestamptz NOT NULL,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    PRIMARY KEY (scope, grant_id),
    UNIQUE (scope, idempotency_key),
    CHECK (
        (status = 'reserved' AND lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_until IS NOT NULL AND receipt_json IS NULL)
        OR (status = 'completed' AND lease_owner IS NULL AND lease_token IS NULL AND lease_until IS NULL AND receipt_id IS NOT NULL AND receipt_json IS NOT NULL AND completed_at IS NOT NULL)
        OR (status = 'uncertain' AND lease_owner IS NULL AND lease_token IS NULL AND lease_until IS NULL AND receipt_json IS NULL AND safe_error_code IS NOT NULL AND completed_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS aegis_execution_retention_idx
    ON aegis_execution_ledger (retention_until)
    WHERE status IN ('completed', 'uncertain');

CREATE TABLE IF NOT EXISTS aegis_incident_reports (
    request_id text PRIMARY KEY CHECK (length(request_id) BETWEEN 1 AND 512),
    signed_fingerprint bytea NOT NULL CHECK (octet_length(signed_fingerprint) = 32),
    request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    report_id text NOT NULL UNIQUE CHECK (length(report_id) BETWEEN 1 AND 512),
    incident_id text NOT NULL UNIQUE CHECK (length(incident_id) BETWEEN 1 AND 512),
    request_json jsonb NOT NULL CHECK (octet_length(request_json::text) <= 131072),
    report_json jsonb NOT NULL CHECK (octet_length(report_json::text) <= 131072),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS aegis_notification_outbox (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    report_id text NOT NULL REFERENCES aegis_incident_reports(report_id) ON DELETE RESTRICT,
    channel text NOT NULL CHECK (channel = 'whatsapp'),
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 512),
    report_json jsonb NOT NULL CHECK (octet_length(report_json::text) <= 131072),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sending', 'retry_wait', 'delivered', 'dead_letter')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lease_owner text,
    lease_token text,
    lease_until timestamptz,
    provider_message_id text,
    safe_error_code text,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    delivered_at timestamptz,
    UNIQUE (channel, report_id),
    UNIQUE (channel, idempotency_key),
    CHECK (
        (status = 'sending' AND lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_until IS NOT NULL)
        OR (status <> 'sending' AND lease_owner IS NULL AND lease_token IS NULL AND lease_until IS NULL)
    ),
    CHECK (
        (status = 'delivered' AND provider_message_id IS NOT NULL AND delivered_at IS NOT NULL AND safe_error_code IS NULL)
        OR (status <> 'delivered' AND provider_message_id IS NULL AND delivered_at IS NULL)
    ),
    CHECK (status NOT IN ('retry_wait', 'dead_letter') OR safe_error_code IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS aegis_outbox_due_idx
    ON aegis_notification_outbox (available_at, id)
    WHERE status IN ('pending', 'retry_wait');

CREATE INDEX IF NOT EXISTS aegis_outbox_stale_lease_idx
    ON aegis_notification_outbox (lease_until, id)
    WHERE status = 'sending';

CREATE TABLE IF NOT EXISTS aegis_audit_events (
    id text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 512),
    incident_id text NOT NULL CHECK (length(incident_id) BETWEEN 1 AND 512),
    actor text NOT NULL CHECK (length(actor) BETWEEN 1 AND 512),
    operation text NOT NULL CHECK (length(operation) BETWEEN 1 AND 512),
    decision text NOT NULL CHECK (length(decision) BETWEEN 1 AND 512),
    side_effect boolean NOT NULL,
    occurred_at timestamptz NOT NULL,
    event_json jsonb NOT NULL CHECK (octet_length(event_json::text) <= 131072),
    event_fingerprint bytea NOT NULL CHECK (octet_length(event_fingerprint) = 32),
    inserted_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS aegis_audit_incident_time_idx
    ON aegis_audit_events (incident_id, occurred_at, id);

-- Runtime roles should receive INSERT/SELECT only on the audit table. These
-- revocations protect installations that accidentally grant privileges to
-- PUBLIC; the migration owner must separately grant narrowly scoped rights.
REVOKE UPDATE, DELETE, TRUNCATE ON aegis_audit_events FROM PUBLIC;

