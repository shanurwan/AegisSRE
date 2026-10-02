CREATE TABLE IF NOT EXISTS aegis_monitor_leases (
    namespace text PRIMARY KEY CHECK (length(namespace) BETWEEN 1 AND 253),
    lease_owner text NOT NULL CHECK (length(lease_owner) BETWEEN 1 AND 512),
    lease_token text NOT NULL CHECK (length(lease_token) BETWEEN 1 AND 128),
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    lease_until timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS aegis_monitor_lease_expiry_idx
    ON aegis_monitor_leases (lease_until);

CREATE TABLE IF NOT EXISTS aegis_monitor_checkpoints (
    namespace text PRIMARY KEY REFERENCES aegis_monitor_leases(namespace) ON DELETE RESTRICT,
    checkpoint_json jsonb NOT NULL CHECK (octet_length(checkpoint_json::text) <= 4194304),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

