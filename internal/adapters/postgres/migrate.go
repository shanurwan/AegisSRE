package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	SchemaVersion = "000003_execution_report_fences"
	migrationLock = int64(0x4145474953535245)
)

//go:embed migrations/*.up.sql
var migrationFiles embed.FS

// Migrate applies embedded forward-only migrations under a session advisory
// lock. A checksum mismatch is fatal: already-applied migrations are immutable.
// Production should run this with a migration-only database role.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return fmt.Errorf("postgres migration pool is required")
	}
	connection, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire postgres migration connection: %w", err)
	}
	defer connection.Release()
	if _, err := connection.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLock); err != nil {
		return fmt.Errorf("acquire postgres migration lock: %w", err)
	}
	defer func() {
		unlockContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = connection.Exec(unlockContext, "SELECT pg_advisory_unlock($1)", migrationLock)
	}()

	if _, err := connection.Exec(ctx, `
CREATE TABLE IF NOT EXISTS aegis_schema_migrations (
    version text PRIMARY KEY,
    checksum bytea NOT NULL CHECK (octet_length(checksum) = 32),
    applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
)`); err != nil {
		return fmt.Errorf("create schema migration ledger: %w", err)
	}

	names, err := fs.Glob(migrationFiles, "migrations/*.up.sql")
	if err != nil {
		return fmt.Errorf("list embedded postgres migrations: %w", err)
	}
	sort.Strings(names)
	for _, name := range names {
		body, err := migrationFiles.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read embedded postgres migration %s: %w", name, err)
		}
		body = normalizeMigration(body)
		version := strings.TrimSuffix(filepath.Base(name), ".up.sql")
		checksum := sha256.Sum256(body)
		var existing []byte
		err = connection.QueryRow(ctx,
			"SELECT checksum FROM aegis_schema_migrations WHERE version = $1", version,
		).Scan(&existing)
		switch {
		case err == nil:
			if !bytes.Equal(existing, checksum[:]) {
				return fmt.Errorf("postgres migration %s checksum differs from the applied migration", version)
			}
			continue
		case !noRows(err):
			return fmt.Errorf("read postgres migration %s state: %w", version, err)
		}

		transaction, err := connection.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin postgres migration %s: %w", version, err)
		}
		if _, err = transaction.Exec(ctx, string(body)); err == nil {
			_, err = transaction.Exec(ctx,
				"INSERT INTO aegis_schema_migrations(version, checksum) VALUES ($1, $2)",
				version, checksum[:],
			)
		}
		if err != nil {
			_ = transaction.Rollback(ctx)
			return fmt.Errorf("apply postgres migration %s: %w", version, err)
		}
		if err := transaction.Commit(ctx); err != nil {
			return fmt.Errorf("commit postgres migration %s: %w", version, err)
		}
	}
	return nil
}

// CheckSchema verifies the exact migration-version set, every checksum, and
// the resulting catalog shape without taking DDL privileges. These checks are
// intentional: a forged, stale, or forward-incompatible ledger must not make
// an incompatible pre-existing schema appear ready. Runtime processes should
// call this before becoming ready.
func CheckSchema(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return fmt.Errorf("postgres pool is required")
	}
	names, err := fs.Glob(migrationFiles, "migrations/*.up.sql")
	if err != nil {
		return fmt.Errorf("list expected postgres schema migrations: %w", err)
	}
	sort.Strings(names)
	if len(names) == 0 || strings.TrimSuffix(filepath.Base(names[len(names)-1]), ".up.sql") != SchemaVersion {
		return fmt.Errorf("embedded postgres schema version %s is not the newest migration", SchemaVersion)
	}
	expectedMigrations := make(map[string][]byte, len(names))
	for _, name := range names {
		body, err := migrationFiles.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read expected postgres schema migration %s: %w", name, err)
		}
		version := strings.TrimSuffix(filepath.Base(name), ".up.sql")
		expected := sha256.Sum256(normalizeMigration(body))
		expectedMigrations[version] = expected[:]
	}
	rows, err := pool.Query(ctx, "SELECT version, checksum FROM aegis_schema_migrations ORDER BY version")
	if err != nil {
		return fmt.Errorf("read postgres schema migration ledger: %w", err)
	}
	seen := make(map[string]struct{}, len(expectedMigrations))
	for rows.Next() {
		var version string
		var checksum []byte
		if err := rows.Scan(&version, &checksum); err != nil {
			rows.Close()
			return fmt.Errorf("scan postgres schema migration ledger: %w", err)
		}
		expected, known := expectedMigrations[version]
		if !known {
			rows.Close()
			return fmt.Errorf("postgres schema has an unknown migration version")
		}
		if !bytes.Equal(checksum, expected) {
			rows.Close()
			return fmt.Errorf("postgres schema migration %s checksum mismatch", version)
		}
		seen[version] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("read postgres schema migration ledger: %w", err)
	}
	rows.Close()
	for _, name := range names {
		version := strings.TrimSuffix(filepath.Base(name), ".up.sql")
		if _, ok := seen[version]; !ok {
			return fmt.Errorf("postgres schema is missing required migration %s", version)
		}
	}
	if err := checkSchemaContract(ctx, pool); err != nil {
		return fmt.Errorf("postgres schema contract mismatch: %w", err)
	}
	return nil
}

func normalizeMigration(body []byte) []byte {
	// Git may check unspecified text files out with CRLF on Windows. Migration
	// identity must not vary with the build host's line-ending policy.
	return bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n"))
}
