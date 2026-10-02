package postgres

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"
)

type columnContract struct {
	Type      string
	NotNull   bool
	Default   string
	Identity  string
	Generated string
}

type indexContract struct {
	Table     string
	Columns   []string
	Predicate string
}

type inspectedTable struct {
	Name             string
	Kind             string
	Persistence      string
	IsPartition      bool
	InheritanceLinks int
	RowSecurity      bool
	ForceRLS         bool
	UserTriggers     int
	HasRules         bool
	RewriteRules     int
}

type inspectedColumn struct {
	Table            string
	Name             string
	Type             string
	NotNull          bool
	Default          string
	Identity         string
	Generated        string
	DefaultCollation bool
}

type inspectedConstraint struct {
	Table      string
	Definition string
	Validated  bool
}

type inspectedIndex struct {
	Name             string
	Table            string
	Method           string
	Columns          []string
	Predicate        string
	Unique           bool
	Exclusion        bool
	ConstraintBacked bool
	Expression       bool
	Valid            bool
	Ready            bool
}

type schemaSnapshot struct {
	Tables      []inspectedTable
	Columns     []inspectedColumn
	Constraints []inspectedConstraint
	Indexes     []inspectedIndex
}

var expectedColumns = map[string]map[string]columnContract{
	"aegis_schema_migrations": {
		"version":    {Type: "text", NotNull: true},
		"checksum":   {Type: "bytea", NotNull: true},
		"applied_at": {Type: "timestamp with time zone", NotNull: true, Default: "CURRENT_TIMESTAMP"},
	},
	"aegis_execution_ledger": {
		"scope":              {Type: "text", NotNull: true},
		"grant_id":           {Type: "text", NotNull: true},
		"idempotency_key":    {Type: "text", NotNull: true},
		"signed_fingerprint": {Type: "bytea", NotNull: true},
		"incident_id":        {Type: "text", NotNull: true},
		"grant_json":         {Type: "jsonb", NotNull: true},
		"status":             {Type: "text", NotNull: true},
		"lease_owner":        {Type: "text"},
		"lease_token":        {Type: "text"},
		"lease_until":        {Type: "timestamp with time zone"},
		"receipt_id":         {Type: "text"},
		"receipt_json":       {Type: "jsonb"},
		"safe_error_code":    {Type: "text"},
		"started_at":         {Type: "timestamp with time zone", NotNull: true, Default: "CURRENT_TIMESTAMP"},
		"completed_at":       {Type: "timestamp with time zone"},
		"reported_at":        {Type: "timestamp with time zone"},
		"retention_until":    {Type: "timestamp with time zone", NotNull: true},
		"version":            {Type: "bigint", NotNull: true, Default: "1"},
	},
	"aegis_execution_report_fences": {
		"scope":               {Type: "text", NotNull: true},
		"grant_id":            {Type: "text", NotNull: true},
		"incident_id":         {Type: "text", NotNull: true},
		"diagnosis_report_id": {Type: "text", NotNull: true},
		"target_json":         {Type: "jsonb", NotNull: true},
		"report_request_id":   {Type: "text", NotNull: true},
		"created_at":          {Type: "timestamp with time zone", NotNull: true, Default: "CURRENT_TIMESTAMP"},
		"retention_until":     {Type: "timestamp with time zone", NotNull: true},
	},
	"aegis_incident_reports": {
		"request_id":             {Type: "text", NotNull: true},
		"signed_fingerprint":     {Type: "bytea", NotNull: true},
		"request_digest":         {Type: "text", NotNull: true},
		"report_id":              {Type: "text", NotNull: true},
		"incident_id":            {Type: "text", NotNull: true},
		"request_json":           {Type: "jsonb", NotNull: true},
		"report_json":            {Type: "jsonb", NotNull: true},
		"notification_requested": {Type: "boolean", NotNull: true, Default: "false"},
		"created_at":             {Type: "timestamp with time zone", NotNull: true, Default: "CURRENT_TIMESTAMP"},
		"updated_at":             {Type: "timestamp with time zone", NotNull: true, Default: "CURRENT_TIMESTAMP"},
	},
	"aegis_notification_outbox": {
		"id":                  {Type: "bigint", NotNull: true, Identity: "a"},
		"report_id":           {Type: "text", NotNull: true},
		"channel":             {Type: "text", NotNull: true},
		"idempotency_key":     {Type: "text", NotNull: true},
		"report_json":         {Type: "jsonb", NotNull: true},
		"status":              {Type: "text", NotNull: true, Default: "'pending'::text"},
		"attempts":            {Type: "integer", NotNull: true, Default: "0"},
		"available_at":        {Type: "timestamp with time zone", NotNull: true, Default: "CURRENT_TIMESTAMP"},
		"lease_owner":         {Type: "text"},
		"lease_token":         {Type: "text"},
		"lease_until":         {Type: "timestamp with time zone"},
		"provider_message_id": {Type: "text"},
		"safe_error_code":     {Type: "text"},
		"created_at":          {Type: "timestamp with time zone", NotNull: true, Default: "CURRENT_TIMESTAMP"},
		"updated_at":          {Type: "timestamp with time zone", NotNull: true, Default: "CURRENT_TIMESTAMP"},
		"delivered_at":        {Type: "timestamp with time zone"},
	},
	"aegis_audit_events": {
		"id":                {Type: "text", NotNull: true},
		"incident_id":       {Type: "text", NotNull: true},
		"actor":             {Type: "text", NotNull: true},
		"operation":         {Type: "text", NotNull: true},
		"decision":          {Type: "text", NotNull: true},
		"side_effect":       {Type: "boolean", NotNull: true},
		"occurred_at":       {Type: "timestamp with time zone", NotNull: true},
		"event_json":        {Type: "jsonb", NotNull: true},
		"event_fingerprint": {Type: "bytea", NotNull: true},
		"inserted_at":       {Type: "timestamp with time zone", NotNull: true, Default: "CURRENT_TIMESTAMP"},
	},
	"aegis_monitor_leases": {
		"namespace":     {Type: "text", NotNull: true},
		"lease_owner":   {Type: "text", NotNull: true},
		"lease_token":   {Type: "text", NotNull: true},
		"fencing_token": {Type: "bigint", NotNull: true},
		"lease_until":   {Type: "timestamp with time zone", NotNull: true},
		"updated_at":    {Type: "timestamp with time zone", NotNull: true, Default: "CURRENT_TIMESTAMP"},
	},
	"aegis_monitor_checkpoints": {
		"namespace":       {Type: "text", NotNull: true},
		"checkpoint_json": {Type: "jsonb", NotNull: true},
		"version":         {Type: "bigint", NotNull: true, Default: "1"},
		"fencing_token":   {Type: "bigint", NotNull: true},
		"updated_at":      {Type: "timestamp with time zone", NotNull: true, Default: "CURRENT_TIMESTAMP"},
	},
}

// Constraint definitions are compared in PostgreSQL's deparsed form. The
// normalizer only folds unquoted keyword/identifier case and insignificant
// whitespace. Parentheses, casts, quoted identifiers, and string-literal
// bytes remain significant so different boolean grouping or regex character
// classes cannot collide.
var expectedConstraints = map[string][]string{
	"aegis_schema_migrations": {
		"PRIMARY KEY (version)",
		"CHECK (octet_length(checksum) = 32)",
	},
	"aegis_execution_ledger": {
		"PRIMARY KEY (scope, grant_id)",
		"UNIQUE (scope, idempotency_key)",
		"CHECK (scope = ANY (ARRAY['operator'::text, 'mcp_action'::text]))",
		"CHECK (length(grant_id) >= 1 AND length(grant_id) <= 512)",
		"CHECK (length(idempotency_key) >= 1 AND length(idempotency_key) <= 512)",
		"CHECK (octet_length(signed_fingerprint) = 32)",
		"CHECK (length(incident_id) >= 1 AND length(incident_id) <= 512)",
		"CHECK (octet_length(grant_json::text) <= 131072)",
		"CHECK (status = ANY (ARRAY['reserved'::text, 'completed'::text, 'uncertain'::text]))",
		"CHECK (receipt_json IS NULL OR octet_length(receipt_json::text) <= 131072)",
		"CHECK (version > 0)",
		`CHECK (
			status = 'reserved'::text AND lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_until IS NOT NULL AND receipt_json IS NULL
			OR status = 'completed'::text AND lease_owner IS NULL AND lease_token IS NULL AND lease_until IS NULL AND receipt_id IS NOT NULL AND receipt_json IS NOT NULL AND completed_at IS NOT NULL
			OR status = 'uncertain'::text AND lease_owner IS NULL AND lease_token IS NULL AND lease_until IS NULL AND receipt_json IS NULL AND safe_error_code IS NOT NULL AND completed_at IS NOT NULL
		)`,
	},
	"aegis_execution_report_fences": {
		"PRIMARY KEY (scope, grant_id)",
		"UNIQUE (report_request_id, scope)",
		"FOREIGN KEY (report_request_id) REFERENCES aegis_incident_reports(request_id) ON DELETE RESTRICT",
		"CHECK (scope = ANY (ARRAY['operator'::text, 'mcp_action'::text]))",
		"CHECK (length(grant_id) >= 1 AND length(grant_id) <= 512)",
		"CHECK (length(incident_id) >= 1 AND length(incident_id) <= 512)",
		"CHECK (length(diagnosis_report_id) >= 1 AND length(diagnosis_report_id) <= 512)",
		"CHECK (octet_length(target_json::text) <= 16384)",
		"CHECK (retention_until > created_at)",
	},
	"aegis_incident_reports": {
		"PRIMARY KEY (request_id)",
		"UNIQUE (report_id)",
		"UNIQUE (incident_id)",
		"CHECK (length(request_id) >= 1 AND length(request_id) <= 512)",
		"CHECK (octet_length(signed_fingerprint) = 32)",
		"CHECK (request_digest ~ '^[0-9a-f]{64}$'::text)",
		"CHECK (length(report_id) >= 1 AND length(report_id) <= 512)",
		"CHECK (length(incident_id) >= 1 AND length(incident_id) <= 512)",
		"CHECK (octet_length(request_json::text) <= 131072)",
		"CHECK (octet_length(report_json::text) <= 131072)",
	},
	"aegis_notification_outbox": {
		"PRIMARY KEY (id)",
		"FOREIGN KEY (report_id) REFERENCES aegis_incident_reports(report_id) ON DELETE RESTRICT",
		"UNIQUE (channel, report_id)",
		"UNIQUE (channel, idempotency_key)",
		"CHECK (channel = 'whatsapp'::text)",
		"CHECK (length(idempotency_key) >= 1 AND length(idempotency_key) <= 512)",
		"CHECK (octet_length(report_json::text) <= 131072)",
		"CHECK (status = ANY (ARRAY['pending'::text, 'sending'::text, 'retry_wait'::text, 'delivered'::text, 'dead_letter'::text]))",
		"CHECK (attempts >= 0)",
		"CHECK (status = 'sending'::text AND lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_until IS NOT NULL OR status <> 'sending'::text AND lease_owner IS NULL AND lease_token IS NULL AND lease_until IS NULL)",
		"CHECK (status = 'delivered'::text AND provider_message_id IS NOT NULL AND delivered_at IS NOT NULL AND safe_error_code IS NULL OR status <> 'delivered'::text AND provider_message_id IS NULL AND delivered_at IS NULL)",
		"CHECK ((status <> ALL (ARRAY['retry_wait'::text, 'dead_letter'::text])) OR safe_error_code IS NOT NULL)",
	},
	"aegis_audit_events": {
		"PRIMARY KEY (id)",
		"CHECK (length(id) >= 1 AND length(id) <= 512)",
		"CHECK (length(incident_id) >= 1 AND length(incident_id) <= 512)",
		"CHECK (length(actor) >= 1 AND length(actor) <= 512)",
		"CHECK (length(operation) >= 1 AND length(operation) <= 512)",
		"CHECK (length(decision) >= 1 AND length(decision) <= 512)",
		"CHECK (octet_length(event_json::text) <= 131072)",
		"CHECK (octet_length(event_fingerprint) = 32)",
	},
	"aegis_monitor_leases": {
		"PRIMARY KEY (namespace)",
		"CHECK (length(namespace) >= 1 AND length(namespace) <= 253)",
		"CHECK (length(lease_owner) >= 1 AND length(lease_owner) <= 512)",
		"CHECK (length(lease_token) >= 1 AND length(lease_token) <= 128)",
		"CHECK (fencing_token > 0)",
	},
	"aegis_monitor_checkpoints": {
		"PRIMARY KEY (namespace)",
		"FOREIGN KEY (namespace) REFERENCES aegis_monitor_leases(namespace) ON DELETE RESTRICT",
		"CHECK (octet_length(checkpoint_json::text) <= 4194304)",
		"CHECK (version > 0)",
		"CHECK (fencing_token > 0)",
	},
}

var expectedIndexes = map[string]indexContract{
	"aegis_execution_retention_idx": {
		Table: "aegis_execution_ledger", Columns: []string{"retention_until"},
		Predicate: "status = ANY (ARRAY['completed'::text, 'uncertain'::text])",
	},
	"aegis_execution_report_fence_incident_idx": {
		Table: "aegis_execution_report_fences", Columns: []string{"incident_id", "scope", "grant_id"},
	},
	"aegis_execution_report_fence_retention_idx": {
		Table: "aegis_execution_report_fences", Columns: []string{"retention_until", "grant_id", "scope"},
	},
	"aegis_outbox_due_idx": {
		Table: "aegis_notification_outbox", Columns: []string{"available_at", "id"},
		Predicate: "status = ANY (ARRAY['pending'::text, 'retry_wait'::text])",
	},
	"aegis_outbox_stale_lease_idx": {
		Table: "aegis_notification_outbox", Columns: []string{"lease_until", "id"},
		Predicate: "status = 'sending'::text",
	},
	"aegis_audit_incident_time_idx": {
		Table: "aegis_audit_events", Columns: []string{"incident_id", "occurred_at", "id"},
	},
	"aegis_monitor_lease_expiry_idx": {
		Table: "aegis_monitor_leases", Columns: []string{"lease_until"},
	},
}

func checkSchemaContract(ctx context.Context, pool *pgxpool.Pool) error {
	snapshot, err := inspectSchemaContract(ctx, pool)
	if err != nil {
		return err
	}
	return validateSchemaContract(snapshot)
}

func inspectSchemaContract(ctx context.Context, pool *pgxpool.Pool) (schemaSnapshot, error) {
	var snapshot schemaSnapshot
	var schema string
	if err := pool.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		return snapshot, fmt.Errorf("resolve current PostgreSQL schema: %w", err)
	}
	tables := sortedMapKeys(expectedColumns)
	rows, err := pool.Query(ctx, `
SELECT table_class.relname,
       table_class.relkind::text,
       table_class.relpersistence::text,
       table_class.relispartition,
       (
           SELECT count(*)::integer
           FROM pg_catalog.pg_inherits AS inheritance
           WHERE inheritance.inhrelid = table_class.oid
              OR inheritance.inhparent = table_class.oid
       ),
       table_class.relrowsecurity,
       table_class.relforcerowsecurity,
       (
           SELECT count(*)::integer
           FROM pg_catalog.pg_trigger AS trigger_row
           WHERE trigger_row.tgrelid = table_class.oid
             AND NOT trigger_row.tgisinternal
       ),
       table_class.relhasrules,
       (
           SELECT count(*)::integer
           FROM pg_catalog.pg_rewrite AS rewrite_rule
           WHERE rewrite_rule.ev_class = table_class.oid
       )
FROM pg_catalog.pg_class AS table_class
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = table_class.relnamespace
WHERE namespace.nspname = $1
  AND table_class.relname = ANY($2::text[])
ORDER BY table_class.relname`, schema, tables)
	if err != nil {
		return snapshot, fmt.Errorf("inspect PostgreSQL table properties: %w", err)
	}
	for rows.Next() {
		var table inspectedTable
		if err := rows.Scan(
			&table.Name, &table.Kind, &table.Persistence, &table.IsPartition,
			&table.InheritanceLinks, &table.RowSecurity, &table.ForceRLS, &table.UserTriggers,
			&table.HasRules, &table.RewriteRules,
		); err != nil {
			rows.Close()
			return snapshot, fmt.Errorf("scan PostgreSQL table properties: %w", err)
		}
		snapshot.Tables = append(snapshot.Tables, table)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return snapshot, fmt.Errorf("read PostgreSQL table properties: %w", err)
	}
	rows.Close()

	rows, err = pool.Query(ctx, `
SELECT table_class.relname,
       attribute.attname,
       pg_catalog.format_type(attribute.atttypid, attribute.atttypmod),
       attribute.attnotnull,
       COALESCE(pg_catalog.pg_get_expr(default_value.adbin, default_value.adrelid), ''),
       attribute.attidentity::text,
       attribute.attgenerated::text,
       attribute.attcollation = type_row.typcollation
FROM pg_catalog.pg_class AS table_class
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = table_class.relnamespace
JOIN pg_catalog.pg_attribute AS attribute ON attribute.attrelid = table_class.oid
JOIN pg_catalog.pg_type AS type_row ON type_row.oid = attribute.atttypid
LEFT JOIN pg_catalog.pg_attrdef AS default_value
       ON default_value.adrelid = table_class.oid AND default_value.adnum = attribute.attnum
WHERE namespace.nspname = $1
  AND table_class.relname = ANY($2::text[])
  AND table_class.relkind IN ('r', 'p')
  AND attribute.attnum > 0
  AND NOT attribute.attisdropped
ORDER BY table_class.relname, attribute.attnum`, schema, tables)
	if err != nil {
		return snapshot, fmt.Errorf("inspect PostgreSQL columns: %w", err)
	}
	for rows.Next() {
		var column inspectedColumn
		if err := rows.Scan(
			&column.Table, &column.Name, &column.Type, &column.NotNull,
			&column.Default, &column.Identity, &column.Generated, &column.DefaultCollation,
		); err != nil {
			rows.Close()
			return snapshot, fmt.Errorf("scan PostgreSQL column contract: %w", err)
		}
		snapshot.Columns = append(snapshot.Columns, column)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return snapshot, fmt.Errorf("read PostgreSQL column contract: %w", err)
	}
	rows.Close()

	rows, err = pool.Query(ctx, `
SELECT table_class.relname,
       pg_catalog.pg_get_constraintdef(constraint_row.oid, true),
       constraint_row.convalidated
FROM pg_catalog.pg_constraint AS constraint_row
JOIN pg_catalog.pg_class AS table_class ON table_class.oid = constraint_row.conrelid
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = table_class.relnamespace
WHERE namespace.nspname = $1
  AND table_class.relname = ANY($2::text[])
  AND constraint_row.contype IN ('p', 'u', 'f', 'c', 'x')
ORDER BY table_class.relname, constraint_row.oid`, schema, tables)
	if err != nil {
		return snapshot, fmt.Errorf("inspect PostgreSQL constraints: %w", err)
	}
	for rows.Next() {
		var constraint inspectedConstraint
		if err := rows.Scan(&constraint.Table, &constraint.Definition, &constraint.Validated); err != nil {
			rows.Close()
			return snapshot, fmt.Errorf("scan PostgreSQL constraint contract: %w", err)
		}
		snapshot.Constraints = append(snapshot.Constraints, constraint)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return snapshot, fmt.Errorf("read PostgreSQL constraint contract: %w", err)
	}
	rows.Close()

	rows, err = pool.Query(ctx, `
SELECT index_class.relname,
       table_class.relname,
       access_method.amname,
       ARRAY(
           SELECT pg_catalog.pg_get_indexdef(index_row.indexrelid, position, true)
           FROM generate_series(1, index_row.indnkeyatts) AS position
           ORDER BY position
       ),
       COALESCE(pg_catalog.pg_get_expr(index_row.indpred, index_row.indrelid, true), ''),
       index_row.indisunique,
       index_row.indisexclusion,
       EXISTS (
           SELECT 1
           FROM pg_catalog.pg_constraint AS index_constraint
           WHERE index_constraint.conindid = index_row.indexrelid
       ),
       index_row.indexprs IS NOT NULL,
       index_row.indisvalid,
       index_row.indisready
FROM pg_catalog.pg_index AS index_row
JOIN pg_catalog.pg_class AS index_class ON index_class.oid = index_row.indexrelid
JOIN pg_catalog.pg_class AS table_class ON table_class.oid = index_row.indrelid
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = index_class.relnamespace
JOIN pg_catalog.pg_am AS access_method ON access_method.oid = index_class.relam
WHERE namespace.nspname = $1
  AND table_class.relname = ANY($2::text[])
ORDER BY index_class.relname`, schema, tables)
	if err != nil {
		return snapshot, fmt.Errorf("inspect PostgreSQL indexes: %w", err)
	}
	for rows.Next() {
		var index inspectedIndex
		if err := rows.Scan(
			&index.Name, &index.Table, &index.Method, &index.Columns, &index.Predicate,
			&index.Unique, &index.Exclusion, &index.ConstraintBacked, &index.Expression,
			&index.Valid, &index.Ready,
		); err != nil {
			rows.Close()
			return snapshot, fmt.Errorf("scan PostgreSQL index contract: %w", err)
		}
		snapshot.Indexes = append(snapshot.Indexes, index)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return snapshot, fmt.Errorf("read PostgreSQL index contract: %w", err)
	}
	rows.Close()
	return snapshot, nil
}

func validateSchemaContract(snapshot schemaSnapshot) error {
	actualTables := make(map[string]inspectedTable, len(expectedColumns))
	for _, table := range snapshot.Tables {
		if _, managed := expectedColumns[table.Name]; !managed {
			continue
		}
		if _, duplicate := actualTables[table.Name]; duplicate {
			return fmt.Errorf("managed table %s appears more than once in the active schema", table.Name)
		}
		actualTables[table.Name] = table
	}
	for _, name := range sortedMapKeys(expectedColumns) {
		table, ok := actualTables[name]
		if !ok {
			return fmt.Errorf("required table %s is missing", name)
		}
		if table.Kind != "r" || table.Persistence != "p" || table.IsPartition || table.InheritanceLinks != 0 {
			return fmt.Errorf("table %s must be an ordinary permanent PostgreSQL table", name)
		}
		if table.RowSecurity || table.ForceRLS {
			return fmt.Errorf("table %s must not enable or force row-level security", name)
		}
		if table.UserTriggers != 0 {
			return fmt.Errorf("table %s must not have user-defined triggers", name)
		}
		// PostgreSQL can retain relhasrules after the final rule is dropped
		// until VACUUM clears the hint. Readiness deliberately remains closed
		// during that interval: both the catalog hint and pg_rewrite must attest
		// that no write-rewriting surface remains.
		if table.HasRules || table.RewriteRules != 0 {
			return fmt.Errorf("table %s must not have rewrite rules", name)
		}
	}

	actualColumns := make(map[string]map[string]inspectedColumn, len(expectedColumns))
	for _, column := range snapshot.Columns {
		if _, managed := expectedColumns[column.Table]; !managed {
			continue
		}
		if actualColumns[column.Table] == nil {
			actualColumns[column.Table] = make(map[string]inspectedColumn)
		}
		if _, duplicate := actualColumns[column.Table][column.Name]; duplicate {
			return fmt.Errorf("table %s has duplicate catalog column %s", column.Table, column.Name)
		}
		actualColumns[column.Table][column.Name] = column
	}
	for _, table := range sortedMapKeys(expectedColumns) {
		expectedTable := expectedColumns[table]
		actualTable := actualColumns[table]
		if len(actualTable) == 0 {
			return fmt.Errorf("required table %s is missing or is not a base table", table)
		}
		if len(actualTable) != len(expectedTable) {
			return fmt.Errorf("table %s has %d columns; expected %d", table, len(actualTable), len(expectedTable))
		}
		for _, name := range sortedMapKeys(expectedTable) {
			expected := expectedTable[name]
			actual, ok := actualTable[name]
			if !ok {
				return fmt.Errorf("table %s is missing required column %s", table, name)
			}
			if actual.Type != expected.Type || actual.NotNull != expected.NotNull ||
				canonicalSQL(actual.Default) != canonicalSQL(expected.Default) ||
				actual.Identity != expected.Identity || actual.Generated != expected.Generated ||
				!actual.DefaultCollation {
				return fmt.Errorf("table %s column %s has an incompatible type, nullability, default, identity, generation, or collation policy", table, name)
			}
		}
	}

	actualConstraints := make(map[string]map[string]int, len(expectedConstraints))
	for _, constraint := range snapshot.Constraints {
		if _, managed := expectedConstraints[constraint.Table]; !managed {
			continue
		}
		if !constraint.Validated {
			return fmt.Errorf("table %s has a required constraint that is not validated", constraint.Table)
		}
		if actualConstraints[constraint.Table] == nil {
			actualConstraints[constraint.Table] = make(map[string]int)
		}
		actualConstraints[constraint.Table][canonicalSQL(constraint.Definition)]++
	}
	for _, table := range sortedMapKeys(expectedConstraints) {
		expectedSet := make(map[string]int, len(expectedConstraints[table]))
		for _, definition := range expectedConstraints[table] {
			expectedSet[canonicalSQL(definition)]++
		}
		actualSet := actualConstraints[table]
		if len(actualSet) != len(expectedSet) {
			return fmt.Errorf("table %s has an incompatible primary, unique, foreign-key, or check constraint set", table)
		}
		for definition, count := range expectedSet {
			if actualSet[definition] != count {
				return fmt.Errorf("table %s is missing or has altered a required constraint", table)
			}
		}
	}

	actualIndexes := make(map[string]inspectedIndex, len(expectedIndexes))
	for _, index := range snapshot.Indexes {
		if _, expected := expectedIndexes[index.Name]; !expected {
			if index.Exclusion || index.Unique && !index.ConstraintBacked ||
				index.Expression || index.Predicate != "" {
				return fmt.Errorf("table %s has an unexpected behavior-changing index", index.Table)
			}
			continue
		}
		if _, duplicate := actualIndexes[index.Name]; duplicate {
			return fmt.Errorf("index %s appears more than once in the active schema", index.Name)
		}
		actualIndexes[index.Name] = index
	}
	for _, name := range sortedMapKeys(expectedIndexes) {
		expected := expectedIndexes[name]
		actual, ok := actualIndexes[name]
		if !ok {
			return fmt.Errorf("required index %s is missing", name)
		}
		if actual.Table != expected.Table || actual.Method != "btree" || actual.Unique ||
			actual.Exclusion || actual.ConstraintBacked || actual.Expression ||
			!actual.Valid || !actual.Ready || !equalStrings(actual.Columns, expected.Columns) ||
			canonicalSQL(actual.Predicate) != canonicalSQL(expected.Predicate) {
			return fmt.Errorf("index %s has an incompatible table, method, keys, predicate, or validity state", name)
		}
	}
	return nil
}

func canonicalSQL(value string) string {
	var normalized strings.Builder
	normalized.Grow(len(value))
	for index := 0; index < len(value); {
		character, width := utf8.DecodeRuneInString(value[index:])
		if isSQLSpace(character) {
			index += width
			continue
		}

		start := index
		switch {
		case character == '\'' || character == '"':
			quote := character
			index += width
			for index < len(value) {
				current, currentWidth := utf8.DecodeRuneInString(value[index:])
				index += currentWidth
				if current != quote {
					continue
				}
				if index < len(value) {
					next, nextWidth := utf8.DecodeRuneInString(value[index:])
					if next == quote {
						index += nextWidth
						continue
					}
				}
				break
			}
			appendSQLToken(&normalized, value[start:index])
		case isSQLWordCharacter(character):
			index += width
			for index < len(value) {
				current, currentWidth := utf8.DecodeRuneInString(value[index:])
				if !isSQLWordCharacter(current) {
					break
				}
				index += currentWidth
			}
			appendSQLToken(&normalized, strings.Map(toLowerASCII, value[start:index]))
		case isSQLDelimiter(character):
			index += width
			appendSQLToken(&normalized, value[start:index])
		default:
			index += width
			for index < len(value) {
				current, currentWidth := utf8.DecodeRuneInString(value[index:])
				if isSQLSpace(current) || isSQLWordCharacter(current) || current == '\'' || current == '"' || isSQLDelimiter(current) {
					break
				}
				index += currentWidth
			}
			appendSQLToken(&normalized, value[start:index])
		}
	}
	return normalized.String()
}

func appendSQLToken(destination *strings.Builder, token string) {
	destination.WriteString(strconv.Itoa(len(token)))
	destination.WriteByte(':')
	destination.WriteString(token)
	destination.WriteByte(';')
}

func isSQLSpace(character rune) bool {
	switch character {
	case ' ', '\t', '\n', '\r', '\f':
		return true
	default:
		return false
	}
}

func isSQLWordCharacter(character rune) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' ||
		character == '_' || character == '$' || character >= 0x80
}

func isSQLDelimiter(character rune) bool {
	switch character {
	case '(', ')', '[', ']', ',', '.', ';':
		return true
	default:
		return false
	}
}

func toLowerASCII(character rune) rune {
	if character >= 'A' && character <= 'Z' {
		return character + ('a' - 'A')
	}
	return character
}

func sortedMapKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
