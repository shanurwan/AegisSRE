package postgres

import (
	"strings"
	"testing"
)

func TestValidateSchemaContract(t *testing.T) {
	t.Run("accepts exact migrated catalog", func(t *testing.T) {
		if err := validateSchemaContract(contractSnapshot()); err != nil {
			t.Fatalf("valid schema contract was rejected: %v", err)
		}
	})

	tests := []struct {
		name       string
		mutate     func(*schemaSnapshot)
		wantReason string
	}{
		{
			name: "partitioned parent table",
			mutate: func(snapshot *schemaSnapshot) {
				for index := range snapshot.Tables {
					if snapshot.Tables[index].Name == "aegis_audit_events" {
						snapshot.Tables[index].Kind = "p"
					}
				}
			},
			wantReason: "ordinary permanent PostgreSQL table",
		},
		{
			name: "partition leaf table",
			mutate: func(snapshot *schemaSnapshot) {
				for index := range snapshot.Tables {
					if snapshot.Tables[index].Name == "aegis_audit_events" {
						snapshot.Tables[index].IsPartition = true
						snapshot.Tables[index].InheritanceLinks = 1
					}
				}
			},
			wantReason: "ordinary permanent PostgreSQL table",
		},
		{
			name: "unlogged table",
			mutate: func(snapshot *schemaSnapshot) {
				for index := range snapshot.Tables {
					if snapshot.Tables[index].Name == "aegis_audit_events" {
						snapshot.Tables[index].Persistence = "u"
					}
				}
			},
			wantReason: "ordinary permanent PostgreSQL table",
		},
		{
			name: "row level security enabled",
			mutate: func(snapshot *schemaSnapshot) {
				snapshot.Tables[0].RowSecurity = true
			},
			wantReason: "must not enable or force row-level security",
		},
		{
			name: "row level security forced",
			mutate: func(snapshot *schemaSnapshot) {
				snapshot.Tables[0].ForceRLS = true
			},
			wantReason: "must not enable or force row-level security",
		},
		{
			name: "user trigger",
			mutate: func(snapshot *schemaSnapshot) {
				snapshot.Tables[0].UserTriggers = 1
			},
			wantReason: "must not have user-defined triggers",
		},
		{
			name: "relation rewrite-rule flag",
			mutate: func(snapshot *schemaSnapshot) {
				snapshot.Tables[0].HasRules = true
			},
			wantReason: "must not have rewrite rules",
		},
		{
			name: "rewrite catalog row",
			mutate: func(snapshot *schemaSnapshot) {
				snapshot.Tables[0].RewriteRules = 1
			},
			wantReason: "must not have rewrite rules",
		},
		{
			name: "missing table",
			mutate: func(snapshot *schemaSnapshot) {
				snapshot.Tables = snapshot.Tables[1:]
			},
			wantReason: "required table",
		},
		{
			name: "unexpected column",
			mutate: func(snapshot *schemaSnapshot) {
				snapshot.Columns = append(snapshot.Columns, inspectedColumn{
					Table: "aegis_execution_ledger", Name: "shadow_status", Type: "text",
				})
			},
			wantReason: "has 19 columns; expected 18",
		},
		{
			name: "weakened nullability",
			mutate: func(snapshot *schemaSnapshot) {
				for index := range snapshot.Columns {
					if snapshot.Columns[index].Table == "aegis_monitor_checkpoints" && snapshot.Columns[index].Name == "checkpoint_json" {
						snapshot.Columns[index].NotNull = false
					}
				}
			},
			wantReason: "column checkpoint_json has an incompatible",
		},
		{
			name: "altered default",
			mutate: func(snapshot *schemaSnapshot) {
				for index := range snapshot.Columns {
					if snapshot.Columns[index].Table == "aegis_notification_outbox" && snapshot.Columns[index].Name == "status" {
						snapshot.Columns[index].Default = "'delivered'::text"
					}
				}
			},
			wantReason: "column status has an incompatible",
		},
		{
			name: "non-default column collation",
			mutate: func(snapshot *schemaSnapshot) {
				for index := range snapshot.Columns {
					if snapshot.Columns[index].Table == "aegis_audit_events" && snapshot.Columns[index].Name == "actor" {
						snapshot.Columns[index].DefaultCollation = false
					}
				}
			},
			wantReason: "collation policy",
		},
		{
			name: "missing constraint",
			mutate: func(snapshot *schemaSnapshot) {
				snapshot.Constraints = snapshot.Constraints[1:]
			},
			wantReason: "constraint set",
		},
		{
			name: "unexpected exclusion constraint",
			mutate: func(snapshot *schemaSnapshot) {
				snapshot.Constraints = append(snapshot.Constraints, inspectedConstraint{
					Table: "aegis_audit_events", Definition: "EXCLUDE USING gist (occurred_at WITH =)", Validated: true,
				})
			},
			wantReason: "constraint set",
		},
		{
			name: "unvalidated constraint",
			mutate: func(snapshot *schemaSnapshot) {
				snapshot.Constraints[0].Validated = false
			},
			wantReason: "not validated",
		},
		{
			name: "altered check constraint",
			mutate: func(snapshot *schemaSnapshot) {
				for index := range snapshot.Constraints {
					if snapshot.Constraints[index].Table == "aegis_monitor_leases" && strings.Contains(snapshot.Constraints[index].Definition, "fencing_token") {
						snapshot.Constraints[index].Definition = "CHECK (fencing_token >= 0)"
					}
				}
			},
			wantReason: "missing or has altered a required constraint",
		},
		{
			name: "missing operational index",
			mutate: func(snapshot *schemaSnapshot) {
				snapshot.Indexes = snapshot.Indexes[1:]
			},
			wantReason: "required index",
		},
		{
			name: "unexpected standalone unique index",
			mutate: func(snapshot *schemaSnapshot) {
				snapshot.Indexes = append(snapshot.Indexes, inspectedIndex{
					Name: "aegis_shadow_unique", Table: "aegis_audit_events", Method: "btree",
					Columns: []string{"incident_id"}, Unique: true, Valid: true, Ready: true,
				})
			},
			wantReason: "unexpected behavior-changing index",
		},
		{
			name: "unexpected expression index",
			mutate: func(snapshot *schemaSnapshot) {
				snapshot.Indexes = append(snapshot.Indexes, inspectedIndex{
					Name: "aegis_shadow_expression", Table: "aegis_audit_events", Method: "btree",
					Columns: []string{"(actor::integer)"}, Expression: true, Valid: true, Ready: true,
				})
			},
			wantReason: "unexpected behavior-changing index",
		},
		{
			name: "unexpected partial index",
			mutate: func(snapshot *schemaSnapshot) {
				snapshot.Indexes = append(snapshot.Indexes, inspectedIndex{
					Name: "aegis_shadow_partial", Table: "aegis_audit_events", Method: "btree",
					Columns: []string{"id"}, Predicate: "actor = 'operator'::text", Valid: true, Ready: true,
				})
			},
			wantReason: "unexpected behavior-changing index",
		},
		{
			name: "altered partial index predicate",
			mutate: func(snapshot *schemaSnapshot) {
				for index := range snapshot.Indexes {
					if snapshot.Indexes[index].Name == "aegis_outbox_due_idx" {
						snapshot.Indexes[index].Predicate = "status = 'pending'::text"
					}
				}
			},
			wantReason: "index aegis_outbox_due_idx has an incompatible",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := contractSnapshot()
			test.mutate(&snapshot)
			err := validateSchemaContract(snapshot)
			if err == nil {
				t.Fatal("incompatible schema contract was accepted")
			}
			if !strings.Contains(err.Error(), test.wantReason) {
				t.Fatalf("unexpected error %q; want it to contain %q", err, test.wantReason)
			}
		})
	}
}

func TestCanonicalSQLIgnoresOnlySafeCatalogPresentationDifferences(t *testing.T) {
	left := "CHECK (\n  status = 'Pending Value'::TEXT\t)"
	right := ` check(status='Pending Value'::text) `
	if canonicalSQL(left) != canonicalSQL(right) {
		t.Fatalf("equivalent catalog expressions did not normalize equally: %q != %q", canonicalSQL(left), canonicalSQL(right))
	}
}

func TestCanonicalSQLPreservesBooleanGrouping(t *testing.T) {
	left := `CHECK ((status = 'pending'::text OR attempts = 0) AND safe_error_code IS NULL)`
	right := `CHECK (status = 'pending'::text OR (attempts = 0 AND safe_error_code IS NULL))`
	if canonicalSQL(left) == canonicalSQL(right) {
		t.Fatalf("different AND/OR grouping collided as %q", canonicalSQL(left))
	}
}

func TestCanonicalSQLPreservesQuotedLiteralCase(t *testing.T) {
	lowercaseClass := `CHECK (request_digest ~ '^[0-9a-f]{64}$'::text)`
	uppercaseClass := `CHECK (request_digest ~ '^[0-9A-F]{64}$'::text)`
	if canonicalSQL(lowercaseClass) == canonicalSQL(uppercaseClass) {
		t.Fatalf("case-sensitive regex literals collided as %q", canonicalSQL(lowercaseClass))
	}
}

func contractSnapshot() schemaSnapshot {
	var snapshot schemaSnapshot
	for _, table := range sortedMapKeys(expectedColumns) {
		snapshot.Tables = append(snapshot.Tables, inspectedTable{
			Name: table, Kind: "r", Persistence: "p",
		})
		for _, name := range sortedMapKeys(expectedColumns[table]) {
			column := expectedColumns[table][name]
			snapshot.Columns = append(snapshot.Columns, inspectedColumn{
				Table: table, Name: name, Type: column.Type, NotNull: column.NotNull,
				Default: column.Default, Identity: column.Identity, Generated: column.Generated,
				DefaultCollation: true,
			})
		}
	}
	for _, table := range sortedMapKeys(expectedConstraints) {
		for _, definition := range expectedConstraints[table] {
			snapshot.Constraints = append(snapshot.Constraints, inspectedConstraint{
				Table: table, Definition: definition, Validated: true,
			})
		}
	}
	for _, name := range sortedMapKeys(expectedIndexes) {
		index := expectedIndexes[name]
		snapshot.Indexes = append(snapshot.Indexes, inspectedIndex{
			Name: name, Table: index.Table, Method: "btree", Columns: append([]string(nil), index.Columns...),
			Predicate: index.Predicate, Valid: true, Ready: true,
		})
	}
	return snapshot
}
