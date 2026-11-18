package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"fmt"
	"strings"
)

// The existing admission v1/v2/v3 migration sources and checksums are immutable.
// These four separately versioned extensions are forward-only.
//
//go:embed schema_permit_v4.sql
var permitClaimSchema string

//go:embed schema_permit_v5.sql
var permitIdentitySchema string

//go:embed schema_permit_v6.sql
var permitUnknownSchema string

//go:embed schema_permit_v7.sql
var permitRevocationSchema string

//go:embed schema_permit_v8.sql
var permitEvidenceFenceSchema string

//go:embed schema_permit_v9.sql
var permitIdentityFenceSchema string

func applyPermitLedgerExtension(ctx context.Context, tx *sql.Tx, applied int) error {
	migrations := []struct {
		version int64
		source  string
	}{
		{4, permitClaimSchema},
		{5, permitIdentitySchema},
		{6, permitUnknownSchema},
		{7, permitRevocationSchema},
		{8, permitEvidenceFenceSchema},
		{9, permitIdentityFenceSchema},
	}
	for _, item := range migrations {
		if applied >= int(item.version) {
			continue
		}
		// All four extension files contain only plain DDL. Do not use
		// this delimiter for future functions with semicolon bodies.
		statements := strings.Split(item.source, ";")
		if item.version == 9 {
			// PL/pgSQL trigger bodies contain semicolons.
			statements = strings.Split(item.source, "-- statement break")
		}
		for _, stmt := range statements {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("apply forward Permit migration v%d: %w", item.version, err)
			}
		}
		sum := sha256.Sum256([]byte(item.source))
		if _, err := tx.ExecContext(ctx, "INSERT INTO guard_schema_migrations(version,checksum) VALUES ($1,$2)",
			item.version, fmt.Sprintf("%x", sum)); err != nil {
			return fmt.Errorf("record forward Permit migration v%d: %w", item.version, err)
		}
	}
	return verifyPermitLedgerCatalog(ctx, tx)
}

func verifyPermitLedgerCatalog(ctx context.Context, tx *sql.Tx) error {
	for _, name := range []string{
		"guard_permits", "guard_operation_intents", "guard_execution_audit",
		"guard_operation_unknown_events", "guard_permit_revocations",
	} {
		var valid bool
		err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
			  SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=to_regclass($1)
			    AND c.relkind='r' AND c.relpersistence='p'
			    AND c.relnamespace=current_schema()::regnamespace
			)
		`, name).Scan(&valid)
		if err != nil || !valid {
			return fmt.Errorf("%w: invalid Permit relation %s: %v", ErrSchemaDrift, name, err)
		}
	}
	for _, pair := range []struct {
		table, name, referenced, columns, target string
	}{
		{"guard_operation_intents", "guard_intent_resolved_permit_fk", "guard_permits",
			"tenant_id,operation_id,permit_id,action_hash,binding_digest",
			"tenant_id,operation_id,permit_id,action_hash,binding_digest"},
		{"guard_execution_audit", "guard_audit_resolved_intent_fk", "guard_operation_intents",
			"tenant_id,operation_id,permit_id,attempt_id,action_hash",
			"tenant_id,operation_id,permit_id,attempt_id,action_hash"},
		{"guard_operation_unknown_events", "guard_unknown_exact_intent_fk", "guard_operation_intents",
			"tenant_id,operation_id,permit_id,attempt_id,action_hash",
			"tenant_id,operation_id,permit_id,attempt_id,action_hash"},
		{"guard_permit_revocations", "guard_revocation_exact_permit_fk", "guard_permits",
			"tenant_id,permit_id", "tenant_id,permit_id"},
	} {
		var valid bool
		err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
			  SELECT 1 FROM pg_catalog.pg_constraint c
			    WHERE c.conrelid=to_regclass($1) AND c.conname=$2
			      AND c.contype='f' AND c.convalidated
			      AND NOT c.condeferrable AND NOT c.condeferred
			      AND c.confrelid=to_regclass($3)
			      AND (SELECT string_agg(a.attname,',' ORDER BY k.ord)
			           FROM unnest(c.conkey) WITH ORDINALITY k(attnum,ord)
			           JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum)=$4
			      AND (SELECT string_agg(a.attname,',' ORDER BY k.ord)
			           FROM unnest(c.confkey) WITH ORDINALITY k(attnum,ord)
			           JOIN pg_catalog.pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.attnum)=$5
			)
		`, pair.table, pair.name, pair.referenced, pair.columns, pair.target).Scan(&valid)
		if err != nil || !valid {
			return fmt.Errorf("%w: invalid Permit relation %s: %v", ErrSchemaDrift, pair.name, err)
		}
	}
	// Checksums alone cannot prove the actual database still enforces
	// immutable evidence. Reject disabled, replacement or origin-only
	// triggers (including disabled triggers after a privileged DDL change).
	for _, table := range []string{
		"guard_execution_audit", "guard_operation_unknown_events", "guard_permit_revocations",
	} {
		for _, trigger := range []struct {
			suffix string
			kind   int
		}{{"_immutable_row", 27}, {"_immutable_truncate", 34}} {
			var valid bool
			err := tx.QueryRowContext(ctx, `
				SELECT EXISTS (
					SELECT 1 FROM pg_catalog.pg_trigger t
					WHERE t.tgrelid = to_regclass($1)
					  AND t.tgname = $2
					  AND t.tgenabled = 'A'
					  AND NOT t.tgisinternal
					  AND t.tgtype = $3
					  AND t.tgfoid = to_regprocedure('guard_reject_snapshot_mutation()')
				)
			`, table, table+trigger.suffix, trigger.kind).Scan(&valid)
			if err != nil || !valid {
				return fmt.Errorf("%w: immutable Guard evidence trigger %s%s: %v",
					ErrSchemaDrift, table, trigger.suffix, err)
			}
		}
	}
	for _, expected := range []struct {
		name, function string
		tgtype         int
	}{
		{"guard_permit_immutable_row_v9", "guard_permit_immutable_row_v9()", 27},
		{"guard_permit_immutable_truncate_v9", "guard_reject_snapshot_mutation()", 34},
	} {
		var intact bool
		err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
			  SELECT 1 FROM pg_catalog.pg_trigger t
			  WHERE t.tgrelid=to_regclass('guard_permits')
			    AND t.tgname=$1 AND t.tgtype=$2
			    AND NOT t.tgisinternal AND t.tgenabled='A'
			    AND t.tgfoid=to_regprocedure($3)
			)
			`, expected.name, expected.tgtype, expected.function).Scan(&intact)
		if err != nil || !intact {
			return fmt.Errorf("%w: Permit v9 write-once trigger %s disabled or changed: %v", ErrSchemaDrift, expected.name, err)
		}
	}
	return nil
}
