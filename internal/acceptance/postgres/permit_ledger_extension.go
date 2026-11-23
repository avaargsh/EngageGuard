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
// These separately versioned extensions are forward-only.
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

//go:embed schema_permit_v10.sql
var permitCausalFenceSchema string

//go:embed schema_permit_v11.sql
var permitCommitExpirySchema string

//go:embed schema_permit_v12.sql
var permitInsertStateSchema string

//go:embed schema_permit_v13.sql
var permitCausalSchemaPinnedV13 string

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
		{10, permitCausalFenceSchema},
		{11, permitCommitExpirySchema},
		{12, permitInsertStateSchema},
		{13, permitCausalSchemaPinnedV13},
	}
	for _, item := range migrations {
		if applied >= int(item.version) {
			continue
		}
		// Earlier extension files contain plain DDL. Do not use
		// this delimiter for future functions with semicolon bodies.
		statements := strings.Split(item.source, ";")
		if item.version >= 9 {
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
			  SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=pg_catalog.to_regclass(pg_catalog.format('%I.%I', current_schema(), $1::text))
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
			    WHERE c.conrelid=pg_catalog.to_regclass(pg_catalog.format('%I.%I', current_schema(), $1::text)) AND c.conname=$2
			      AND c.contype='f' AND c.convalidated
			      AND NOT c.condeferrable AND NOT c.condeferred
			      AND c.confrelid=pg_catalog.to_regclass(pg_catalog.format('%I.%I', current_schema(), $3::text))
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
	// A WHEN predicate can skip an ENABLE ALWAYS trigger, even when deferred;
	// UPDATE OF can narrow its firing columns. Require no tgqual/tgattr.
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
					WHERE t.tgrelid = pg_catalog.to_regclass(pg_catalog.format('%I.%I', current_schema(), $1::text))
					  AND t.tgname = $2
					  AND t.tgenabled = 'A'
					  AND t.tgqual IS NULL AND t.tgattr::text=''
					  AND NOT t.tgisinternal
					  AND t.tgtype = $3
					  AND t.tgfoid = pg_catalog.to_regprocedure(pg_catalog.format('%I.%I()', current_schema(), 'guard_reject_snapshot_mutation'))
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
			  WHERE t.tgrelid=pg_catalog.to_regclass(pg_catalog.format('%I.%I', current_schema(), 'guard_permits'))
			    AND t.tgname=$1 AND t.tgtype=$2
			    AND NOT t.tgisinternal AND t.tgenabled='A'
			    AND t.tgqual IS NULL AND t.tgattr::text=''
			    AND t.tgfoid=pg_catalog.to_regprocedure(pg_catalog.format('%I.%s', current_schema(), $3::text))
			)
			`, expected.name, expected.tgtype, expected.function).Scan(&intact)
		if err != nil || !intact {
			return fmt.Errorf("%w: Permit v9 write-once trigger %s disabled or changed: %v", ErrSchemaDrift, expected.name, err)
		}
	}
	// A valid migration checksum is insufficient if an administrator has
	// disabled the deferred causal claim/revoke guard. This must be an
	// always-on, constraint-backed AFTER UPDATE row trigger, deferred until
	// the entire Permit+Intent+Audit transaction is ready to commit.
	var causalIntact bool
	err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_trigger t
			WHERE t.tgrelid = pg_catalog.to_regclass(pg_catalog.format('%I.%I', current_schema(), 'guard_permits'))
			  AND t.tgname = 'guard_permit_causal_transition_v10'
			  AND t.tgtype = 17
			  AND NOT t.tgisinternal AND t.tgenabled = 'A'
			  AND t.tgqual IS NULL AND t.tgattr::text=''
			  AND t.tgdeferrable AND t.tginitdeferred
			  AND t.tgconstraint <> 0
			  AND t.tgfoid = pg_catalog.to_regprocedure(pg_catalog.format('%I.%I()', current_schema(), 'guard_permit_causal_transition_v10'))
		)
	`).Scan(&causalIntact)
	if err != nil || !causalIntact {
		return fmt.Errorf("%w: Permit v10 deferred causal journal trigger disabled or changed: %v",
			ErrSchemaDrift, err)
	}
	// A valid checksum does not prove that the v11 expiry guard still fires
	// at transaction end. Explicitly reject a disabled, non-deferred,
	// replacement, origin-only, or non-constraint trigger.
	var expiryIntact bool
	err = tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_trigger t
			WHERE t.tgrelid=pg_catalog.to_regclass(pg_catalog.format('%I.%I', current_schema(), 'guard_permits'))
			  AND t.tgname='guard_permit_claim_expiry_v11'
			  AND t.tgtype=17 AND NOT t.tgisinternal
			  AND t.tgenabled='A'
			  AND t.tgqual IS NULL AND t.tgattr::text=''
			  AND t.tgdeferrable AND t.tginitdeferred
			  AND t.tgconstraint <> 0
			  AND t.tgfoid=pg_catalog.to_regprocedure(pg_catalog.format('%I.%I()', current_schema(), 'guard_permit_claim_expiry_v11'))
		)
	`).Scan(&expiryIntact)
	if err != nil || !expiryIntact {
		return fmt.Errorf("%w: Permit v11 deferred expiry trigger disabled or changed: %v",
			ErrSchemaDrift, err)
	}
	// The INSERT-only issuer cannot create a CLAIMED or pre-revoked row.
	// A disabled/replaced or origin-only trigger invalidates the entire
	// ledger at startup even when migration checksums are unchanged.
	var initialStateIntact bool
	err = tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_trigger t
			WHERE t.tgrelid=pg_catalog.to_regclass(pg_catalog.format('%I.%I', current_schema(), 'guard_permits'))
			  AND t.tgname='guard_permit_initial_state_v12'
			  AND t.tgtype=7 AND NOT t.tgisinternal
			  AND t.tgenabled='A'
			  AND t.tgqual IS NULL AND t.tgattr::text=''
			  AND t.tgfoid=pg_catalog.to_regprocedure(pg_catalog.format('%I.%I()', current_schema(), 'guard_permit_initial_state_v12'))
		)
	`).Scan(&initialStateIntact)
	if err != nil || !initialStateIntact {
		return fmt.Errorf("%w: Permit v12 initial INSERT state trigger disabled or changed: %v",
			ErrSchemaDrift, err)
	}
	return verifyPermitTriggerFunctions(ctx, tx)
}
