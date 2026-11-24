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
// All v4-v11 extensions are forward-only and retain historical checksums.
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
var permitCausalCommitSchema string

//go:embed schema_permit_v11.sql
var permitCausalPinnedSchema string

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
		{10, permitCausalCommitSchema},
		{11, permitCausalPinnedSchema},
	}
	// An existing v10 database must pass its original integrity checks before
	// replacing the function; never silently bless a tampered baseline.
	if applied == 10 {
		if err := verifyPermitLedgerCatalog(ctx, tx, permitCausalCommitSchema); err != nil {
			return err
		}
	}
	for _, item := range migrations {
		if applied >= int(item.version) {
			continue
		}
		// v4-v8 use plain DDL; v9+ trigger functions contain semicolons.
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
	return verifyPermitLedgerCatalog(ctx, tx, permitCausalPinnedSchema)
}

func verifyPermitLedgerCatalog(ctx context.Context, tx *sql.Tx, causalSource string) error {
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
					  AND t.tgqual IS NULL AND t.tgattr::text=''
					  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
					  AND NOT t.tgdeferrable AND NOT t.tginitdeferred
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
			    AND t.tgqual IS NULL AND t.tgattr::text=''
			    AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
			    AND NOT t.tgdeferrable AND NOT t.tginitdeferred
			    AND t.tgfoid=to_regprocedure($3)
			)
			`, expected.name, expected.tgtype, expected.function).Scan(&intact)
		if err != nil || !intact {
			return fmt.Errorf("%w: Permit v9 write-once trigger %s disabled or changed: %v", ErrSchemaDrift, expected.name, err)
		}
	}
	// The v9 write-once function can be replaced without changing its OID.
	// Compare its original body and security attributes before trusting it.
	if err := verifyPermitV9ImmutableFunction(ctx, tx); err != nil {
		return err
	}
	// Attest the exact function body shipped in the applicable immutable migration.
	// CREATE OR REPLACE FUNCTION can retain the OID while removing enforcement.
	prefix := "CREATE FUNCTION guard_claim_causal_commit_v10() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if causalSource == permitCausalPinnedSchema {
		prefix = "CREATE OR REPLACE FUNCTION guard_claim_causal_commit_v10() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	}
	if strings.Count(causalSource, prefix) != 1 {
		return fmt.Errorf("%w: missing or ambiguous v10 causal function source", ErrSchemaDrift)
	}
	body := strings.SplitN(causalSource, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v10 causal function source", ErrSchemaDrift)
	}
	var actualBody string
	var attributesSafe bool
	err := tx.QueryRowContext(ctx, `
		SELECT p.prosrc,
		       NOT p.prosecdef AND NOT p.proleakproof
		       AND p.provolatile='v' AND NOT p.proisstrict
		       AND p.proparallel='u' AND p.proconfig IS NULL
		       AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
		       AND p.pronamespace=current_schema()::regnamespace
		       AND p.prorettype='pg_catalog.trigger'::regtype AND p.pronargs=0
		FROM pg_catalog.pg_proc p
		WHERE p.oid=pg_catalog.to_regprocedure(
			pg_catalog.format('%I.%I()', current_schema(), 'guard_claim_causal_commit_v10'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_claim_causal_commit_v10()')
	`).Scan(&actualBody, &attributesSafe)
	if err != nil || !attributesSafe || actualBody != body[:end] {
		return fmt.Errorf("%w: v10 causal function definition or security attributes drifted: %v", ErrSchemaDrift, err)
	}
	// A function name or migration checksum is not an enforcement gate.
	// Verify both initially deferred, enabled-always constraint triggers
	// still invoke the attested causal function, not a substitute.
	for _, trigger := range []struct {
		table, name string
	}{
		{"guard_permits", "guard_permit_causal_commit_v10"},
		{"guard_operation_intents", "guard_intent_causal_commit_v10"},
	} {
		var intact bool
		err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger t
				WHERE t.tgrelid=to_regclass($1)
				  AND t.tgname=$2 AND t.tgtype=21
				  AND t.tgenabled='A' AND NOT t.tgisinternal
				  AND t.tgdeferrable AND t.tginitdeferred
				  AND t.tgqual IS NULL AND t.tgattr::text=''
				  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
				  AND t.tgfoid=to_regprocedure('guard_claim_causal_commit_v10()')
			)
		`, trigger.table, trigger.name).Scan(&intact)
		if err != nil || !intact {
			return fmt.Errorf("%w: Guard v10 deferred causal trigger %s invalid: %v",
				ErrSchemaDrift, trigger.name, err)
		}
	}
	// Constraint triggers are not retroactive. Validate already-committed
	// data again at every startup; migration v10 itself also rejects drift.
	var consistent bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1 FROM guard_permits p WHERE p.state='CLAIMED'
			  AND NOT EXISTS (
				SELECT 1 FROM guard_operation_intents i
				JOIN guard_execution_audit a
				  ON a.tenant_id=i.tenant_id
				 AND a.operation_id=i.operation_id
				 AND a.permit_id=i.permit_id
				 AND a.attempt_id=i.attempt_id
				 AND a.action_hash=i.action_hash
				 AND a.event_type='guard.operation.dispatching.v1'
				WHERE i.tenant_id=p.tenant_id
				  AND i.operation_id=p.operation_id
				  AND i.permit_id=p.permit_id
				  AND i.action_hash=p.action_hash
				  AND i.binding_digest=p.binding_digest
			  )
		) AND NOT EXISTS (
			SELECT 1 FROM guard_operation_intents i WHERE NOT EXISTS (
				SELECT 1 FROM guard_permits p
				JOIN guard_execution_audit a
				  ON a.tenant_id=i.tenant_id
				 AND a.operation_id=i.operation_id
				 AND a.permit_id=i.permit_id
				 AND a.attempt_id=i.attempt_id
				 AND a.action_hash=i.action_hash
				 AND a.event_type='guard.operation.dispatching.v1'
				WHERE p.tenant_id=i.tenant_id
				  AND p.operation_id=i.operation_id
				  AND p.permit_id=i.permit_id
				  AND p.action_hash=i.action_hash
				  AND p.binding_digest=i.binding_digest
				  AND p.state='CLAIMED'
			)
		)
	`).Scan(&consistent); err != nil || !consistent {
		return fmt.Errorf("%w: Guard v10 claimed Permit/Intent/Audit graph corrupt: %v",
			ErrSchemaDrift, err)
	}
	return nil
}

func verifyPermitV9ImmutableFunction(ctx context.Context, tx *sql.Tx) error {
	const prefix = "CREATE FUNCTION guard_permit_immutable_row_v9() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(permitIdentityFenceSchema, prefix) != 1 {
		return fmt.Errorf("%w: missing or ambiguous v9 immutable function source", ErrSchemaDrift)
	}
	body := strings.SplitN(permitIdentityFenceSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v9 immutable function source", ErrSchemaDrift)
	}
	var actualBody string
	var attributesSafe bool
	err := tx.QueryRowContext(ctx, `
		SELECT p.prosrc,
		       NOT p.prosecdef AND NOT p.proleakproof
		       AND p.provolatile='v' AND NOT p.proisstrict
		       AND p.proparallel='u' AND p.proconfig IS NULL
		       AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
		       AND p.pronamespace=current_schema()::regnamespace
		       AND p.prorettype='pg_catalog.trigger'::regtype AND p.pronargs=0
		FROM pg_catalog.pg_proc p
		WHERE p.oid=pg_catalog.to_regprocedure(
			pg_catalog.format('%I.%I()', current_schema(), 'guard_permit_immutable_row_v9'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_permit_immutable_row_v9()')
	`).Scan(&actualBody, &attributesSafe)
	if err != nil || !attributesSafe || actualBody != body[:end] {
		return fmt.Errorf("%w: v9 immutable function definition or security attributes drifted: %v", ErrSchemaDrift, err)
	}
	return nil
}
