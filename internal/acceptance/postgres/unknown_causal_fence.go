package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Verify the executable catalog, not just the stored migration checksum.
func verifyUnknownCausalFence(ctx context.Context, tx *sql.Tx) error {
	const prefix = "CREATE FUNCTION guard_unknown_causal_commit_v15() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(permitUnknownCausalSchema, prefix) != 1 {
		return fmt.Errorf("%w: invalid v15 UNKNOWN causal function source", ErrSchemaDrift)
	}
	body := strings.SplitN(permitUnknownCausalSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v15 UNKNOWN causal function", ErrSchemaDrift)
	}
	var actualBody string
	var safe bool
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
			pg_catalog.format('%I.%I()', current_schema(), 'guard_unknown_causal_commit_v15'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_unknown_causal_commit_v15()')
	`).Scan(&actualBody, &safe)
	if err != nil || !safe || actualBody != body[:end] {
		return fmt.Errorf("%w: v15 UNKNOWN causal function drift: %v", ErrSchemaDrift, err)
	}
	for _, trigger := range []struct {
		table, name string
		kind        int
	}{
		{"guard_operation_intents", "guard_intent_unknown_commit_v15", 21},
		{"guard_operation_unknown_events", "guard_unknown_journal_commit_v15", 5},
	} {
		var intact bool
		err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger t
				WHERE t.tgrelid=pg_catalog.to_regclass($1)
				  AND t.tgname=$2 AND t.tgtype=$3
				  AND t.tgenabled='A' AND NOT t.tgisinternal
				  AND t.tgdeferrable AND t.tginitdeferred
				  AND t.tgqual IS NULL AND t.tgattr::text=''
				  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
				  AND t.tgfoid=pg_catalog.to_regprocedure('guard_unknown_causal_commit_v15()')
			)
		`, trigger.table, trigger.name, trigger.kind).Scan(&intact)
		if err != nil || !intact {
			return fmt.Errorf("%w: v15 UNKNOWN trigger %s drift: %v", ErrSchemaDrift, trigger.name, err)
		}
	}
	var consistent bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1 FROM guard_operation_intents i
			LEFT JOIN guard_operation_unknown_events e
			  ON e.tenant_id=i.tenant_id AND e.attempt_id=i.attempt_id
			WHERE (i.state='DISPATCHING' AND e.attempt_id IS NOT NULL)
			   OR (i.state='UNKNOWN' AND (e.attempt_id IS NULL
			       OR e.operation_id IS DISTINCT FROM i.operation_id
			       OR e.permit_id IS DISTINCT FROM i.permit_id
			       OR e.action_hash IS DISTINCT FROM i.action_hash))
			   OR i.state NOT IN ('DISPATCHING','UNKNOWN')
		) AND NOT EXISTS (
			SELECT 1 FROM guard_operation_unknown_events e
			WHERE NOT EXISTS (
				SELECT 1 FROM guard_operation_intents i
				WHERE i.tenant_id=e.tenant_id AND i.attempt_id=e.attempt_id
			)
		)
	`).Scan(&consistent); err != nil || !consistent {
		return fmt.Errorf("%w: v15 UNKNOWN causal graph corrupt: %v", ErrSchemaDrift, err)
	}
	return nil
}
