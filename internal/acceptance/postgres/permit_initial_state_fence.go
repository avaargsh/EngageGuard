package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Verify the executable catalog, not just the stored migration checksum.
func verifyPermitInitialStateFence(ctx context.Context, tx *sql.Tx) error {
	const prefix = "CREATE FUNCTION guard_permit_initial_state_v13() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(permitInitialStateSchema, prefix) != 1 {
		return fmt.Errorf("%w: invalid v13 initial-state function source", ErrSchemaDrift)
	}
	body := strings.SplitN(permitInitialStateSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v13 initial-state function", ErrSchemaDrift)
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
			pg_catalog.format('%I.%I()', current_schema(), 'guard_permit_initial_state_v13'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_permit_initial_state_v13()')
	`).Scan(&actualBody, &safe)
	if err != nil || !safe || actualBody != body[:end] {
		return fmt.Errorf("%w: v13 initial-state function drift: %v", ErrSchemaDrift, err)
	}
	var intact bool
	err = tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_trigger t
			WHERE t.tgrelid=pg_catalog.to_regclass('guard_permits')
			  AND t.tgname='guard_permit_initial_state_v13' AND t.tgtype=7
			  AND t.tgenabled='A' AND NOT t.tgisinternal
			  AND NOT t.tgdeferrable AND NOT t.tginitdeferred
			  AND t.tgqual IS NULL AND t.tgattr::text=''
			  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
			  AND t.tgfoid=pg_catalog.to_regprocedure('guard_permit_initial_state_v13()')
		)
	`).Scan(&intact)
	if err != nil || !intact {
		return fmt.Errorf("%w: v13 initial-state trigger drift: %v", ErrSchemaDrift, err)
	}
	var consistent bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1 FROM guard_permits p
			WHERE p.revoked_at IS NOT NULL AND NOT EXISTS (
				SELECT 1 FROM guard_permit_revocations r
				WHERE r.tenant_id=p.tenant_id AND r.permit_id=p.permit_id
			)
		)
	`).Scan(&consistent); err != nil || !consistent {
		return fmt.Errorf("%w: revoked Permit lacks durable revocation evidence: %v", ErrSchemaDrift, err)
	}
	return nil
}
