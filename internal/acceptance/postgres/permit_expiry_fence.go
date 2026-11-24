package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Verify the executable catalog, not just the stored migration checksum.
func verifyPermitExpiryFence(ctx context.Context, tx *sql.Tx) error {
	const prefix = "CREATE FUNCTION guard_permit_claim_expiry_v12() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(permitExpiryFenceSchema, prefix) != 1 {
		return fmt.Errorf("%w: invalid v12 expiry function source", ErrSchemaDrift)
	}
	body := strings.SplitN(permitExpiryFenceSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v12 expiry function", ErrSchemaDrift)
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
			pg_catalog.format('%I.%I()', current_schema(), 'guard_permit_claim_expiry_v12'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_permit_claim_expiry_v12()')
	`).Scan(&actualBody, &safe)
	if err != nil || !safe || actualBody != body[:end] {
		return fmt.Errorf("%w: v12 expiry function drift: %v", ErrSchemaDrift, err)
	}
	var intact bool
	err = tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_trigger t
			WHERE t.tgrelid=pg_catalog.to_regclass('guard_permits')
			  AND t.tgname='guard_permit_claim_expiry_v12' AND t.tgtype=17
			  AND t.tgenabled='A' AND NOT t.tgisinternal
			  AND t.tgdeferrable AND t.tginitdeferred
			  AND t.tgqual IS NULL AND t.tgattr::text=''
			  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
			  AND t.tgfoid=pg_catalog.to_regprocedure('guard_permit_claim_expiry_v12()')
		)
	`).Scan(&intact)
	if err != nil || !intact {
		return fmt.Errorf("%w: v12 expiry trigger drift: %v", ErrSchemaDrift, err)
	}
	return nil
}
