package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Verify the executable catalog, not just the stored migration checksum.
func verifyPermitRevocationCausalFence(ctx context.Context, tx *sql.Tx) error {
	const prefix = "CREATE FUNCTION guard_revocation_causal_commit_v14() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(permitRevocationCausalSchema, prefix) != 1 {
		return fmt.Errorf("%w: invalid v14 revocation causal function source", ErrSchemaDrift)
	}
	body := strings.SplitN(permitRevocationCausalSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v14 revocation causal function", ErrSchemaDrift)
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
			pg_catalog.format('%I.%I()', current_schema(), 'guard_revocation_causal_commit_v14'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_revocation_causal_commit_v14()')
	`).Scan(&actualBody, &safe)
	if err != nil || !safe || actualBody != body[:end] {
		return fmt.Errorf("%w: v14 revocation causal function drift: %v", ErrSchemaDrift, err)
	}
	for _, trigger := range []struct {
		table, name string
		kind        int
	}{
		{"guard_permits", "guard_permit_revocation_commit_v14", 17},
		{"guard_permit_revocations", "guard_revocation_journal_commit_v14", 5},
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
				  AND t.tgfoid=pg_catalog.to_regprocedure('guard_revocation_causal_commit_v14()')
			)
		`, trigger.table, trigger.name, trigger.kind).Scan(&intact)
		if err != nil || !intact {
			return fmt.Errorf("%w: v14 revocation trigger %s drift: %v", ErrSchemaDrift, trigger.name, err)
		}
	}
	var consistent bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1 FROM guard_permits p
			LEFT JOIN guard_permit_revocations r
			  ON r.tenant_id=p.tenant_id AND r.permit_id=p.permit_id
			WHERE (p.revoked_at IS NULL AND r.permit_id IS NOT NULL)
			   OR (p.revoked_at IS NOT NULL AND
			       (r.permit_id IS NULL OR r.prior_state IS DISTINCT FROM p.state))
		)
	`).Scan(&consistent); err != nil || !consistent {
		return fmt.Errorf("%w: v14 revocation causal graph corrupt: %v", ErrSchemaDrift, err)
	}
	return nil
}
