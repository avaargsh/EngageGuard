package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// expectedPermitFunctionBody extracts the literal function body from the
// versioned migration source shipped with this binary. The exact v9-v12
// sources/checksums remain immutable; PostgreSQL retains the dollar-quoted
// body verbatim in pg_proc.prosrc.
//
// This intentionally compares exact bytes rather than only function name,
// OID, trigger binding or a SQL expression that a schema owner can replace
// in-place with CREATE OR REPLACE FUNCTION.
func expectedPermitFunctionBody(source, name string) (string, error) {
	const delimiter = "$guard$"
	prefix := "CREATE FUNCTION " + name + "() RETURNS trigger\nLANGUAGE plpgsql AS " + delimiter
	if strings.Count(source, prefix) != 1 {
		return "", fmt.Errorf("missing or ambiguous trusted Permit function source %s", name)
	}
	start := strings.Index(source, prefix) + len(prefix)
	remainder := source[start:]
	end := strings.Index(remainder, delimiter+";")
	if end < 0 {
		return "", fmt.Errorf("unterminated trusted Permit function body %s", name)
	}
	return remainder[:end], nil
}

// verifyPermitTriggerFunctions is a startup/migration catalog attestation,
// not a live atomic DDL/effect fence and not an authorization decision.
// It detects same-OID body replacement and unsafe function attributes for
// all Permit state-transition constraints (v9-v12).
func verifyPermitTriggerFunctions(ctx context.Context, tx *sql.Tx) error {
	for _, item := range []struct {
		name   string
		source string
	}{
		{"guard_permit_immutable_row_v9", permitIdentityFenceSchema},
		{"guard_permit_causal_transition_v10", permitCausalFenceSchema},
		{"guard_permit_claim_expiry_v11", permitCommitExpirySchema},
		{"guard_permit_initial_state_v12", permitInsertStateSchema},
	} {
		expected, err := expectedPermitFunctionBody(item.source, item.name)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrSchemaDrift, err)
		}
		var actual string
		var attributesSafe bool
		err = tx.QueryRowContext(ctx, `
			SELECT p.prosrc,
			       p.prosecdef = false
			       AND p.proleakproof = false
			       AND p.provolatile = 'v'
			       AND p.proisstrict = false
			       AND p.proparallel = 'u'
			       AND p.proconfig IS NULL
			       AND p.prolang = (
			           SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql'
			       )
			       AND p.pronamespace = current_schema()::regnamespace
			       AND p.prorettype = 'pg_catalog.trigger'::regtype
			       AND p.pronargs = 0
			FROM pg_catalog.pg_proc p
			WHERE p.oid = to_regprocedure($1)
		`, item.name+"()").Scan(&actual, &attributesSafe)
		if err != nil || !attributesSafe || actual != expected {
			return fmt.Errorf("%w: Permit trigger function %s definition or security attributes drifted: %v",
				ErrSchemaDrift, item.name, err)
		}
	}
	return nil
}
