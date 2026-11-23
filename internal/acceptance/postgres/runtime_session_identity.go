package postgres

import (
	"context"
	"database/sql"
	"fmt"
)

// beginGuardRuntimeTx binds every Guard ledger operation to one physical
// PostgreSQL session and refuses session-local table/index aliases before
// accessing any protected relation. Migrate() checks schema at startup, but
// a pooled session may later acquire pg_temp shadows independently. An
// in-session check must therefore precede every trusted ledger transaction.
//
// This is necessary-only defense: the database principal must also lack
// unsafe schema DDL/TEMP privileges, and privileged effect execution is
// still gated by independent issuer/PEP/reconciliation controls.
func beginGuardRuntimeTx(ctx context.Context, db *sql.DB) (*sql.Tx, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	// All relations belong to the PostgreSQL schema selected by the
	// deployment connection. pg_temp implicitly takes search precedence
	// for relations even when it does not appear in search_path.
	const query = `
		SELECT COALESCE(pg_catalog.bool_and(
			pg_catalog.to_regclass(
				pg_catalog.format('%I.%I', pg_catalog.current_schema(), r.name)
			) IS NOT NULL
			AND pg_catalog.to_regclass(r.name) =
				pg_catalog.to_regclass(
					pg_catalog.format('%I.%I', pg_catalog.current_schema(), r.name)
				)
		), false)
		FROM (VALUES
			('guard_schema_migrations'),
			('guard_action_operations'),
			('guard_outbox_events'),
			('guard_outbox_unpublished_idx'),
			('guard_accepted_submission_snapshots'),
			('guard_permits'),
			('guard_operation_intents'),
			('guard_execution_audit'),
			('guard_operation_unknown_events'),
			('guard_permit_revocations')
		) AS r(name)
	`
	var safe bool
	if err := tx.QueryRowContext(ctx, query).Scan(&safe); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("%w: inspect runtime PostgreSQL relation identity: %v", ErrSchemaDrift, err)
	}
	if !safe {
		_ = tx.Rollback()
		return nil, fmt.Errorf("%w: runtime PostgreSQL session relation identity is unavailable or shadowed", ErrSchemaDrift)
	}
	return tx, nil
}
