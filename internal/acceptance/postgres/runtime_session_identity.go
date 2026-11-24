package postgres

import (
	"context"
	"database/sql"
	"fmt"
)

// beginLedgerTx checks authority on the same physical session used for the
// ensuing ledger operation. Startup Migrate cannot attest later pool sessions.
// Explicitly provisioned schema identity is preferred; the legacy New
// constructor retains the connection's reset search_path for compatibility
// only. Production still requires trusted configuration and separate DDL roles.
func (s *Store) beginLedgerTx(ctx context.Context, permit bool) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	var safe bool
	err = tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_settings s
			WHERE s.name='search_path' AND s.setting=s.reset_val
			  AND pg_catalog.current_schema() IS NOT NULL
			  AND ($1::text='' OR pg_catalog.current_schema()=$1::text)
		) AND COALESCE((
			SELECT pg_catalog.bool_and(
				c.oid IS NOT NULL
				AND c.relkind='r' AND c.relpersistence='p'
				AND c.relnamespace=pg_catalog.to_regnamespace(pg_catalog.current_schema())
				AND m.oid IS NOT NULL AND c.relowner=m.relowner
				AND pg_catalog.to_regclass(r.name) IS NOT DISTINCT FROM c.oid
			)
			FROM (VALUES
				('guard_schema_migrations',false),
				('guard_action_operations',false),
				('guard_outbox_events',false),
				('guard_accepted_submission_snapshots',false),
				('guard_permits',true),
				('guard_operation_intents',true),
				('guard_execution_audit',true),
				('guard_operation_unknown_events',true),
				('guard_permit_revocations',true)
			) AS r(name,permit_only)
			LEFT JOIN pg_catalog.pg_class c ON c.oid=pg_catalog.to_regclass(
				pg_catalog.format('%I.%I',pg_catalog.current_schema(),r.name))
			LEFT JOIN pg_catalog.pg_class m ON m.oid=pg_catalog.to_regclass(
				pg_catalog.format('%I.%I',pg_catalog.current_schema(),'guard_schema_migrations'))
			WHERE $2::boolean OR NOT r.permit_only
		),false)
	`, s.trustedSchema, permit).Scan(&safe)
	if err != nil || !safe {
		_ = tx.Rollback()
		return nil, fmt.Errorf("%w: runtime ledger relation identity: %v", ErrSchemaDrift, err)
	}
	return tx, nil
}
