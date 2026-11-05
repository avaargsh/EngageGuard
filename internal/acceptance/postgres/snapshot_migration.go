package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"strings"
)

//go:embed schema_v2.sql
var snapshotSchema string

const snapshotMigrationVersion int64 = 2

// ErrSnapshotBackfillRequired blocks automatic adoption of v1 operations that
// have no authentic, immutable copy of their original exact submission bytes.
var ErrSnapshotBackfillRequired = errors.New("Guard v1 accepted records require operator-led recovery before snapshot migration")

// ErrSnapshotMissing/ErrSnapshotCorrupt are fail-closed; neither is permission
// to reconstruct an ActionRequest or issue a Permit.
var (
	ErrSnapshotMissing = errors.New("Guard accepted submission snapshot missing")
	ErrSnapshotCorrupt = errors.New("Guard accepted submission snapshot inconsistent")
)

func applySnapshotMigration(ctx context.Context, tx *sql.Tx) error {
	// SQL blocks are delimited explicitly, so PL/pgSQL semicolons are safe.
	for _, ddl := range strings.Split(snapshotSchema, "\n-- statement break\n") {
		if strings.TrimSpace(ddl) == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("install immutable Guard snapshot schema: %w", err)
		}
	}
	if err := verifySnapshotCatalog(ctx, tx); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(snapshotSchema))
	if _, err := tx.ExecContext(ctx, "INSERT INTO guard_schema_migrations (version,checksum) VALUES ($1,$2)",
		snapshotMigrationVersion, fmt.Sprintf("%x", sum)); err != nil {
		return fmt.Errorf("record Guard v2 migration checksum: %w", err)
	}
	return nil
}

func verifySnapshotCatalog(ctx context.Context, tx *sql.Tx) error {
	var valid bool
	err := tx.QueryRowContext(ctx, `
		SELECT to_regclass('guard_accepted_submission_snapshots') IS NOT NULL
			AND to_regprocedure('guard_reject_snapshot_mutation()') IS NOT NULL
	`).Scan(&valid)
	if err != nil || !valid {
		return fmt.Errorf("%w: missing accepted snapshot relation/function: %v", ErrSchemaDrift, err)
	}
	// The operation tuple, not merely an operation ID, is referenced by
	// snapshot rows. Wrongly rebound or dropped keys must block startup.
	for _, expected := range []struct {
		table, name, kind, cols, refTable, refCols string
	}{
		{"guard_action_operations", "guard_ops_snapshot_binding_uk", "u",
			"tenant_id,submission_key,submission_digest,operation_id", "", ""},
		{"guard_accepted_submission_snapshots", "guard_accepted_submission_snapshots_pkey", "p",
			"tenant_id,operation_id", "", ""},
		{"guard_accepted_submission_snapshots", "guard_snapshot_operation_binding_fk", "f",
			"tenant_id,submission_key,submission_digest,operation_id",
			"guard_action_operations", "tenant_id,submission_key,submission_digest,operation_id"},
		{"guard_accepted_submission_snapshots", "guard_snapshot_bytes_length_check", "c",
			"submission_bytes", "", ""},
	} {
		err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_constraint c
				WHERE c.conrelid=to_regclass($1) AND c.conname=$2
				  AND c.contype::text=$3 AND c.convalidated
				  AND NOT c.condeferrable AND NOT c.condeferred
				  AND (
				    SELECT string_agg(a.attname,',' ORDER BY k.ord)
				    FROM unnest(c.conkey) WITH ORDINALITY k(attnum,ord)
				    JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum
				  ) = $4
				  AND ($3 <> 'f' OR (
					c.confrelid=to_regclass($5)
				    AND (
				      SELECT string_agg(a.attname,',' ORDER BY k.ord)
				      FROM unnest(c.confkey) WITH ORDINALITY k(attnum,ord)
				      JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.attnum
				    )=$6
				  ))
			)
		`, expected.table, expected.name, expected.kind, expected.cols,
			expected.refTable, expected.refCols).Scan(&valid)
		if err != nil || !valid {
			return fmt.Errorf("%w: invalid snapshot constraint %s: %v", ErrSchemaDrift, expected.name, err)
		}
	}
	// A same-named disabled or rebound trigger is not immutable storage.
	err = tx.QueryRowContext(ctx, `
		SELECT EXISTS (
		  SELECT 1 FROM pg_trigger t
		  WHERE t.tgrelid=to_regclass('guard_accepted_submission_snapshots')
		    AND t.tgname='guard_snapshot_immutable_row'
		    AND NOT t.tgisinternal AND t.tgenabled='O'
		    AND t.tgtype=27
		    AND t.tgqual IS NULL
		    AND t.tgattr::text=''
		    AND t.tgfoid=to_regprocedure('guard_reject_snapshot_mutation()')
		)
	`).Scan(&valid)
	if err != nil || !valid {
		return fmt.Errorf("%w: disabled or replaced snapshot immutability trigger: %v", ErrSchemaDrift, err)
	}
	// TRUNCATE bypasses row-level triggers. The statement trigger must be
	// enabled as well or a privileged writer can erase all accepted evidence.
	err = tx.QueryRowContext(ctx, `
		SELECT EXISTS (
		  SELECT 1 FROM pg_trigger t
		  WHERE t.tgrelid=to_regclass('guard_accepted_submission_snapshots')
		    AND t.tgname='guard_snapshot_immutable_truncate'
		    AND NOT t.tgisinternal AND t.tgenabled='O'
		    AND t.tgtype=34
		    AND t.tgqual IS NULL
		    AND t.tgattr::text=''
		    AND t.tgfoid=to_regprocedure('guard_reject_snapshot_mutation()')
		)
	`).Scan(&valid)
	if err != nil || !valid {
		return fmt.Errorf("%w: missing or disabled snapshot TRUNCATE trigger: %v", ErrSchemaDrift, err)
	}
	// A matching constraint name/column is insufficient: reject weaker
	// same-name expressions, including CHECK(TRUE), on every startup.
	var checkExpr string
	err = tx.QueryRowContext(ctx, `
		SELECT pg_get_expr(c.conbin, c.conrelid)
		FROM pg_constraint c
		WHERE c.conrelid=to_regclass('guard_accepted_submission_snapshots')
		  AND c.conname='guard_snapshot_bytes_length_check'
	`).Scan(&checkExpr)
	if err != nil {
		return fmt.Errorf("%w: inspect snapshot size check: %v", ErrSchemaDrift, err)
	}
	normalized := strings.NewReplacer("(", "", ")", "", " ", "", "\n", "").Replace(checkExpr)
	if normalized != "octet_lengthsubmission_bytes>=1ANDoctet_lengthsubmission_bytes<=65536" {
		return fmt.Errorf("%w: weakened accepted snapshot size expression", ErrSchemaDrift)
	}
	// A same-named enabled trigger must still execute the exact immutable
	// implementation, not a replaced no-op function.
	var functionBody string
	err = tx.QueryRowContext(ctx, `
		SELECT p.prosrc FROM pg_proc p
		WHERE p.oid=to_regprocedure('guard_reject_snapshot_mutation()')
	`).Scan(&functionBody)
	if err != nil || strings.TrimSpace(functionBody) != "BEGIN\n    RAISE EXCEPTION 'accepted Guard submission snapshots are immutable';\nEND;" {
		return fmt.Errorf("%w: snapshot mutation trigger function changed: %v", ErrSchemaDrift, err)
	}
	// At least retain exact BYTEA type, NOT NULL, and the CHECK name/column.
	err = tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_attribute a
			WHERE a.attrelid=to_regclass('guard_accepted_submission_snapshots')
			  AND a.attname='submission_bytes'
			  AND a.atttypid='bytea'::regtype AND a.attnotnull AND NOT a.attisdropped
		)
	`).Scan(&valid)
	if err != nil || !valid {
		return fmt.Errorf("%w: invalid accepted submission bytes column: %v", ErrSchemaDrift, err)
	}
	return nil
}
