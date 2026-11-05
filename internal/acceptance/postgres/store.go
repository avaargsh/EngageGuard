package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// ErrConflict indicates a tenant-scoped idempotency key was already accepted
// with different exact submission bytes; no new operation is created.
var ErrConflict = errors.New("Guard Idempotency-Key reused with a different submission")

var tenantIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

//go:embed schema.sql
var initialSchema string

// Migration versions and bytes are immutable after release. A journal's
// durability guarantees depend on a known PostgreSQL schema at every boot.
const initialMigrationVersion int64 = 1
const schemaMigrationLockKey int64 = 0x45474d494752

var (
	// ErrSchemaDrift means the database ledger contradicts this binary's
	// migration or contains a version this binary cannot interpret.
	ErrSchemaDrift = errors.New("Guard schema migration checksum/version mismatch")
	// ErrUnversionedSchema requires explicit operator-led adoption of an
	// existing schema, never automatic stamping of unknown DDL.
	ErrUnversionedSchema = errors.New("Guard schema exists without migration history")
)

// Migrate atomically installs and checks the admission-only schema. This
// serializes concurrent boot migrations within the PostgreSQL database;
// installation, version marker and checksum commit (or roll back) together.
// A schema migration is not authorization to dispatch any external action.
func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("database unavailable")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin Guard schema migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", schemaMigrationLockKey); err != nil {
		return fmt.Errorf("lock Guard schema migration: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS guard_schema_migrations (
			version BIGINT PRIMARY KEY,
			checksum TEXT NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("create Guard schema ledger: %w", err)
	}

	rows, err := tx.QueryContext(ctx, "SELECT version, checksum FROM guard_schema_migrations ORDER BY version")
	if err != nil {
		return fmt.Errorf("read Guard migration ledger: %w", err)
	}
	var applied []struct{ version int64; checksum string }
	for rows.Next() {
		var v int64
		var checksum string
		if err := rows.Scan(&v, &checksum); err != nil {
			rows.Close()
			return fmt.Errorf("read Guard migration entry: %w", err)
		}
		applied = append(applied, struct{ version int64; checksum string }{v, checksum})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return fmt.Errorf("read Guard migration entries: %w", err)
	}

	v1Checksum := fmt.Sprintf("%x", sha256.Sum256([]byte(initialSchema)))
	v2Checksum := fmt.Sprintf("%x", sha256.Sum256([]byte(snapshotSchema)))
	if len(applied) > 2 {
		return ErrSchemaDrift
	}
	for i, entry := range applied {
		expectedVersion, expectedChecksum := int64(1), v1Checksum
		if i == 1 {
			expectedVersion, expectedChecksum = snapshotMigrationVersion, v2Checksum
		}
		if entry.version != expectedVersion || entry.checksum != expectedChecksum {
			return ErrSchemaDrift
		}
	}

	if len(applied) == 0 {
		var unmanaged bool
		if err := tx.QueryRowContext(ctx, `
			SELECT to_regclass('guard_action_operations') IS NOT NULL
			    OR to_regclass('guard_outbox_events') IS NOT NULL
			    OR to_regclass('guard_accepted_submission_snapshots') IS NOT NULL
		`).Scan(&unmanaged); err != nil {
			return fmt.Errorf("inspect unversioned Guard relations: %w", err)
		}
		if unmanaged {
			return ErrUnversionedSchema
		}
		// The v1 bytes remain unchanged and are still checksummed separately.
		for _, statement := range strings.Split(initialSchema, ";") {
			if strings.TrimSpace(statement) == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("install Guard v1 admission schema: %w", err)
			}
		}
		if err := verifyGuardCatalog(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO guard_schema_migrations (version, checksum) VALUES ($1, $2)",
			initialMigrationVersion, v1Checksum); err != nil {
			return fmt.Errorf("record Guard v1 migration checksum: %w", err)
		}
	} else {
		if err := verifyGuardCatalog(ctx, tx); err != nil {
			return err
		}
	}

	if len(applied) < 2 {
		// No authentic exact bytes can be recovered from a v1 digest alone.
		// Never stamp old admitted operations as migrated to v2.
		var originalOperations int64
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM guard_action_operations").Scan(&originalOperations); err != nil {
			return fmt.Errorf("inspect v1 accepted operations before snapshot migration: %w", err)
		}
		if originalOperations != 0 {
			return ErrSnapshotBackfillRequired
		}
		if err := applySnapshotMigration(ctx, tx); err != nil {
			return err
		}
	} else if err := verifySnapshotCatalog(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit Guard versioned schema migration: %w", err)
	}
	return nil
}

// verifyGuardCatalog ensures a matching migration source checksum is not
// mistaken for proof that the current PostgreSQL schema is intact. This
// checks admission-critical constraints and the index used for outbox scans.
// It does not replace full production migration/backup review.
func verifyGuardCatalog(ctx context.Context, tx *sql.Tx) error {
	for _, relation := range []string{
		"guard_action_operations", "guard_outbox_events", "guard_outbox_unpublished_idx",
	} {
		var exists bool
		if err := tx.QueryRowContext(ctx, "SELECT to_regclass($1) IS NOT NULL", relation).Scan(&exists); err != nil {
			return fmt.Errorf("%w: inspect relation %s: %v", ErrSchemaDrift, relation, err)
		}
		if !exists {
			return fmt.Errorf("%w: missing relation %s", ErrSchemaDrift, relation)
		}
	}
	required := []struct {
		table, name, kind, columns string
		refTable, refColumns       string
	}{
		{"guard_action_operations", "guard_action_operations_pkey", "p", "operation_id", "", ""},
		{"guard_action_operations", "guard_action_operations_tenant_id_submission_key_key", "u", "tenant_id,submission_key", "", ""},
		{"guard_action_operations", "guard_action_operations_tenant_id_operation_id_key", "u", "tenant_id,operation_id", "", ""},
		{"guard_action_operations", "guard_action_operations_submission_digest_check", "c", "submission_digest", "", ""},
		{"guard_action_operations", "guard_action_operations_status_check", "c", "status", "", ""},
		{"guard_outbox_events", "guard_outbox_events_pkey", "p", "event_id", "", ""},
		{"guard_outbox_events", "guard_outbox_events_tenant_id_operation_id_event_type_key", "u", "tenant_id,operation_id,event_type", "", ""},
		{"guard_outbox_events", "guard_outbox_events_event_type_check", "c", "event_type", "", ""},
		{"guard_outbox_events", "guard_outbox_operation_fk", "f", "tenant_id,operation_id", "guard_action_operations", "tenant_id,operation_id"},
	}
	for _, expected := range required {
		var valid bool
		refTable := expected.refTable
		if refTable == "" {
			refTable = expected.table
		}
		err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_constraint AS c
				WHERE c.conrelid = to_regclass($1)
					AND c.conname = $2
					AND c.contype::text = $3
					AND c.convalidated
					AND NOT c.condeferrable
					AND NOT c.condeferred
					AND (
						SELECT string_agg(att.attname, ',' ORDER BY keys.ord)
						FROM unnest(c.conkey) WITH ORDINALITY AS keys(attnum, ord)
						JOIN pg_attribute AS att
						  ON att.attrelid = c.conrelid AND att.attnum = keys.attnum
					) = $4
					AND ($3 <> 'f' OR (
						c.confrelid = to_regclass($5)
						AND (
							SELECT string_agg(att.attname, ',' ORDER BY keys.ord)
							FROM unnest(c.confkey) WITH ORDINALITY AS keys(attnum, ord)
							JOIN pg_attribute AS att
							  ON att.attrelid = c.confrelid AND att.attnum = keys.attnum
						) = $6
					))
			)
		`, expected.table, expected.name, expected.kind, expected.columns,
			refTable, expected.refColumns).Scan(&valid)
		if err != nil {
			return fmt.Errorf("%w: inspect constraint %s: %v", ErrSchemaDrift, expected.name, err)
		}
		if !valid {
			return fmt.Errorf("%w: missing or misbound constraint %s", ErrSchemaDrift, expected.name)
		}
	}
	// A matching migration checksum and constraint name do not prove the
	// original CHECK expression is still in force. A changed pg_get_expr
	// is treated as drift, including across unreviewed major PG upgrades.
	var validCheckExpressions int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*)
		FROM (
			VALUES
				('guard_action_operations','guard_action_operations_status_check',
				 '(status = ''ACCEPTED''::text)'),
				('guard_action_operations','guard_action_operations_submission_digest_check',
				 '(submission_digest ~ ''^[0-9a-f]{64}$''::text)'),
				('guard_outbox_events','guard_outbox_events_event_type_check',
				 '(event_type = ''guard.submission.recorded.v1''::text)')
		) AS expected(table_name, constraint_name, check_expr)
		JOIN pg_constraint c
		  ON c.conrelid = to_regclass(expected.table_name)
		 AND c.conname = expected.constraint_name
		 AND c.contype = 'c'
		 AND c.convalidated
		 AND pg_get_expr(c.conbin,c.conrelid) = expected.check_expr
	`).Scan(&validCheckExpressions); err != nil {
		return fmt.Errorf("%w: inspect Guard CHECK definitions: %v", ErrSchemaDrift, err)
	}
	if validCheckExpressions != 3 {
		return fmt.Errorf("%w: Guard CHECK definition differs from v1 contract", ErrSchemaDrift)
	}
	var usableIndex bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_index AS i
			JOIN pg_class AS idx ON idx.oid = i.indexrelid
			JOIN pg_am AS am ON am.oid = idx.relam
			WHERE i.indrelid = to_regclass('guard_outbox_events')
			  AND idx.oid = to_regclass('guard_outbox_unpublished_idx')
			  AND i.indisvalid AND i.indisready AND i.indislive
			  AND NOT i.indisunique AND NOT i.indisprimary
			  AND i.indnkeyatts = 2 AND i.indnatts = 2
			  AND i.indexprs IS NULL AND i.indpred IS NULL
			  AND am.amname = 'btree'
			  AND (
				SELECT string_agg(att.attname, ',' ORDER BY keys.ord)
				FROM unnest(i.indkey) WITH ORDINALITY AS keys(attnum, ord)
				JOIN pg_attribute AS att
				  ON att.attrelid = i.indrelid AND att.attnum = keys.attnum
			  ) = 'occurred_at,event_id'
		)
	`).Scan(&usableIndex); err != nil {
		return fmt.Errorf("%w: inspect Guard outbox index: %v", ErrSchemaDrift, err)
	}
	if !usableIndex {
		return fmt.Errorf("%w: invalid Guard outbox index", ErrSchemaDrift)
	}
	return nil
}

// Operation is a durable acceptance receipt, not permission to execute.
type Operation struct {
	OperationID      string
	TenantID         string
	SubmissionKey    string
	SubmissionDigest string
	Status           string
}

type Store struct{ db *sql.DB }

func New(db *sql.DB) *Store { return &Store{db: db} }

// Accept must receive tenantID from a trusted authenticated principal, never
// from the untrusted ActionSubmission. Exactly one operation and one outbox
// event are committed per tenant/key. No external effects occur here.
func (s *Store) Accept(ctx context.Context, tenantID, submissionKey string, raw []byte) (Operation, bool, error) {
	if s == nil || s.db == nil {
		return Operation{}, false, errors.New("Guard admission database unavailable")
	}
	if !tenantIDPattern.MatchString(tenantID) {
		return Operation{}, false, errors.New("invalid authenticated tenant")
	}
	if err := action.ValidateSubmissionKey(submissionKey); err != nil {
		return Operation{}, false, err
	}
	digest, err := action.SubmissionDigest(raw)
	if err != nil {
		return Operation{}, false, err
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return Operation{}, false, fmt.Errorf("begin submission acceptance: %w", err)
	}
	defer tx.Rollback()

	op := Operation{TenantID: tenantID, SubmissionKey: submissionKey, SubmissionDigest: digest}
	err = tx.QueryRowContext(ctx, `
		INSERT INTO guard_action_operations (tenant_id, submission_key, submission_digest)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, submission_key) DO NOTHING
		RETURNING operation_id, status
	`, tenantID, submissionKey, digest).Scan(&op.OperationID, &op.Status)

	if errors.Is(err, sql.ErrNoRows) {
		var existingDigest string
		err = tx.QueryRowContext(ctx, `
			SELECT operation_id, submission_digest, status
			FROM guard_action_operations
			WHERE tenant_id=$1 AND submission_key=$2
		`, tenantID, submissionKey).Scan(&op.OperationID, &existingDigest, &op.Status)
		if err != nil {
			return Operation{}, false, fmt.Errorf("read committed Guard submission: %w", err)
		}
		if existingDigest != digest {
			return Operation{}, false, ErrConflict
		}
		// Never report a successful replay if the immutable original intent
		// cannot be recovered and verified against the accepted digest.
		if err := readAcceptedBytesTx(ctx, tx, op); err != nil {
			return Operation{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return Operation{}, false, fmt.Errorf("commit Guard replay read: %w", err)
		}
		return op, false, nil
	}
	if err != nil {
		return Operation{}, false, fmt.Errorf("claim Guard submission key: %w", err)
	}

	// Store exactly the bytes the caller submitted. The immutable snapshot,
	// operation receipt, and non-dispatchable outbox event commit atomically.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO guard_accepted_submission_snapshots
		    (tenant_id, operation_id, submission_key, submission_digest, submission_bytes)
		VALUES ($1, $2, $3, $4, $5)
	`, tenantID, op.OperationID, submissionKey, digest, raw); err != nil {
		return Operation{}, false, fmt.Errorf("persist immutable Guard accepted submission: %w", err)
	}

	// An accepted outbox notification cannot exist without the durable
	// operation intent; an outbox failure rolls the operation back.
	_, err = tx.ExecContext(ctx, `
		INSERT INTO guard_outbox_events (tenant_id, operation_id, event_type)
		VALUES ($1, $2, 'guard.submission.recorded.v1')
	`, tenantID, op.OperationID)
	if err != nil {
		return Operation{}, false, fmt.Errorf("append Guard accepted outbox: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Operation{}, false, fmt.Errorf("commit Guard acceptance: %w", err)
	}
	return op, true, nil
}
