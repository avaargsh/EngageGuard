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

//go:embed schema_v2.sql
var permitSchema string

//go:embed schema_v3.sql
var ledgerIntegritySchema string

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

// Migrate serializes schema installation in one transaction. Version 1
// bytes are unchanged; version 2 introduces the internal pre-dispatch
// Permit/Intent/Audit ledger, and v3 binds the same operation and hash across
// all three tables. Versions and checksums are fail-closed.
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
	rows, err := tx.QueryContext(ctx, "SELECT version, checksum FROM guard_schema_migrations")
	if err != nil {
		return fmt.Errorf("read Guard migration history: %w", err)
	}
	applied := make(map[int64]string)
	for rows.Next() {
		var version int64
		var digest string
		if err := rows.Scan(&version, &digest); err != nil {
			rows.Close()
			return fmt.Errorf("scan Guard migration history: %w", err)
		}
		applied[version] = digest
	}
	readErr := rows.Err()
	closeErr := rows.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return fmt.Errorf("finish Guard migration history: %w", err)
	}
	migrations := []struct {
		version int64
		source string
	}{
		{initialMigrationVersion, initialSchema},
		{2, permitSchema},
		{3, ledgerIntegritySchema},
	}
	if len(applied) > len(migrations) {
		return ErrSchemaDrift
	}
	for _, item := range migrations {
		digest := fmt.Sprintf("%x", sha256.Sum256([]byte(item.source)))
		if existing, ok := applied[item.version]; ok && existing != digest {
			return ErrSchemaDrift
		}
	}
	// Never run a future binary against an unknown or non-prefix history.
	for version := range applied {
		if version < initialMigrationVersion || version > int64(len(migrations)) {
			return ErrSchemaDrift
		}
		if version > 1 {
			if _, ok := applied[version-1]; !ok {
				return ErrSchemaDrift
			}
		}
	}
	if len(applied) == 0 {
		var existing bool
		if err := tx.QueryRowContext(ctx, `
			SELECT to_regclass('guard_action_operations') IS NOT NULL
			    OR to_regclass('guard_outbox_events') IS NOT NULL
			    OR to_regclass('guard_permits') IS NOT NULL
			    OR to_regclass('guard_operation_intents') IS NOT NULL
			    OR to_regclass('guard_execution_audit') IS NOT NULL
		`).Scan(&existing); err != nil {
			return fmt.Errorf("inspect unversioned Guard relations: %w", err)
		}
		if existing {
			return ErrUnversionedSchema
		}
	}
	for _, item := range migrations {
		if _, ok := applied[item.version]; ok {
			continue
		}
		// Only fixed, semicolon-separated DDL is allowed in these versions.
		// A future migration with PL/pgSQL must use a different runner.
		for _, stmt := range strings.Split(item.source, ";") {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("install Guard migration %d: %w", item.version, err)
			}
		}
		digest := fmt.Sprintf("%x", sha256.Sum256([]byte(item.source)))
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO guard_schema_migrations (version, checksum) VALUES ($1,$2)",
			item.version, digest,
		); err != nil {
			return fmt.Errorf("record Guard migration %d checksum: %w", item.version, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit Guard schema migrations: %w", err)
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
		if err := tx.Commit(); err != nil {
			return Operation{}, false, fmt.Errorf("commit Guard replay read: %w", err)
		}
		return op, false, nil
	}
	if err != nil {
		return Operation{}, false, fmt.Errorf("claim Guard submission key: %w", err)
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
