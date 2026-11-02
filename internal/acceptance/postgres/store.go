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

	var currentVersionCount int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM guard_schema_migrations").Scan(&currentVersionCount); err != nil {
		return fmt.Errorf("inspect Guard migration history: %w", err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(initialSchema)))
	if currentVersionCount > 0 {
		var existing string
		if currentVersionCount != 1 {
			return ErrSchemaDrift
		}
		if err := tx.QueryRowContext(ctx,
			"SELECT checksum FROM guard_schema_migrations WHERE version=$1",
			initialMigrationVersion,
		).Scan(&existing); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrSchemaDrift
			}
			return fmt.Errorf("read Guard schema checksum: %w", err)
		}
		if existing != digest {
			return ErrSchemaDrift
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit Guard schema verification: %w", err)
		}
		return nil
	}

	// Never silently assign canonical status to an existing unmanaged
	// installation. An operator must inspect/upgrade it explicitly.
	var hasUnversionedRelations bool
	if err := tx.QueryRowContext(ctx, `
		SELECT to_regclass('guard_action_operations') IS NOT NULL
		    OR to_regclass('guard_outbox_events') IS NOT NULL
	`).Scan(&hasUnversionedRelations); err != nil {
		return fmt.Errorf("inspect unversioned Guard relations: %w", err)
	}
	if hasUnversionedRelations {
		return ErrUnversionedSchema
	}
	// This initial SQL consists only of fixed DDL statements; future
	// migrations must be separate immutable, checksummed versions.
	for _, statement := range strings.Split(initialSchema, ";") {
		if strings.TrimSpace(statement) == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("install Guard admission schema: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO guard_schema_migrations (version, checksum) VALUES ($1, $2)",
		initialMigrationVersion, digest,
	); err != nil {
		return fmt.Errorf("record Guard schema checksum: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit Guard schema migration: %w", err)
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
