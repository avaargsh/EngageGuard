package postgres

import (
	"context"
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

// Migrate installs the first admission-only schema in the current database
// search_path. A versioned, checksummed migration runner remains P0 release work.
func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("database unavailable")
	}
	// pgx uses the extended query protocol by default, which requires
	// one statement per Exec. These three fixed DDL statements have no
	// procedural bodies; a versioned migration runner will supersede this.
	for _, statement := range strings.Split(initialSchema, ";") {
		if strings.TrimSpace(statement) == "" {
			continue
		}
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("install Guard admission schema: %w", err)
		}
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
		VALUES ($1, $2, 'guard.operation.accepted.v1')
	`, tenantID, op.OperationID)
	if err != nil {
		return Operation{}, false, fmt.Errorf("append Guard accepted outbox: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Operation{}, false, fmt.Errorf("commit Guard acceptance: %w", err)
	}
	return op, true, nil
}
