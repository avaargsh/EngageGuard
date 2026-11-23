package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// AcceptedSubmission is a recovery-only view of untrusted original intent.
// It is NOT a resolved ActionRequest, approval, Permit or executable receipt.
type AcceptedSubmission struct {
	Operation Operation
	Raw       []byte
}

func verifyOriginalSubmission(raw []byte, expectedDigest string) error {
	digest, err := action.SubmissionDigest(raw)
	if err != nil || digest != expectedDigest {
		return ErrSnapshotCorrupt
	}
	return nil
}

func readAcceptedBytesTx(ctx context.Context, tx *sql.Tx, op Operation) error {
	var raw []byte
	err := tx.QueryRowContext(ctx, `
		SELECT submission_bytes
		FROM guard_accepted_submission_snapshots
		WHERE tenant_id=$1 AND operation_id=$2 AND submission_key=$3 AND submission_digest=$4
	`, op.TenantID, op.OperationID, op.SubmissionKey, op.SubmissionDigest).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrSnapshotMissing
	}
	if err != nil {
		return fmt.Errorf("read Guard accepted submission replay snapshot: %w", err)
	}
	return verifyOriginalSubmission(raw, op.SubmissionDigest)
}

// ReadAcceptedSubmission retrieves the exact accepted bytes with an authenticated
// tenant scope. Callers MUST separately reverify Run/Plan/Step authorization;
// restoring this record never authorizes any external side effect.
func (s *Store) ReadAcceptedSubmission(ctx context.Context, tenantID, operationID string) (AcceptedSubmission, error) {
	if s == nil || s.db == nil || ctx == nil {
		return AcceptedSubmission{}, errors.New("Guard admission database unavailable")
	}
	if !tenantIDPattern.MatchString(tenantID) || operationID == "" {
		return AcceptedSubmission{}, ErrSnapshotMissing
	}
	// Bind trusted acceptance evidence to a checked physical PostgreSQL
	// session. A pool can acquire pg_temp Operation/Snapshot lookalikes
	// after migration and must never return a temporary ACCEPTED source
	// as evidence for protected Permit issuance.
	tx, err := beginGuardRuntimeTx(ctx, s.db)
	if err != nil {
		return AcceptedSubmission{}, fmt.Errorf("inspect Guard accepted source relation identity: %w", err)
	}
	defer tx.Rollback()
	if s.trustedSchema == "" {
		return AcceptedSubmission{}, fmt.Errorf("%w: authoritative accepted-source schema not configured", ErrSchemaDrift)
	}
	var safe bool
	err = tx.QueryRowContext(ctx, `
		SELECT EXISTS (
		    SELECT 1 FROM pg_catalog.pg_settings s
		    WHERE s.name='search_path' AND s.setting=s.reset_val
		      AND pg_catalog.current_schema() = $1::text
		) AND COALESCE((
		    SELECT pg_catalog.bool_and(
		        c.oid IS NOT NULL
		        AND c.relkind = 'r' AND c.relpersistence = 'p'
		        AND c.relnamespace = pg_catalog.to_regnamespace($1::text)
		        AND m.oid IS NOT NULL AND c.relowner = m.relowner
		        AND pg_catalog.to_regclass(r.name) = c.oid
		    )
		    FROM (VALUES ('guard_schema_migrations'),
		                 ('guard_action_operations'),
		                 ('guard_accepted_submission_snapshots')) AS r(name)
		    LEFT JOIN pg_catalog.pg_class c ON c.oid =
		        pg_catalog.to_regclass(
		            pg_catalog.format('%I.%I',$1::text,r.name)
		        )
		    LEFT JOIN pg_catalog.pg_class m ON m.oid =
		        pg_catalog.to_regclass(
		            pg_catalog.format('%I.%I',$1::text,'guard_schema_migrations')
		        )
		), false)
	`, s.trustedSchema).Scan(&safe)
	if err != nil || !safe {
		return AcceptedSubmission{}, fmt.Errorf("%w: accepted source runtime schema identity: %v", ErrSchemaDrift, err)
	}
	var out AcceptedSubmission
	out.Operation.TenantID = tenantID
	out.Operation.OperationID = operationID
	err = tx.QueryRowContext(ctx, `
		SELECT o.submission_key, o.submission_digest, o.status, s.submission_bytes
		FROM guard_action_operations o
		JOIN guard_accepted_submission_snapshots s
		  ON s.tenant_id=o.tenant_id AND s.operation_id=o.operation_id
		 AND s.submission_key=o.submission_key AND s.submission_digest=o.submission_digest
		WHERE o.tenant_id=$1 AND o.operation_id=$2
	`, tenantID, operationID).Scan(&out.Operation.SubmissionKey,
		&out.Operation.SubmissionDigest, &out.Operation.Status, &out.Raw)
	if errors.Is(err, sql.ErrNoRows) {
		return AcceptedSubmission{}, ErrSnapshotMissing
	}
	if err != nil {
		return AcceptedSubmission{}, fmt.Errorf("read durable Guard accepted submission: %w", err)
	}
	if out.Operation.Status != "ACCEPTED" {
		return AcceptedSubmission{}, ErrSnapshotCorrupt
	}
	if err := verifyOriginalSubmission(out.Raw, out.Operation.SubmissionDigest); err != nil {
		return AcceptedSubmission{}, err
	}
	if err := tx.Commit(); err != nil {
		return AcceptedSubmission{}, fmt.Errorf("finish Guard accepted submission read: %w", err)
	}
	return out, nil
}
