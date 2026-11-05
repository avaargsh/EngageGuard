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
	if s == nil || s.db == nil {
		return AcceptedSubmission{}, errors.New("Guard admission database unavailable")
	}
	if !tenantIDPattern.MatchString(tenantID) || operationID == "" {
		return AcceptedSubmission{}, ErrSnapshotMissing
	}
	var out AcceptedSubmission
	out.Operation.TenantID = tenantID
	out.Operation.OperationID = operationID
	err := s.db.QueryRowContext(ctx, `
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
	return out, nil
}
