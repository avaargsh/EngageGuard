package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// This file implements a package-private, necessary-only durable INSERT
// primitive. It is NOT the trusted issuer, cannot verify externally sourced
// Runtime/Decision/ACP/Approval/Risk, and is deliberately not exported to an
// API, the executor or any production authorization service.
var (
	ErrPermitAlreadyIssued         = errors.New("Guard operation already has a Permit")
	ErrPendingPermitInvalid        = errors.New("Guard pending Permit input or issuance window invalid")
	ErrPendingPermitSourceMismatch = errors.New("Guard pending Permit not bound to exact accepted submission")
	ErrPendingPermitUnavailable    = errors.New("Guard pending Permit database unavailable")
)

const maxPendingPermitLifetime = time.Minute

// pendingPermitWrite is intentionally unexported. Its resolved action and
// original submission must eventually come from independent authenticated
// sources. SQL stamps issued_by from the effective PostgreSQL current_user,
// never a caller-provided issuer string. Test fixtures are not authority.
type pendingPermitWrite struct {
	Submission action.ActionSubmission
	Resolved   action.WorkspaceWrite
	ExpiresAt  time.Time
}

// insertPendingPermit demonstrates the database half of protected issuance.
// It binds the original accepted source and the requested resolved action in
// one SQL transaction, uses the PostgreSQL clock, and does not return existing
// Permit IDs after a duplicate/lost ACK. It MUST NOT be exposed as an issuer
// endpoint: this private primitive does not authenticate Approval or Decision,
// and it cannot create an atomic distributed fence across independent sources.
// issued_by is the SQL current_user of the session performing INSERT, not
// an externally supplied actor name or an authenticated Approval identity.
func (s *Store) insertPendingPermit(ctx context.Context, req pendingPermitWrite) (string, error) {
	if s == nil || s.db == nil || ctx == nil {
		return "", ErrPendingPermitUnavailable
	}
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("%w: %v", ErrPendingPermitUnavailable, err)
	}
	if err := req.Submission.Validate(); err != nil {
		return "", ErrPendingPermitInvalid
	}
	if err := req.Resolved.Validate(); err != nil {
		return "", ErrPendingPermitInvalid
	}
	if req.Resolved.CapabilityID != "workspace.write" ||
		req.Submission.Capability.ID != "workspace.write" ||
		req.Submission.Capability.Version != "1.0.0" ||
		req.Resolved.WorkspaceID != req.Submission.ResourceRef ||
		!tenantIDPattern.MatchString(req.Resolved.TenantID) ||
		!validDispatchUUID(req.Resolved.OperationID) ||
		req.ExpiresAt.IsZero() {
		return "", ErrPendingPermitInvalid
	}
	hash, err := action.Hash(req.Resolved)
	if err != nil {
		return "", ErrPendingPermitInvalid
	}
	tx, err := beginGuardRuntimeTx(ctx, s.db)
	if err != nil {
		return "", fmt.Errorf("%w: begin source-bound Permit transaction: %w", ErrPendingPermitUnavailable, err)
	}
	defer tx.Rollback()

	// The immutable accepted tuple, its exact original bytes and the source
	// operation identity are read from one SQL statement; no caller-provided
	// submission digest or OperationID may replace this source check. Rows
	// are immutable under migration-checked triggers; SELECT does not need
	// UPDATE privilege or FOR SHARE, preserving source-reader least privilege.
	var sourceStatus, sourceDigest string
	var sourceBytes []byte
	err = tx.QueryRowContext(ctx, `
		SELECT o.status, o.submission_digest, s.submission_bytes
		FROM guard_action_operations o
		JOIN guard_accepted_submission_snapshots s
		  ON s.tenant_id=o.tenant_id AND s.operation_id=o.operation_id
		 AND s.submission_key=o.submission_key AND s.submission_digest=o.submission_digest
		WHERE o.tenant_id=$1 AND o.operation_id=$2::uuid

	`, req.Resolved.TenantID, req.Resolved.OperationID).
		Scan(&sourceStatus, &sourceDigest, &sourceBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrPendingPermitSourceMismatch
	}
	if err != nil {
		return "", fmt.Errorf("%w: read accepted source: %v", ErrPendingPermitUnavailable, err)
	}
	if sourceStatus != "ACCEPTED" {
		return "", ErrPendingPermitSourceMismatch
	}
	digest, err := action.SubmissionDigest(sourceBytes)
	if err != nil || digest != sourceDigest {
		return "", ErrPendingPermitSourceMismatch
	}
	original, err := action.ParseActionSubmission(sourceBytes)
	if err != nil || !reflect.DeepEqual(original, req.Submission) {
		return "", ErrPendingPermitSourceMismatch
	}

	// Use the trusted PostgreSQL clock rather than client time to reject
	// expired or excessive issuance windows. Recheck inside INSERT to
	// prevent a slow transaction from issuing after its expiry.
	var dbNow time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&dbNow); err != nil {
		return "", fmt.Errorf("%w: read DB clock: %v", ErrPendingPermitUnavailable, err)
	}
	if !req.ExpiresAt.After(dbNow) ||
		req.ExpiresAt.After(dbNow.Add(maxPendingPermitLifetime)) {
		return "", ErrPendingPermitInvalid
	}
	var permitID string
	err = tx.QueryRowContext(ctx, `
		WITH sampled AS MATERIALIZED (SELECT clock_timestamp() AS at)
		INSERT INTO guard_permits (
			tenant_id, operation_id, action_hash, binding_digest,
			audience, policy_version, issued_by, issued_at, expires_at
		)
		SELECT $1, $2::uuid, $3, $4, $5, $6, current_user, sampled.at, $7
		FROM sampled
		WHERE sampled.at < $7 AND $7 <= sampled.at + interval '60 seconds'
		ON CONFLICT (tenant_id, operation_id) DO NOTHING
		RETURNING permit_id::text
	`, req.Resolved.TenantID, req.Resolved.OperationID, hash,
		req.Resolved.ToolBindingDigest, req.Resolved.Audience,
		req.Resolved.PolicyVersion, req.ExpiresAt).Scan(&permitID)
	if errors.Is(err, sql.ErrNoRows) {
		var exists bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM guard_permits
				WHERE tenant_id=$1 AND operation_id=$2::uuid
			)
		`, req.Resolved.TenantID, req.Resolved.OperationID).Scan(&exists); err != nil {
			return "", fmt.Errorf("%w: inspect failed insert: %v", ErrPendingPermitUnavailable, err)
		}
		if exists {
			return "", ErrPermitAlreadyIssued
		}
		return "", ErrPendingPermitInvalid
	}
	if err != nil {
		return "", fmt.Errorf("%w: atomic pending Permit insert: %v", ErrPendingPermitUnavailable, err)
	}
	if !validDispatchUUID(permitID) {
		return "", ErrPendingPermitUnavailable
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("%w: commit pending Permit insert: %v", ErrPendingPermitUnavailable, err)
	}
	return permitID, nil
}
