package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrPermitRevocationConflict prevents rewriting an existing revocation's
// identity or reason. A different operator event needs independent review.
var ErrPermitRevocationConflict = errors.New("Guard Permit already revoked with another evidence")

func validPermitRevocationReason(s string) bool {
	switch s {
	case "POLICY_REVOKED", "SECURITY_RESPONSE", "HUMAN_REVOKED":
		return true
	default:
		return false
	}
}

// RevokeScopedPermit is an internal storage primitive only. The caller MUST
// first authenticate the operator/authority and tenant, and independently
// verify current policy. No public route, effect, or Permit issuer is here.
// The same locked Permit row serializes claim vs revoke. Even a CLAIMED
// Permit can be revoked; its downstream effect remains UNKNOWN until
// independently reconciled, not magically compensated or confirmed.
func (s *Store) RevokeScopedPermit(ctx context.Context, tenant, permitID, evidenceRef, reason string) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("Guard database unavailable")
	}
	if !tenantIDPattern.MatchString(tenant) || !validDispatchUUID(permitID) ||
		len(evidenceRef) == 0 || len(evidenceRef) > 128 ||
		!validPermitRevocationReason(reason) {
		return false, ErrPermitUnavailable
	}
	for _, ch := range evidenceRef {
		if ch <= 32 || ch == 127 {
			return false, ErrPermitUnavailable
		}
	}
	tx, err := beginGuardRuntimeTx(ctx, s.db)
	if err != nil {
		return false, fmt.Errorf("begin Permit revocation: %w", err)
	}
	defer tx.Rollback()
	var state string
	var revoked sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT state, revoked_at FROM guard_permits
		WHERE tenant_id=$1 AND permit_id=$2::uuid FOR UPDATE
	`, tenant, permitID).Scan(&state, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrPermitUnavailable
	}
	if err != nil {
		return false, fmt.Errorf("read locked Permit for revocation: %w", err)
	}
	if state != "ISSUED" && state != "CLAIMED" {
		return false, ErrPermitUnavailable
	}
	if revoked.Valid {
		var currentEvidence, currentReason, currentState string
		err = tx.QueryRowContext(ctx, `
			SELECT evidence_ref, reason, prior_state
			FROM guard_permit_revocations
			WHERE tenant_id=$1 AND permit_id=$2::uuid
		`, tenant, permitID).Scan(&currentEvidence, &currentReason, &currentState)
		if err != nil || currentEvidence != evidenceRef || currentReason != reason ||
			currentState != state {
			return false, ErrPermitRevocationConflict
		}
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("commit idempotent revocation replay: %w", err)
		}
		return false, nil
	}
	updated, err := tx.ExecContext(ctx, `
		UPDATE guard_permits SET revoked_at=clock_timestamp()
		WHERE tenant_id=$1 AND permit_id=$2::uuid AND revoked_at IS NULL
	`, tenant, permitID)
	if err != nil {
		return false, fmt.Errorf("mark Permit revoked: %w", err)
	}
	count, err := updated.RowsAffected()
	if err != nil || count != 1 {
		return false, ErrPermitRevocationConflict
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO guard_permit_revocations (tenant_id,permit_id,evidence_ref,reason,prior_state)
		VALUES ($1,$2::uuid,$3,$4,$5)
	`, tenant, permitID, evidenceRef, reason, state); err != nil {
		return false, fmt.Errorf("append Permit revocation evidence: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit Permit revocation + evidence: %w", err)
	}
	return true, nil
}
