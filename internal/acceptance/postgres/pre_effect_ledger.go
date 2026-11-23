package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// ErrPreEffectBlocked means the local Guard ledger cannot support even a
// necessary pre-effect check. It does NOT mean the provider did not run.
var ErrPreEffectBlocked = errors.New("Guard pre-effect ledger does not support a protected side effect")

// ErrPreEffectUnavailable means the required trusted DB snapshot could not
// be read. It is fail-closed and is NOT permission to retry an effect.
var ErrPreEffectUnavailable = errors.New("Guard pre-effect ledger source unavailable")

// InspectPreEffectLedger validates necessary, source-owned Guard DB facts
// from ONE SQL snapshot and ONE sampled PostgreSQL clock instant.
// It returns nil ONLY for an unexpired, unrevoked CLAIMED Permit with exact
// matching DISPATCHING Intent and immutable pre-dispatch Audit.
//
// This is NOT an execution grant, Permit issuer or deployed executor PEP.
// Callers still need mutually authenticated executor identity, fresh
// independent Run/Decision/ACP/approval/risk checks, authorization binding,
// and enforcement at the actual effect boundary. Never redispatch UNKNOWN
// based on this method. Direct DB test fixtures do NOT prove trusted issuance.
func (s *Store) InspectPreEffectLedger(
	ctx context.Context, permitID, attemptID string, resolved action.WorkspaceWrite,
) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrPreEffectUnavailable
	}
	if !validDispatchUUID(permitID) || !validDispatchUUID(attemptID) ||
		!validDispatchUUID(resolved.OperationID) ||
		!tenantIDPattern.MatchString(resolved.TenantID) {
		return ErrPreEffectBlocked
	}
	hash, err := action.Hash(resolved)
	if err != nil {
		return ErrPreEffectBlocked
	}
	// The migration-time schema attestation cannot protect a pooled session
	// that acquires pg_temp lookalikes later. Inspect the same physical
	// PostgreSQL session, within the transaction used for the actual
	// pre-effect read, before trusting any Permit/Intent/Audit relation.
	// This remains a necessary-only observation; it does not grant effects.
	tx, err := beginGuardRuntimeTx(ctx, s.db)
	if err != nil {
		return fmt.Errorf("%w: runtime Guard ledger identity: %w", ErrPreEffectUnavailable, err)
	}
	defer tx.Rollback()
	var complete bool
	err = tx.QueryRowContext(ctx, `
		WITH sampled AS MATERIALIZED (SELECT clock_timestamp() AS at)
		SELECT EXISTS (
			SELECT 1 FROM guard_permits p
			JOIN guard_operation_intents i
			  ON i.tenant_id=p.tenant_id
			  AND i.operation_id=p.operation_id
			  AND i.permit_id=p.permit_id
			CROSS JOIN sampled t
			WHERE p.tenant_id=$1 AND p.operation_id=$2::uuid
			  AND p.permit_id=$3::uuid AND i.attempt_id=$4::uuid
			  AND p.state='CLAIMED' AND i.state='DISPATCHING'
			  AND p.claimed_at IS NOT NULL
			  AND p.issued_at <= p.claimed_at AND p.claimed_at < p.expires_at
			  AND p.issued_at <= t.at AND t.at < p.expires_at
			  AND p.revoked_at IS NULL
			  AND p.action_hash=$5 AND i.action_hash=$5
			  AND p.binding_digest=$6 AND i.binding_digest=$6
			  AND p.audience=$7 AND p.policy_version=$8
			  AND EXISTS (
				  SELECT 1 FROM guard_execution_audit a
				  WHERE a.tenant_id=p.tenant_id
				    AND a.operation_id=p.operation_id
				    AND a.permit_id=p.permit_id
				    AND a.attempt_id=i.attempt_id
				    AND a.action_hash=p.action_hash
				    AND a.event_type='guard.operation.dispatching.v1'
			  )
		)
	`, resolved.TenantID, resolved.OperationID, permitID, attemptID,
		hash, resolved.ToolBindingDigest, resolved.Audience, resolved.PolicyVersion).
		Scan(&complete)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPreEffectBlocked
		}
		return fmt.Errorf("%w: database snapshot read failed: %v", ErrPreEffectUnavailable, err)
	}
	if !complete {
		return ErrPreEffectBlocked
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: finish Guard pre-effect ledger inspection: %v", ErrPreEffectUnavailable, err)
	}
	return nil
}
