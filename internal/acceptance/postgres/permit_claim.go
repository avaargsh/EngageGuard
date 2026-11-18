package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// ErrPermitAlreadyClaimed is an explicit lost-ACK fence. Never treat a
// duplicate claim as a new permission to dispatch. Reconciliation must query
// the durable attempt, not call an executor again.
var ErrPermitAlreadyClaimed = errors.New("Guard Permit already claimed")

// ErrPermitUnavailable covers missing, revoked and expired execution rights.
var ErrPermitUnavailable = errors.New("Guard Permit unavailable or expired")

// ErrPermitMismatch means that the resolved trusted action no longer matches
// the issued Permit. In particular action, tenant, binding, target, policy,
// operation and audience changes cannot reuse prior approval.
var ErrPermitMismatch = errors.New("Guard Permit does not match resolved action")

// DispatchIntent is a committed internal dispatch-intent record, not an
// executor receipt, external ACK, or permission to call an external API
// independently of trusted-executor verification.
type DispatchIntent struct {
	TenantID    string
	OperationID string
	PermitID    string
	AttemptID   string
	ActionHash  string
	State       string
}

// ClaimAuthorizedIntent is ONLY for the future trusted Guard authorization
// service after verifying authentic Permit issuance, policy/revocation, Run
// authority, and resolved Action. No API or trusted issuer exists in this
// release. It atomically claims one pre-existing Permit, journals the attempt,
// and appends a pre-dispatch audit event BEFORE any external side effect.
// This function never dispatches. Failure to commit returns no dispatch right.
func (s *Store) ClaimAuthorizedIntent(ctx context.Context, permitID string, resolved action.WorkspaceWrite) (DispatchIntent, error) {
	if s == nil || s.db == nil {
		return DispatchIntent{}, errors.New("Guard database unavailable")
	}
	if permitID == "" || !tenantIDPattern.MatchString(resolved.TenantID) {
		return DispatchIntent{}, ErrPermitMismatch
	}
	hash, err := action.Hash(resolved)
	if err != nil {
		return DispatchIntent{}, fmt.Errorf("%w: %v", ErrPermitMismatch, err)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return DispatchIntent{}, fmt.Errorf("begin Permit claim: %w", err)
	}
	defer tx.Rollback()
	var state, actionHash, bindingDigest, audience, policyVersion string
	var unexpired, notRevoked bool
	err = tx.QueryRowContext(ctx, `
		SELECT state, action_hash, binding_digest, audience, policy_version,
			expires_at > clock_timestamp(), revoked_at IS NULL
		FROM guard_permits
		WHERE permit_id=$1::uuid AND tenant_id=$2 AND operation_id=$3::uuid
		FOR UPDATE
	`, permitID, resolved.TenantID, resolved.OperationID).Scan(
		&state, &actionHash, &bindingDigest, &audience, &policyVersion, &unexpired, &notRevoked)
	if errors.Is(err, sql.ErrNoRows) {
		return DispatchIntent{}, ErrPermitUnavailable
	}
	if err != nil {
		return DispatchIntent{}, fmt.Errorf("read locked Permit: %w", err)
	}
	if state == "CLAIMED" {
		return DispatchIntent{}, ErrPermitAlreadyClaimed
	}
	if state != "ISSUED" || !unexpired || !notRevoked {
		return DispatchIntent{}, ErrPermitUnavailable
	}
	if actionHash != hash || bindingDigest != resolved.ToolBindingDigest ||
		audience != resolved.Audience || policyVersion != resolved.PolicyVersion {
		return DispatchIntent{}, ErrPermitMismatch
	}
	// Recheck expiry/revocation using the DB clock on the write; a slow
	// transaction must not claim after the Permit expires.
	tag, err := tx.ExecContext(ctx, `
		UPDATE guard_permits
		SET state='CLAIMED', claimed_at=clock_timestamp()
		WHERE permit_id=$1::uuid AND tenant_id=$2 AND operation_id=$3::uuid
			AND state='ISSUED' AND revoked_at IS NULL AND expires_at > clock_timestamp()
	`, permitID, resolved.TenantID, resolved.OperationID)
	if err != nil {
		return DispatchIntent{}, fmt.Errorf("claim Permit: %w", err)
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return DispatchIntent{}, fmt.Errorf("count Permit claims: %w", err)
	}
	if affected != 1 {
		return DispatchIntent{}, ErrPermitUnavailable
	}
	intent := DispatchIntent{
		TenantID: resolved.TenantID, OperationID: resolved.OperationID,
		PermitID: permitID, ActionHash: hash, State: "DISPATCHING",
	}
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO guard_operation_intents
			(tenant_id, operation_id, permit_id, action_hash, binding_digest, state)
		VALUES ($1,$2::uuid,$3::uuid,$4,$5,'DISPATCHING')
		RETURNING attempt_id::text
	`, resolved.TenantID, resolved.OperationID, permitID, hash, resolved.ToolBindingDigest).
		Scan(&intent.AttemptID); err != nil {
		return DispatchIntent{}, fmt.Errorf("persist pre-dispatch operation intent: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO guard_execution_audit
			(tenant_id, operation_id, permit_id, attempt_id, event_type, action_hash)
		VALUES ($1,$2::uuid,$3::uuid,$4::uuid,'guard.operation.dispatching.v1',$5)
	`, resolved.TenantID, resolved.OperationID, permitID, intent.AttemptID, hash); err != nil {
		return DispatchIntent{}, fmt.Errorf("persist pre-dispatch audit intent: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return DispatchIntent{}, fmt.Errorf("commit Permit claim + intent + audit: %w", err)
	}
	return intent, nil
}
