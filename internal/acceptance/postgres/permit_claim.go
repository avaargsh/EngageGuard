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

type permitClaimBinding struct {
	TenantID                 string
	OperationID              string
	RunID                    string
	DecisionID               string
	PlanID                   string
	PlanHash                 string
	StepID                   string
	CapabilityID             string
	CapabilityVersion        string
	CapabilityContractSHA256 string
	ResourceRef              string
	ToolBindingDigest        string
	PolicyVersion            string
	Audience                 string
	ActionHash               string
	RequireActionRequestV1   bool
}

// ClaimAuthorizedIntent is retained for the legacy WorkspaceWrite v0.1
// compatibility tests. It cannot claim a Permit minted by the ActionRequest
// v1 issuer because its action hash and evidence bindings are different.
func (s *Store) ClaimAuthorizedIntent(
	ctx context.Context, permitID string, resolved action.WorkspaceWrite,
) (DispatchIntent, error) {
	hash, err := action.Hash(resolved)
	if err != nil {
		return DispatchIntent{}, fmt.Errorf("%w: %v", ErrPermitMismatch, err)
	}
	return s.claimAuthorizedIntent(ctx, permitID, permitClaimBinding{
		TenantID: resolved.TenantID, OperationID: resolved.OperationID,
		ToolBindingDigest:        resolved.ToolBindingDigest,
		PolicyVersion:     resolved.PolicyVersion, Audience: resolved.Audience,
		ActionHash: hash,
	})
}

// ClaimResolvedActionIntent claims only a Permit whose immutable authority
// evidence records the exact ActionRequest v1 Run/Decision/Plan/Step,
// capability ID/version/contract, and resource binding. It never dispatches.
func (s *Store) ClaimResolvedActionIntent(
	ctx context.Context, permitID string, resolved action.ActionRequest,
) (DispatchIntent, error) {
	if err := resolved.Validate(); err != nil ||
		!validDispatchUUID(resolved.OperationID) ||
		!tenantIDPattern.MatchString(resolved.TenantID) {
		return DispatchIntent{}, ErrPermitMismatch
	}
	hash, err := action.ActionHash(resolved)
	if err != nil {
		return DispatchIntent{}, fmt.Errorf("%w: %v", ErrPermitMismatch, err)
	}
	return s.claimAuthorizedIntent(ctx, permitID, permitClaimBinding{
		TenantID: resolved.TenantID, OperationID: resolved.OperationID,
		RunID: resolved.RunID, DecisionID: resolved.DecisionID,
		PlanID: resolved.PlanID, PlanHash: resolved.PlanHash,
		StepID: resolved.StepID, CapabilityID: resolved.Capability.ID,
		CapabilityVersion:        resolved.Capability.Version,
		CapabilityContractSHA256: resolved.Capability.ContractSHA256,
		ResourceRef:              resolved.ResourceRef,
		ToolBindingDigest: resolved.ToolBindingDigest,
		PolicyVersion: resolved.PolicyVersion, Audience: resolved.Audience,
		ActionHash: hash, RequireActionRequestV1: true,
	})
}

// claimAuthorizedIntent atomically claims one pre-existing Permit, journals
// the attempt and appends pre-dispatch audit evidence before any side effect.
// A committed DispatchIntent is not an external execution grant.
func (s *Store) claimAuthorizedIntent(
	ctx context.Context, permitID string, binding permitClaimBinding,
) (DispatchIntent, error) {
	if s == nil || s.db == nil || ctx == nil {
		return DispatchIntent{}, errors.New("Guard database unavailable")
	}
	if !validDispatchUUID(permitID) || !validDispatchUUID(binding.OperationID) ||
		!tenantIDPattern.MatchString(binding.TenantID) {
		return DispatchIntent{}, ErrPermitMismatch
	}

	tx, err := s.beginLedgerTx(ctx, true)
	if err != nil {
		return DispatchIntent{}, fmt.Errorf("begin Permit claim: %w", err)
	}
	defer tx.Rollback()
	if err := verifyPermitAuthorityEvidence(ctx, tx); err != nil {
		return DispatchIntent{}, fmt.Errorf("%w: trusted issuance evidence: %w", ErrPermitUnavailable, err)
	}

	var state, actionHash, bindingDigest, audience, policyVersion, evidenceRunID string
	var evidenceDecisionID, evidencePlanID, evidencePlanHash, evidenceStepID sql.NullString
	var evidenceCapabilityID, evidenceCapabilityVersion, evidenceCapabilityContractSHA256, evidenceResourceRef sql.NullString
	var unexpired, notRevoked bool
	err = tx.QueryRowContext(ctx, `
		SELECT p.state, p.action_hash, p.binding_digest, p.audience, p.policy_version,
			p.expires_at > clock_timestamp(), p.revoked_at IS NULL,
			e.run_id,e.decision_id,e.plan_id,e.plan_hash,e.step_id,
			e.capability_id,e.capability_version,e.capability_contract_sha256,e.resource_ref
		FROM guard_permits p
		JOIN guard_permit_authority_evidence e
		  ON e.tenant_id=p.tenant_id
		 AND e.operation_id=p.operation_id
		 AND e.permit_id=p.permit_id
		WHERE p.permit_id=$1::uuid AND p.tenant_id=$2 AND p.operation_id=$3::uuid
		FOR UPDATE OF p
	`, permitID, binding.TenantID, binding.OperationID).Scan(
		&state, &actionHash, &bindingDigest, &audience, &policyVersion,
		&unexpired, &notRevoked, &evidenceRunID,
		&evidenceDecisionID, &evidencePlanID, &evidencePlanHash, &evidenceStepID,
		&evidenceCapabilityID, &evidenceCapabilityVersion,
		&evidenceCapabilityContractSHA256, &evidenceResourceRef,
	)
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
	if actionHash != binding.ActionHash || bindingDigest != binding.ToolBindingDigest ||
		audience != binding.Audience || policyVersion != binding.PolicyVersion {
		return DispatchIntent{}, ErrPermitMismatch
	}
	if binding.RequireActionRequestV1 &&
		(evidenceRunID != binding.RunID ||
			!evidenceDecisionID.Valid || evidenceDecisionID.String != binding.DecisionID ||
			!evidencePlanID.Valid || evidencePlanID.String != binding.PlanID ||
			!evidencePlanHash.Valid || evidencePlanHash.String != binding.PlanHash ||
			!evidenceStepID.Valid || evidenceStepID.String != binding.StepID ||
			!evidenceCapabilityID.Valid || evidenceCapabilityID.String != binding.CapabilityID ||
			!evidenceCapabilityVersion.Valid || evidenceCapabilityVersion.String != binding.CapabilityVersion ||
			!evidenceCapabilityContractSHA256.Valid || evidenceCapabilityContractSHA256.String != binding.CapabilityContractSHA256 ||
			!evidenceResourceRef.Valid || evidenceResourceRef.String != binding.ResourceRef) {
		return DispatchIntent{}, ErrPermitMismatch
	}

	// Recheck expiry/revocation using the DB clock on the write; a slow
	// transaction must not claim after the Permit expires.
	tag, err := tx.ExecContext(ctx, `
		UPDATE guard_permits p
		SET state='CLAIMED', claimed_at=clock_timestamp()
		WHERE p.permit_id=$1::uuid AND p.tenant_id=$2 AND p.operation_id=$3::uuid
			AND p.state='ISSUED' AND p.revoked_at IS NULL AND p.expires_at > clock_timestamp()
			AND EXISTS (
				SELECT 1 FROM guard_permit_authority_evidence e
				WHERE e.tenant_id=p.tenant_id
				  AND e.operation_id=p.operation_id
				  AND e.permit_id=p.permit_id
			)
	`, permitID, binding.TenantID, binding.OperationID)
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
		TenantID: binding.TenantID, OperationID: binding.OperationID,
		PermitID: permitID, ActionHash: binding.ActionHash, State: "DISPATCHING",
	}
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO guard_operation_intents
			(tenant_id, operation_id, permit_id, action_hash, binding_digest, state)
		VALUES ($1,$2::uuid,$3::uuid,$4,$5,'DISPATCHING')
		RETURNING attempt_id::text
	`, binding.TenantID, binding.OperationID, permitID, binding.ActionHash, binding.ToolBindingDigest).
		Scan(&intent.AttemptID); err != nil {
		return DispatchIntent{}, fmt.Errorf("persist pre-dispatch operation intent: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO guard_execution_audit
			(tenant_id, operation_id, permit_id, attempt_id, event_type, action_hash)
		VALUES ($1,$2::uuid,$3::uuid,$4::uuid,'guard.operation.dispatching.v1',$5)
	`, binding.TenantID, binding.OperationID, permitID, intent.AttemptID, binding.ActionHash); err != nil {
		return DispatchIntent{}, fmt.Errorf("persist pre-dispatch audit intent: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return DispatchIntent{}, fmt.Errorf("commit Permit claim + intent + audit: %w", err)
	}
	return intent, nil
}
