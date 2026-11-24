package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/avaargsh/EngageGuard/internal/issuer"
)

var permitDigestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

type PermitIssuerLedger struct {
	store *Store
}

var _ issuer.PermitLedger = (*PermitIssuerLedger)(nil)

func NewPermitIssuerLedger(store *Store) (*PermitIssuerLedger, error) {
	if store == nil || store.db == nil || store.trustedSchema == "" {
		return nil, fmt.Errorf("%w: pinned Guard store required", issuer.ErrUnavailable)
	}
	return &PermitIssuerLedger{store: store}, nil
}

func validPermitEvidence(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 512 {
		return false
	}
	for _, r := range value {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validPermitDraft(d issuer.PermitDraft) bool {
	return tenantIDPattern.MatchString(d.TenantID) &&
		validDispatchUUID(d.OperationID) &&
		validPermitEvidence(d.RunID) &&
		validPermitEvidence(d.RuntimeAttemptID) &&
		validPermitEvidence(d.TurnID) &&
		validPermitEvidence(d.ApprovalRef) &&
		validPermitEvidence(d.RiskRevision) &&
		permitDigestRE.MatchString(d.ActionHash) &&
		permitDigestRE.MatchString(d.ToolBindingDigest) &&
		validPermitEvidence(d.PolicyVersion) &&
		validPermitEvidence(d.Audience) &&
		validPermitEvidence(d.IssuedBy) &&
		!d.IssuedAt.IsZero() && d.IssuedAt.Equal(d.IssuedAt.Truncate(time.Microsecond)) &&
		!d.ExpiresAt.IsZero() && d.ExpiresAt.Equal(d.ExpiresAt.Truncate(time.Microsecond)) &&
		d.ExpiresAt.After(d.IssuedAt)
}

func samePermitDraft(
	d issuer.PermitDraft,
	runID, runtimeAttemptID, turnID, approvalRef, riskRevision,
	actionHash, bindingDigest, audience, policyVersion, issuedBy string,
	issuedAt, expiresAt time.Time,
) bool {
	return d.RunID == runID &&
		d.RuntimeAttemptID == runtimeAttemptID &&
		d.TurnID == turnID &&
		d.ApprovalRef == approvalRef &&
		d.RiskRevision == riskRevision &&
		d.ActionHash == actionHash &&
		d.ToolBindingDigest == bindingDigest &&
		d.Audience == audience &&
		d.PolicyVersion == policyVersion &&
		d.IssuedBy == issuedBy &&
		d.IssuedAt.Equal(issuedAt) &&
		d.ExpiresAt.Equal(expiresAt)
}

func (l *PermitIssuerLedger) PersistIssuedPermit(
	ctx context.Context, draft issuer.PermitDraft,
) (issuer.ScopedPermit, error) {
	var zero issuer.ScopedPermit
	if l == nil || l.store == nil || ctx == nil {
		return zero, issuer.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("%w: context: %w", issuer.ErrUnavailable, err)
	}
	if !validPermitDraft(draft) {
		return zero, issuer.ErrDenied
	}

	tx, err := l.store.beginLedgerTx(ctx, true)
	if err != nil {
		return zero, fmt.Errorf("%w: begin issuer ledger: %w", issuer.ErrUnavailable, err)
	}
	defer tx.Rollback()
	if err := verifyPermitAuthorityEvidence(ctx, tx); err != nil {
		return zero, fmt.Errorf("%w: authority-evidence catalog: %w", issuer.ErrUnavailable, err)
	}

	var permitID string
	err = tx.QueryRowContext(ctx, `
		INSERT INTO guard_permits
			(tenant_id,operation_id,action_hash,binding_digest,audience,
			 policy_version,issued_by,issued_at,expires_at)
		VALUES ($1,$2::uuid,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (tenant_id,operation_id) DO NOTHING
		RETURNING permit_id::text
	`, draft.TenantID, draft.OperationID, draft.ActionHash, draft.ToolBindingDigest,
		draft.Audience, draft.PolicyVersion, draft.IssuedBy, draft.IssuedAt, draft.ExpiresAt).
		Scan(&permitID)

	switch {
	case err == nil:
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO guard_permit_authority_evidence
				(tenant_id,operation_id,permit_id,run_id,runtime_attempt_id,turn_id,
				 approval_ref,risk_revision,action_hash,binding_digest,audience,
				 policy_version,issued_by,issued_at,expires_at)
			VALUES ($1,$2::uuid,$3::uuid,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		`, draft.TenantID, draft.OperationID, permitID, draft.RunID,
			draft.RuntimeAttemptID, draft.TurnID, draft.ApprovalRef, draft.RiskRevision,
			draft.ActionHash, draft.ToolBindingDigest, draft.Audience, draft.PolicyVersion,
			draft.IssuedBy, draft.IssuedAt, draft.ExpiresAt); err != nil {
			return zero, fmt.Errorf("%w: persist Permit authority evidence: %w", issuer.ErrUnavailable, err)
		}
	case errors.Is(err, sql.ErrNoRows):
		var runID, runtimeAttemptID, turnID, approvalRef, riskRevision string
		var actionHash, bindingDigest, audience, policyVersion, issuedBy string
		var issuedAt, expiresAt time.Time
		err = tx.QueryRowContext(ctx, `
			SELECT p.permit_id::text,
			       e.run_id,e.runtime_attempt_id,e.turn_id,e.approval_ref,e.risk_revision,
			       p.action_hash,p.binding_digest,p.audience,p.policy_version,p.issued_by,
			       p.issued_at,p.expires_at
			FROM guard_permits p
			JOIN guard_permit_authority_evidence e
			  ON e.tenant_id=p.tenant_id AND e.operation_id=p.operation_id
			 AND e.permit_id=p.permit_id
			WHERE p.tenant_id=$1 AND p.operation_id=$2::uuid
		`, draft.TenantID, draft.OperationID).Scan(
			&permitID, &runID, &runtimeAttemptID, &turnID, &approvalRef, &riskRevision,
			&actionHash, &bindingDigest, &audience, &policyVersion, &issuedBy,
			&issuedAt, &expiresAt,
		)
		if errors.Is(err, sql.ErrNoRows) {
			return zero, issuer.ErrConflict
		}
		if err != nil {
			return zero, fmt.Errorf("%w: inspect existing Permit: %w", issuer.ErrUnavailable, err)
		}
		if !samePermitDraft(draft, runID, runtimeAttemptID, turnID, approvalRef,
			riskRevision, actionHash, bindingDigest, audience, policyVersion,
			issuedBy, issuedAt, expiresAt) {
			return zero, issuer.ErrConflict
		}
	default:
		return zero, fmt.Errorf("%w: insert Permit: %w", issuer.ErrUnavailable, err)
	}

	if err := tx.Commit(); err != nil {
		return zero, fmt.Errorf("%w: commit Permit issuance: %w", issuer.ErrUnavailable, err)
	}
	return issuer.ScopedPermit{PermitID: permitID, Draft: draft}, nil
}
