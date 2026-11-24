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
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func validPermitDraft(d issuer.PermitDraft) bool {
	v := d.Values()
	return tenantIDPattern.MatchString(v.TenantID) &&
		validDispatchUUID(v.OperationID) &&
		validPermitEvidence(v.RunID) &&
		validPermitEvidence(v.RuntimeAttemptID) &&
		validPermitEvidence(v.TurnID) &&
		validPermitEvidence(v.ApprovalRef) &&
		validPermitEvidence(v.RiskRevision) &&
		validPermitEvidence(v.DecisionID) &&
		validPermitEvidence(v.PlanID) &&
		permitDigestRE.MatchString(v.PlanHash) &&
		validPermitEvidence(v.StepID) &&
		validPermitEvidence(v.CapabilityID) &&
		validPermitEvidence(v.CapabilityVersion) &&
		permitDigestRE.MatchString(v.CapabilityContractSHA256) &&
		validPermitEvidence(v.ResourceRef) &&
		permitDigestRE.MatchString(v.ActionHash) &&
		permitDigestRE.MatchString(v.ToolBindingDigest) &&
		validPermitEvidence(v.PolicyVersion) &&
		validPermitEvidence(v.Audience) &&
		validPermitEvidence(v.IssuedBy) &&
		!v.IssuedAt.IsZero() && v.IssuedAt.Equal(v.IssuedAt.Truncate(time.Microsecond)) &&
		!v.ExpiresAt.IsZero() && v.ExpiresAt.Equal(v.ExpiresAt.Truncate(time.Microsecond)) &&
		v.ExpiresAt.After(v.IssuedAt)
}

func samePermitAuthority(expected, actual issuer.PermitDraftValues) bool {
	return expected.TenantID == actual.TenantID &&
		expected.OperationID == actual.OperationID &&
		expected.RunID == actual.RunID &&
		expected.RuntimeAttemptID == actual.RuntimeAttemptID &&
		expected.TurnID == actual.TurnID &&
		expected.ApprovalRef == actual.ApprovalRef &&
		expected.RiskRevision == actual.RiskRevision &&
		expected.DecisionID == actual.DecisionID &&
		expected.PlanID == actual.PlanID &&
		expected.PlanHash == actual.PlanHash &&
		expected.StepID == actual.StepID &&
		expected.CapabilityID == actual.CapabilityID &&
		expected.CapabilityVersion == actual.CapabilityVersion &&
		expected.CapabilityContractSHA256 == actual.CapabilityContractSHA256 &&
		expected.ResourceRef == actual.ResourceRef &&
		expected.ActionHash == actual.ActionHash &&
		expected.ToolBindingDigest == actual.ToolBindingDigest &&
		expected.PolicyVersion == actual.PolicyVersion &&
		expected.Audience == actual.Audience &&
		expected.IssuedBy == actual.IssuedBy
}

func (l *PermitIssuerLedger) PersistIssuedPermit(
	ctx context.Context, draft issuer.PermitDraft, maxTTL time.Duration,
) (issuer.PersistedPermit, error) {
	var zero issuer.PersistedPermit
	if l == nil || l.store == nil || ctx == nil {
		return zero, issuer.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("%w: context: %w", issuer.ErrUnavailable, err)
	}
	if !validPermitDraft(draft) {
		return zero, issuer.ErrDenied
	}
	values := draft.Values()

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
	`, values.TenantID, values.OperationID, values.ActionHash, values.ToolBindingDigest,
		values.Audience, values.PolicyVersion, values.IssuedBy, values.IssuedAt, values.ExpiresAt).
		Scan(&permitID)

	persistedValues := values
	switch {
	case err == nil:
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO guard_permit_authority_evidence
				(tenant_id,operation_id,permit_id,run_id,runtime_attempt_id,turn_id,
				 approval_ref,risk_revision,decision_id,plan_id,plan_hash,step_id,
				 capability_id,capability_version,capability_contract_sha256,resource_ref,
				 action_hash,binding_digest,audience,policy_version,issued_by,issued_at,expires_at)
			VALUES ($1,$2::uuid,$3::uuid,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
		`, values.TenantID, values.OperationID, permitID, values.RunID,
			values.RuntimeAttemptID, values.TurnID, values.ApprovalRef, values.RiskRevision,
			values.DecisionID, values.PlanID, values.PlanHash, values.StepID,
			values.CapabilityID, values.CapabilityVersion, values.CapabilityContractSHA256, values.ResourceRef,
			values.ActionHash, values.ToolBindingDigest, values.Audience, values.PolicyVersion,
			values.IssuedBy, values.IssuedAt, values.ExpiresAt); err != nil {
			return zero, fmt.Errorf("%w: persist Permit authority evidence: %w", issuer.ErrUnavailable, err)
		}
		// A new Permit must be issued within the allowed clock-skew window.
		// This check is intentionally limited to new rows; replay returns the
		// original issuance timestamps and must remain idempotent after restart.
		if err := verifyPermitIssueWindow(ctx, tx, values, maxTTL); err != nil {
			return zero, err
		}

	case errors.Is(err, sql.ErrNoRows):
		var runID, runtimeAttemptID, turnID, approvalRef, riskRevision string
		var decisionID, planID, planHash, stepID, capabilityID, capabilityVersion sql.NullString
		var capabilityContractSHA256, resourceRef sql.NullString
		var actionHash, bindingDigest, audience, policyVersion, issuedBy string
		var issuedAt, expiresAt time.Time
		err = tx.QueryRowContext(ctx, `
			SELECT p.permit_id::text,
			       e.run_id,e.runtime_attempt_id,e.turn_id,e.approval_ref,e.risk_revision,
			       e.decision_id,e.plan_id,e.plan_hash,e.step_id,e.capability_id,e.capability_version,
			       e.capability_contract_sha256,e.resource_ref,
		       p.action_hash,p.binding_digest,p.audience,p.policy_version,p.issued_by,
		       p.issued_at,p.expires_at
			FROM guard_permits p
			JOIN guard_permit_authority_evidence e
			  ON e.tenant_id=p.tenant_id AND e.operation_id=p.operation_id
			 AND e.permit_id=p.permit_id
			WHERE p.tenant_id=$1 AND p.operation_id=$2::uuid
		`, values.TenantID, values.OperationID).Scan(
			&permitID, &runID, &runtimeAttemptID, &turnID, &approvalRef, &riskRevision,
			&decisionID, &planID, &planHash, &stepID, &capabilityID, &capabilityVersion,
			&capabilityContractSHA256, &resourceRef,
			&actionHash, &bindingDigest, &audience, &policyVersion, &issuedBy,
			&issuedAt, &expiresAt,
		)
		if errors.Is(err, sql.ErrNoRows) {
			return zero, issuer.ErrConflict
		}
		if err != nil {
			return zero, fmt.Errorf("%w: inspect existing Permit: %w", issuer.ErrUnavailable, err)
		}
		if !decisionID.Valid || !planID.Valid || !planHash.Valid || !stepID.Valid ||
			!capabilityID.Valid || !capabilityVersion.Valid ||
			!capabilityContractSHA256.Valid || !resourceRef.Valid {
			return zero, issuer.ErrConflict
		}
		persistedValues = issuer.PermitDraftValues{
			TenantID:                 values.TenantID,
			OperationID:              values.OperationID,
			RunID:                    runID,
			RuntimeAttemptID:         runtimeAttemptID,
			TurnID:                   turnID,
			ApprovalRef:              approvalRef,
			RiskRevision:             riskRevision,
			DecisionID:               decisionID.String,
			PlanID:                   planID.String,
			PlanHash:                 planHash.String,
			StepID:                   stepID.String,
			CapabilityID:             capabilityID.String,
			CapabilityVersion:        capabilityVersion.String,
			CapabilityContractSHA256: capabilityContractSHA256.String,
			ResourceRef:              resourceRef.String,
			ActionHash:               actionHash,
			ToolBindingDigest:        bindingDigest,
			PolicyVersion:            policyVersion,
			Audience:                 audience,
			IssuedBy: issuedBy,
			// database/sql returns timestamps with the driver's location
			// pointer. Normalize to UTC so replay reconstructs the exact
			// canonical PermitDraft value, not merely an Equal() timestamp.
			IssuedAt:  issuedAt.UTC().Truncate(time.Microsecond),
			ExpiresAt: expiresAt.UTC().Truncate(time.Microsecond),
		}
		if !samePermitAuthority(values, persistedValues) {
			return zero, issuer.ErrConflict
		}
		if err := verifyPermitReplayWindow(ctx, tx, persistedValues, values.ExpiresAt, maxTTL); err != nil {
			return zero, err
		}

	default:
		return zero, fmt.Errorf("%w: insert Permit: %w", issuer.ErrUnavailable, err)
	}

	if err := tx.Commit(); err != nil {
		return zero, fmt.Errorf("%w: commit Permit issuance: %w", issuer.ErrUnavailable, err)
	}
	return issuer.PersistedPermit{PermitID: permitID, Values: persistedValues}, nil
}

const maxPermitIssuerClockSkew = 30 * time.Second

func verifyPermitIssueWindow(
	ctx context.Context, tx *sql.Tx, values issuer.PermitDraftValues, maxTTL time.Duration,
) error {
	if maxTTL <= 0 || values.ExpiresAt.After(values.IssuedAt.Add(maxTTL)) {
		return issuer.ErrDenied
	}
	var dbNow time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&dbNow); err != nil {
		return fmt.Errorf("%w: sample PostgreSQL issuance clock: %w", issuer.ErrUnavailable, err)
	}
	if values.IssuedAt.Before(dbNow.Add(-maxPermitIssuerClockSkew)) ||
		values.IssuedAt.After(dbNow.Add(maxPermitIssuerClockSkew)) ||
		!values.ExpiresAt.After(dbNow) ||
		values.ExpiresAt.After(dbNow.Add(maxTTL)) {
		return issuer.ErrDenied
	}
	return nil
}

func verifyPermitReplayWindow(
	ctx context.Context, tx *sql.Tx, existing issuer.PermitDraftValues,
	requestedExpiry time.Time, maxTTL time.Duration,
) error {
	if maxTTL <= 0 || existing.IssuedAt.IsZero() ||
		existing.ExpiresAt.IsZero() ||
		!existing.ExpiresAt.After(existing.IssuedAt) ||
		existing.ExpiresAt.After(existing.IssuedAt.Add(maxTTL)) ||
		existing.ExpiresAt.After(requestedExpiry) {
		return issuer.ErrDenied
	}
	var dbNow time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&dbNow); err != nil {
		return fmt.Errorf("%w: sample PostgreSQL replay clock: %w", issuer.ErrUnavailable, err)
	}
	if existing.IssuedAt.After(dbNow.Add(maxPermitIssuerClockSkew)) ||
		!existing.ExpiresAt.After(dbNow) ||
		existing.ExpiresAt.After(dbNow.Add(maxTTL)) {
		return issuer.ErrDenied
	}
	return nil
}
