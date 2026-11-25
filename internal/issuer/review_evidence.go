package issuer

import (
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// ReviewBinding identifies the exact Guard-resolved intent that was reviewed.
// The ActionHash also binds the Run, actor, capability, arguments and audience.
type ReviewBinding struct {
	TenantID      string
	OperationID   string
	ActionHash    string
	PolicyVersion string
}

const (
	ApprovalApproved = "APPROVED"
	RiskAllowed      = "ALLOW"
)

// ApprovalEvidence and RiskEvidence are internal source records. They must be
// obtained from independently authenticated, current Guard-owned authorities,
// never decoded from an untrusted ActionSubmission.
type ApprovalEvidence struct {
	Binding    ReviewBinding
	Reference  string
	Status     string
	Revoked    bool
	ValidUntil time.Time
}

type RiskEvidence struct {
	Binding    ReviewBinding
	Revision   string
	Status     string
	Revoked    bool
	ValidUntil time.Time
}

// reviewSummary is not an authorization or Permit. It carries only the
// review evidence references and their common validity ceiling.
type reviewSummary struct {
	ApprovalRef  string
	RiskRevision string
	ValidUntil   time.Time
}

// validateReviewEvidence checks record consistency only. It does not establish
// source authenticity, freshness of a source read, or execution permission.
// It is intentionally not wired into issuance until the live source adapters
// and their independent acceptance are available.
func validateReviewEvidence(resolved action.ActionRequest, approval ApprovalEvidence, risk RiskEvidence, now time.Time) (reviewSummary, error) {
	hash, err := action.ActionHash(resolved)
	if err != nil || now.IsZero() {
		return reviewSummary{}, ErrDenied
	}
	expected := ReviewBinding{
		TenantID: resolved.TenantID, OperationID: resolved.OperationID,
		ActionHash: hash, PolicyVersion: resolved.PolicyVersion,
	}
	if approval.Binding != expected || risk.Binding != expected ||
		approval.Status != ApprovalApproved || risk.Status != RiskAllowed ||
		approval.Revoked || risk.Revoked ||
		!validEvidence(approval.Reference) || !validEvidence(risk.Revision) ||
		!approval.ValidUntil.After(now) || !risk.ValidUntil.After(now) {
		return reviewSummary{}, ErrDenied
	}
	until := approval.ValidUntil
	if risk.ValidUntil.Before(until) {
		until = risk.ValidUntil
	}
	return reviewSummary{
		ApprovalRef:  approval.Reference,
		RiskRevision: risk.Revision,
		ValidUntil:   until,
	}, nil
}
