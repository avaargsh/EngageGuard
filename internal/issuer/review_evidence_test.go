package issuer

import (
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
)

func TestReviewEvidenceRequiresCurrentExplicitDecisions(t *testing.T) {
	now := time.Date(2026, 11, 25, 6, 0, 0, 0, time.UTC)
	resolved := resolvedActionRequest()
	hash, err := action.ActionHash(resolved)
	if err != nil {
		t.Fatal(err)
	}
	binding := ReviewBinding{
		TenantID: resolved.TenantID, OperationID: resolved.OperationID,
		ActionHash: hash, PolicyVersion: resolved.PolicyVersion,
	}
	approval := ApprovalEvidence{
		Binding: binding, Reference: "approval-1", Status: ApprovalApproved,
		ValidUntil: now.Add(time.Minute),
	}
	risk := RiskEvidence{
		Binding: binding, Revision: "risk-1", Status: RiskAllowed,
		ValidUntil: now.Add(30 * time.Second),
	}

	t.Run("both current decisions", func(t *testing.T) {
		got, err := validateReviewEvidence(resolved, approval, risk, now)
		if err != nil {
			t.Fatal(err)
		}
		if got.ApprovalRef != approval.Reference || got.RiskRevision != risk.Revision ||
			!got.ValidUntil.Equal(risk.ValidUntil) {
			t.Fatalf("unexpected review summary: %+v", got)
		}
	})

	for _, tc := range []struct {
		name   string
		change func(*ApprovalEvidence, *RiskEvidence)
	}{
		{"missing approval", func(a *ApprovalEvidence, _ *RiskEvidence) { *a = ApprovalEvidence{} }},
		{"missing risk", func(_ *ApprovalEvidence, r *RiskEvidence) { *r = RiskEvidence{} }},
		{"pending approval", func(a *ApprovalEvidence, _ *RiskEvidence) { a.Status = "PENDING" }},
		{"denied risk", func(_ *ApprovalEvidence, r *RiskEvidence) { r.Status = "DENIED" }},
		{"revoked approval", func(a *ApprovalEvidence, _ *RiskEvidence) { a.Revoked = true }},
		{"revoked risk", func(_ *ApprovalEvidence, r *RiskEvidence) { r.Revoked = true }},
		{"expired approval", func(a *ApprovalEvidence, _ *RiskEvidence) { a.ValidUntil = now }},
		{"expired risk", func(_ *ApprovalEvidence, r *RiskEvidence) { r.ValidUntil = now }},
		{"missing approval reference", func(a *ApprovalEvidence, _ *RiskEvidence) { a.Reference = "" }},
		{"missing risk revision", func(_ *ApprovalEvidence, r *RiskEvidence) { r.Revision = "" }},
		{"approval binding mismatch", func(a *ApprovalEvidence, _ *RiskEvidence) { a.Binding.OperationID = "other" }},
		{"risk binding mismatch", func(_ *ApprovalEvidence, r *RiskEvidence) { r.Binding.PolicyVersion = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, r := approval, risk
			tc.change(&a, &r)
			got, err := validateReviewEvidence(resolved, a, r, now)
			if !errors.Is(err, ErrDenied) || got != (reviewSummary{}) {
				t.Fatalf("expected denial without review summary, got %+v, %v", got, err)
			}
		})
	}
}
