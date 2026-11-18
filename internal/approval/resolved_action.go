package approval

import (
	"crypto/ed25519"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// ExecutionBinding is sourced from authenticated Runtime/Decision/ACP
// authorities. Never fill this struct from ActionSubmission or model output.
// Its current generation, policy and approval revocation are re-read by the
// future issuer and executor PEP; this helper performs NO authority I/O.
type ExecutionBinding struct {
	RunID          string
	AttemptID      string
	TurnID         string
	AgentReleaseID string
	DecisionID     string
	PlanHash       string
	StepID         string
}

// ScopeForResolvedWorkspace computes the complete approval scope from the
// actual, trusted, canonical WorkspaceWrite instead of caller-provided action
// hashes. An accepted ActionSubmission remains untrusted intent only.
func ScopeForResolvedWorkspace(resolved action.WorkspaceWrite, execution ExecutionBinding) (Scope, error) {
	if err := resolved.Validate(); err != nil {
		return Scope{}, ErrApprovalRejected
	}
	actualHash, err := action.Hash(resolved)
	if err != nil {
		return Scope{}, ErrApprovalRejected
	}
	scope := Scope{
		TenantID: resolved.TenantID, RunID: execution.RunID,
		AttemptID: execution.AttemptID, TurnID: execution.TurnID,
		OperationID: resolved.OperationID, AgentID: resolved.AgentID,
		AgentReleaseID: execution.AgentReleaseID, SubjectID: resolved.SubjectID,
		DecisionID: execution.DecisionID, PlanHash: execution.PlanHash,
		StepID: execution.StepID, ActionHash: actualHash,
		ToolBindingDigest: resolved.ToolBindingDigest, PolicyVersion: resolved.PolicyVersion,
		Audience: resolved.Audience, ResourceRef: resolved.WorkspaceID,
	}
	if !validScope(scope) {
		return Scope{}, ErrApprovalRejected
	}
	return scope, nil
}

// VerifyResolvedWorkspaceApproval is a necessary-only, independent signed
// approval preflight. It NEVER issues/claims a Permit or authorizes execution.
// The caller MUST separately authenticate/rescan current Run/Decision/ACP,
// risk, policy, approval revocation and all PEP fences at actual dispatch.
func VerifyResolvedWorkspaceApproval(
	wire []byte, publicKey ed25519.PublicKey,
	resolved action.WorkspaceWrite, execution ExecutionBinding, now time.Time,
) (Evidence, error) {
	scope, err := ScopeForResolvedWorkspace(resolved, execution)
	if err != nil {
		return Evidence{}, err
	}
	return VerifySignedEvidence(wire, publicKey, scope, now)
}
