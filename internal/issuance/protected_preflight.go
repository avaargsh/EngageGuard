// Package issuance contains ONLY a protected-write preflight gate.
// It has no Permit writer, HTTP route, executor or durable authorization.
// A successful preflight may not be replayed as an execution grant.
package issuance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
	"github.com/avaargsh/EngageGuard/internal/acceptance/postgres"
	"github.com/avaargsh/EngageGuard/internal/admission"
	"github.com/avaargsh/EngageGuard/internal/approval"
)

var (
	ErrUnavailable = errors.New("Guard protected preflight authority unavailable")
	ErrDenied      = errors.New("Guard protected preflight denied")
)

var canonicalUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var canonicalDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// StepProvenance MUST be sourced from Decision's immutable, current
// protected-action authority. It is NOT caller-submitted execution metadata.
type StepProvenance struct {
	RunID, AgentID, AgentReleaseID, SessionID    string
	DecisionID, PlanID, PlanHash, StepID         string
	CapabilityID, CapabilityVersion, ResourceRef string
	Arguments                                    json.RawMessage
	AttemptID, TurnID                            string
	BreakerEpoch, BreakerVersion                 uint64
}

// ProtectedDecisionAuthority must independently fetch authoritative
// Plan/Step, exact arguments, Run/Attempt/Turn and current revocation.
// The existing DecisionPlanClient only supports read-only sre.*; it CANNOT
// implement this interface for workspace.write without a new source contract.
type ProtectedDecisionAuthority interface {
	VerifyProtectedStep(context.Context, admission.Principal, admission.RunSafetySnapshot, action.ActionSubmission) (StepProvenance, error)
}

// TrustedWorkspaceResolver must derive WorkspaceWrite from the original
// accepted operation and policy-bound ToolBinding, never from untrusted
// ActionSubmission fields, external headers or model suggestions.
type TrustedWorkspaceResolver interface {
	ResolveWorkspaceWrite(context.Context, admission.Principal, admission.RunSafetySnapshot, action.ActionSubmission) (action.WorkspaceWrite, error)
}

// ProtectedWorkspaceAuthority is a necessary-only live ACP catalog check.
type ProtectedWorkspaceAuthority interface {
	ObserveProtectedWorkspace(context.Context, admission.Principal, admission.RunSafetySnapshot, action.WorkspaceWrite, string) (admission.ProtectedWorkspaceObservation, error)
}

// ApprovalState is current signed-approval status from an independently
// authenticated approval source, not a snapshot inside user-provided proof.
type ApprovalState struct {
	ApprovalID string
	Scope      approval.Scope
	Status     string
	Revision   string
}

// CurrentApprovalAuthority must query fresh approval state AND revocation
// on every call; returning cached positive SignedEvidence is insufficient.
type CurrentApprovalAuthority interface {
	CheckCurrentApproval(context.Context, approval.Evidence) (ApprovalState, error)
}

// RiskState must come from the live policy/risk control plane. A generation
// is not itself an authorization token and must not be synthesized by caller.
type RiskState struct {
	Decision      string
	ActionHash    string
	PolicyVersion string
	Generation    uint64
}
type RiskAuthority interface {
	EvaluateRisk(context.Context, approval.Scope) (RiskState, error)
}

// AcceptedSubmissionAuthority reads the source-owned immutable Guard
// acceptance record. The record is untrusted original intent and is never
// an issuance decision. Concrete source: PostgreSQL Store, with its digest
// and immutable snapshot checked by Guard.
type AcceptedSubmissionAuthority interface {
	ReadAcceptedSubmission(context.Context, string, string) (postgres.AcceptedSubmission, error)
}

type Dependencies struct {
	Accepted AcceptedSubmissionAuthority
	Runtime     admission.RunSafetyAuthority
	Decision    ProtectedDecisionAuthority
	Actions     TrustedWorkspaceResolver
	ACP         ProtectedWorkspaceAuthority
	Approvals   CurrentApprovalAuthority
	Risk        RiskAuthority
	ApprovalKey ed25519.PublicKey
	Now         func() time.Time
}

// Gate is deliberately separate from read-only admission and has no method
// that can produce, claim, sign or deliver a Scoped Permit.
type Gate struct {
	deps Dependencies
}

func nilDependency(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	default:
		return false
	}
}

func NewGate(d Dependencies) (*Gate, error) {
	if nilDependency(d.Runtime) || nilDependency(d.Decision) || nilDependency(d.Actions) ||
		nilDependency(d.Accepted) ||
		nilDependency(d.ACP) || nilDependency(d.Approvals) || nilDependency(d.Risk) ||
		len(d.ApprovalKey) != ed25519.PublicKeySize || d.Now == nil {
		return nil, ErrUnavailable
	}
	d.ApprovalKey = append(ed25519.PublicKey(nil), d.ApprovalKey...)
	return &Gate{deps: d}, nil
}

func validRun(p admission.Principal, s admission.RunSafetySnapshot, sub action.ActionSubmission) bool {
	return p.ServiceID == "agent-runtime" && p.TenantID != "" && p.SubjectID != "" &&
		p.ActorID != "" && p.WorkloadID != "" && s.TenantID == p.TenantID &&
		s.RunID == sub.RunID && canonicalUUID.MatchString(s.RunID) &&
		s.AgentID != "" && s.AgentReleaseID != "" && s.SessionID != "" &&
		s.Status == "RUNNING" && s.BreakerState == "CLOSED" &&
		s.BreakerEpoch > 0 && s.BreakerVersion > 0
}

func validProtectedStep(s StepProvenance, run admission.RunSafetySnapshot, sub action.ActionSubmission) bool {
	return s.RunID == run.RunID && s.AgentID == run.AgentID &&
		s.AgentReleaseID == run.AgentReleaseID && s.SessionID == run.SessionID &&
		s.DecisionID == sub.DecisionID && s.PlanID == sub.PlanID &&
		s.PlanHash == sub.PlanHash && s.StepID == sub.StepID &&
		s.CapabilityID == sub.Capability.ID && s.CapabilityVersion == sub.Capability.Version &&
		s.ResourceRef == sub.ResourceRef &&
		bytes.Equal(s.Arguments, sub.Arguments) &&
		s.AttemptID != "" && s.TurnID != "" &&
		s.BreakerEpoch == run.BreakerEpoch && s.BreakerVersion == run.BreakerVersion
}

func validApproval(current ApprovalState, proof approval.Evidence) bool {
	return current.Status == "APPROVED" && current.ApprovalID == proof.ApprovalID &&
		current.Scope == proof.Scope && current.Revision != "" &&
		strings.TrimSpace(current.Revision) == current.Revision
}

func validRisk(r RiskState, scope approval.Scope) bool {
	return r.Decision == "ALLOW" && r.ActionHash == scope.ActionHash &&
		r.PolicyVersion == scope.PolicyVersion && r.Generation > 0
}

func validACP(o admission.ProtectedWorkspaceObservation, policy string) bool {
	return o.PolicyRevision == policy && canonicalDigest.MatchString(o.ContractSHA256) &&
		strings.HasPrefix(o.ConfigDigest, "sha256:") && canonicalDigest.MatchString(strings.TrimPrefix(o.ConfigDigest, "sha256:"))
}

// validAcceptedSubmission checks BOTH the immutable exact-byte digest and the
// source-authenticated identity. Comparing parsed submissions is conservative:
// byte-different JSON arguments do not silently bind to another operation.
func validAcceptedSubmission(rec postgres.AcceptedSubmission, tenantID, operationID string, current action.ActionSubmission) bool {
	if rec.Operation.TenantID != tenantID || rec.Operation.OperationID != operationID ||
		rec.Operation.Status != "ACCEPTED" || !canonicalUUID.MatchString(operationID) {
		return false
	}
	digest, err := action.SubmissionDigest(rec.Raw)
	if err != nil || digest != rec.Operation.SubmissionDigest {
		return false
	}
	original, err := action.ParseActionSubmission(rec.Raw)
	return err == nil && reflect.DeepEqual(original, current)
}

func failure(phase string, err error) error {
	if errors.Is(err, admission.ErrForbidden) || errors.Is(err, approval.ErrApprovalRejected) {
		return fmt.Errorf("%w: %s: %w", ErrDenied, phase, err)
	}
	return fmt.Errorf("%w: %s: %w", ErrUnavailable, phase, err)
}

// Verify checks *only* whether a protected workspace.write has consistent
// current authority and independently pinned signed approval.
// No caller supplies the Action, Operation, approval scope or Decision
// provenance; each is resolved from its own trusted source.
//
// This preflight is NOT a permit or atomic distributed execution fence.
// A future trusted issuer must recheck revocation/risk and use a least-privilege
// Permit writer; a future executor PEP must re-check again before any effect.
func (g *Gate) Verify(ctx context.Context, p admission.Principal, sub action.ActionSubmission, signedApproval []byte) error {
	if g == nil || nilDependency(g.deps.Runtime) || nilDependency(g.deps.Decision) ||
		nilDependency(g.deps.Accepted) ||
		nilDependency(g.deps.Actions) || nilDependency(g.deps.ACP) ||
		nilDependency(g.deps.Approvals) || nilDependency(g.deps.Risk) ||
		len(g.deps.ApprovalKey) != ed25519.PublicKeySize || g.deps.Now == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return failure("context", err)
	}
	if sub.Validate() != nil || sub.Capability.ID != "workspace.write" ||
		sub.Capability.Version != "1.0.0" || !canonicalUUID.MatchString(sub.RunID) {
		return ErrDenied
	}
	run, err := g.deps.Runtime.GetRunSafetySnapshot(ctx, p.TenantID, sub.RunID)
	if err != nil {
		return failure("Runtime", err)
	}
	if !validRun(p, run, sub) {
		return ErrDenied
	}
	step, err := g.deps.Decision.VerifyProtectedStep(ctx, p, run, sub)
	if err != nil {
		return failure("protected Decision", err)
	}
	if !validProtectedStep(step, run, sub) {
		return ErrDenied
	}
	resolved, err := g.deps.Actions.ResolveWorkspaceWrite(ctx, p, run, sub)
	if err != nil {
		return failure("resolved WorkspaceWrite", err)
	}
	if resolved.Validate() != nil || !canonicalUUID.MatchString(resolved.OperationID) ||
		resolved.TenantID != p.TenantID || resolved.AgentID != run.AgentID ||
		resolved.WorkspaceID != sub.ResourceRef {
		return ErrDenied
	}
	// Bind the trusted resolved OperationID to the exact original submission
	// accepted by Guard. Signed approval alone never establishes provenance.
	accepted, err := g.deps.Accepted.ReadAcceptedSubmission(ctx, p.TenantID, resolved.OperationID)
	if err != nil {
		return failure("durable accepted submission", err)
	}
	if !validAcceptedSubmission(accepted, p.TenantID, resolved.OperationID, sub) {
		return ErrDenied
	}
	observed, err := g.deps.ACP.ObserveProtectedWorkspace(ctx, p, run, resolved, sub.Capability.Version)
	if err != nil {
		return failure("ACP protected catalog", err)
	}
	if !validACP(observed, resolved.PolicyVersion) {
		return ErrDenied
	}
	binding := approval.ExecutionBinding{
		RunID: step.RunID, AttemptID: step.AttemptID, TurnID: step.TurnID,
		AgentReleaseID: step.AgentReleaseID, DecisionID: step.DecisionID,
		PlanHash: step.PlanHash, StepID: step.StepID,
	}
	now := g.deps.Now().UTC()
	proof, err := approval.VerifyResolvedWorkspaceApproval(signedApproval, g.deps.ApprovalKey, resolved, binding, now)
	if err != nil {
		return failure("pinned signed approval", err)
	}
	current, err := g.deps.Approvals.CheckCurrentApproval(ctx, proof)
	if err != nil {
		return failure("live approval revocation", err)
	}
	if !validApproval(current, proof) {
		return ErrDenied
	}
	initialApproval := current
	risk, err := g.deps.Risk.EvaluateRisk(ctx, proof.Scope)
	if err != nil {
		return failure("live risk", err)
	}
	if !validRisk(risk, proof.Scope) {
		return ErrDenied
	}
	// Re-read ALL independently mutable sources, not just Runtime.
	// A point-in-time positive capability, risk result or approval revision
	// does not survive a concurrent source transition. These second reads
	// reduce stale success but are NOT a distributed atomic execution fence.
	after, err := g.deps.Runtime.GetRunSafetySnapshot(ctx, p.TenantID, sub.RunID)
	if err != nil {
		return failure("Runtime postflight", err)
	}
	if after != run {
		return ErrDenied
	}
	currentStep, err := g.deps.Decision.VerifyProtectedStep(ctx, p, after, sub)
	if err != nil {
		return failure("protected Decision postflight", err)
	}
	if !validProtectedStep(currentStep, after, sub) || !reflect.DeepEqual(currentStep, step) {
		return ErrDenied
	}
	// A live ToolBinding/Action resolver may change independently of
	// Runtime, Decision, ACP and the approval source. Re-resolve rather
	// than accept a previously valid workspace target or tool digest.
	// Equality is necessary only: there is still no atomic Permit fence.
	currentResolved, err := g.deps.Actions.ResolveWorkspaceWrite(ctx, p, after, sub)
	if err != nil {
		return failure("resolved WorkspaceWrite postflight", err)
	}
	if currentResolved.Validate() != nil || !reflect.DeepEqual(currentResolved, resolved) {
		return ErrDenied
	}
	currentACP, err := g.deps.ACP.ObserveProtectedWorkspace(ctx, p, after, currentResolved, sub.Capability.Version)
	if err != nil {
		return failure("ACP protected catalog postflight", err)
	}
	if currentACP != observed || !validACP(currentACP, resolved.PolicyVersion) {
		return ErrDenied
	}
	current, err = g.deps.Approvals.CheckCurrentApproval(ctx, proof)
	if err != nil {
		return failure("approval postflight", err)
	}
	if !validApproval(current, proof) || current != initialApproval {
		return ErrDenied
	}
	currentRisk, err := g.deps.Risk.EvaluateRisk(ctx, proof.Scope)
	if err != nil {
		return failure("risk postflight", err)
	}
	if !validRisk(currentRisk, proof.Scope) || currentRisk != risk {
		return ErrDenied
	}
	// Repeat the immutable-source read after all mutable authorities. An
	// inconsistent/different response is never a reusable permission.
	currentAccepted, err := g.deps.Accepted.ReadAcceptedSubmission(ctx, p.TenantID, resolved.OperationID)
	if err != nil {
		return failure("durable accepted submission postflight", err)
	}
	if !validAcceptedSubmission(currentAccepted, p.TenantID, resolved.OperationID, sub) ||
		!reflect.DeepEqual(currentAccepted, accepted) {
		return ErrDenied
	}
	if err := ctx.Err(); err != nil {
		return failure("context postflight", err)
	}
	// An initially fresh signature is not enough if independent live source
	// checks cross its short expiry window. Read the trusted clock again
	// immediately before returning; a backwards clock jump also fails
	// closed. This is still only a necessary preflight, not a Permit fence.
	finish := g.deps.Now().UTC()
	if finish.Before(now) || finish.Before(proof.IssuedAt) || !finish.Before(proof.ExpiresAt) {
		return ErrDenied
	}
	return nil
}
