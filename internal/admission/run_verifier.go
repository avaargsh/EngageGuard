package admission

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// ErrAuthorityUnavailable means one or more required authoritative sources
// could not establish current Run, Decision/Plan, or ACP policy state.
// Admission must not fall back to untrusted claims or cached approvals.
var ErrAuthorityUnavailable = errors.New("Guard admission authority unavailable")

// RunSafetySnapshot is a read-only projection of Runtime-owned Run state and
// RUN circuit-breaker fencing. Its fields mirror Runtime's
// GuardRunSafetySnapshot, but this package does not import another service's
// internal Go types or read its PostgreSQL tables.
type RunSafetySnapshot struct {
	TenantID       string
	RunID          string
	AgentID        string
	AgentReleaseID string
	SessionID      string
	Status         string
	BreakerState   string
	BreakerEpoch   uint64
	BreakerVersion uint64
}

// RunSafetyAuthority must read fresh, canonical tenant-scoped Run state from
// Runtime's trusted authority. No caller-provided snapshot may implement this
// contract. A successful read is only a safety precondition, not permission.
type RunSafetyAuthority interface {
	GetRunSafetySnapshot(context.Context, string, string) (RunSafetySnapshot, error)
}

// DecisionPlanAuthority verifies the current immutable DecisionRecord and
// requested PlanHash/PlanID/StepID/resource/arguments provenance against the
// authoritative Decision and Plan records, including Run/AgentRelease binding.
// It must reject a stale/revoked plan, never trust caller fields as authority.
type DecisionPlanAuthority interface {
	VerifyDecisionPlanStep(context.Context, Principal, RunSafetySnapshot, action.ActionSubmission) error
}

// CapabilityAuthority verifies the version-pinned capability contract and
// tenant/AgentRelease/policy visibility against ACP-owned state. It must
// reject revoked or unavailable capabilities rather than returning nil.
type CapabilityAuthority interface {
	VerifyCapabilityAccess(context.Context, Principal, RunSafetySnapshot, action.ActionSubmission) error
}

// ComposedRunVerifier enforces all three *independent* admission checks.
// There is no authorization, Permit issuance, side effect or persistent state.
// A concurrent breaker transition after this read is not atomically fenced:
// G03/G05 execution still requires a later authoritative Guard safety gate.
type ComposedRunVerifier struct {
	run        RunSafetyAuthority
	decision   DecisionPlanAuthority
	capability CapabilityAuthority
}

func nilAuthority(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func NewComposedRunVerifier(
	run RunSafetyAuthority, decision DecisionPlanAuthority, capability CapabilityAuthority,
) (*ComposedRunVerifier, error) {
	if nilAuthority(run) || nilAuthority(decision) || nilAuthority(capability) {
		return nil, fmt.Errorf("%w: Runtime, Decision and ACP are all mandatory", ErrAuthorityUnavailable)
	}
	return &ComposedRunVerifier{run: run, decision: decision, capability: capability}, nil
}

func validRuntimeIdentity(value string) bool {
	return value != "" && len(value) <= 255 &&
		strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t")
}

func (v *ComposedRunVerifier) VerifySubmission(
	ctx context.Context, principal Principal, submission action.ActionSubmission,
) error {
	if v == nil || nilAuthority(v.run) || nilAuthority(v.decision) || nilAuthority(v.capability) {
		return ErrAuthorityUnavailable
	}
	if principal.ServiceID != "agent-runtime" ||
		!validIdentity(principal.TenantID) || !validIdentity(principal.SubjectID) ||
		!validIdentity(principal.ActorID) || !validIdentity(principal.WorkloadID) {
		return ErrForbidden
	}
	if err := submission.Validate(); err != nil {
		return ErrForbidden
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: request context canceled: %w", ErrAuthorityUnavailable, err)
	}

	// Always ask Runtime for the current state, including on a duplicate
	// submission key. Do not reuse a previously accepted safety snapshot.
	snapshot, err := v.run.GetRunSafetySnapshot(ctx, principal.TenantID, submission.RunID)
	if err != nil {
		return verifyAuthorityFailure("Runtime Run", err)
	}
	if snapshot.TenantID != principal.TenantID || snapshot.RunID != submission.RunID ||
		!validRuntimeIdentity(snapshot.AgentID) ||
		!validRuntimeIdentity(snapshot.AgentReleaseID) ||
		!validRuntimeIdentity(snapshot.SessionID) ||
		snapshot.Status != "RUNNING" || snapshot.BreakerState != "CLOSED" ||
		snapshot.BreakerEpoch == 0 || snapshot.BreakerVersion == 0 {
		return ErrForbidden
	}

	// Separate authority owners must validate immutable provenance and
	// current policy. A successful Runtime read alone cannot admit an Action.
	if err := v.decision.VerifyDecisionPlanStep(ctx, principal, snapshot, submission); err != nil {
		return verifyAuthorityFailure("Decision/Plan/Step", err)
	}
	if err := v.capability.VerifyCapabilityAccess(ctx, principal, snapshot, submission); err != nil {
		return verifyAuthorityFailure("ACP capability/policy", err)
	}
	return nil
}

func verifyAuthorityFailure(phase string, err error) error {
	if errors.Is(err, ErrForbidden) {
		return ErrForbidden
	}
	return fmt.Errorf("%w: %s: %w", ErrAuthorityUnavailable, phase, err)
}
