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
// could not establish current Run, Decision/Plan, ACP policy, or Attempt/Turn
// state. Admission must not fall back to untrusted claims or cached approvals.
var ErrAuthorityUnavailable = errors.New("Guard admission authority unavailable")

// RunSafetySnapshot is a read-only projection of Runtime-owned Run state and
// RUN circuit-breaker fencing. It is necessary context, not authorization.
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

// DecisionPlanReceipt carries only untrusted selectors copied from Decision's
// successful, read-only Plan Step verification. Runtime must independently
// confirm the Attempt/Turn tuple before Guard can continue.
type DecisionPlanReceipt struct {
	RunID        string
	RunAttemptID string
	TurnID       string
}

type RunSafetyAuthority interface {
	GetRunSafetySnapshot(context.Context, string, string) (RunSafetySnapshot, error)
}

// DecisionPlanAuthority verifies immutable Decision/Plan/Step provenance and
// returns canonical Runtime Attempt/Turn selectors. Those selectors are not
// authority and are never accepted without a second Runtime read.
type DecisionPlanAuthority interface {
	VerifyDecisionPlanStepReceipt(context.Context, Principal, RunSafetySnapshot, action.ActionSubmission) (DecisionPlanReceipt, error)
}

// RuntimeExecutionAuthority is a separate Runtime read boundary dedicated to
// Guard. It verifies the Decision selectors against the current Run/Attempt/
// Turn. It must not be implemented by caller data or a Decision receipt.
type RuntimeExecutionAuthority interface {
	GetGuardExecutionAuthority(context.Context, string, string, string) (RuntimeExecutionAuthoritySnapshot, error)
}

// CapabilityAuthority verifies version-pinned capability contract and
// tenant/AgentRelease/policy visibility against ACP-owned state.
type CapabilityAuthority interface {
	VerifyCapabilityAccess(context.Context, Principal, RunSafetySnapshot, action.ActionSubmission) error
}

// ComposedRunVerifier performs four independent, read-only authority checks.
// Success is admission evidence only; it is not Approval, Risk, Permit or
// permission to execute a protected effect. Permit issuer and Executor PEP
// must still revalidate and atomically fence the effect-time state.
type ComposedRunVerifier struct {
	run        RunSafetyAuthority
	decision   DecisionPlanAuthority
	execution  RuntimeExecutionAuthority
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
	run RunSafetyAuthority,
	decision DecisionPlanAuthority,
	capability CapabilityAuthority,
	execution RuntimeExecutionAuthority,
) (*ComposedRunVerifier, error) {
	if nilAuthority(run) || nilAuthority(decision) || nilAuthority(capability) || nilAuthority(execution) {
		return nil, fmt.Errorf("%w: Runtime Run, Decision, Runtime Attempt/Turn and ACP are all mandatory", ErrAuthorityUnavailable)
	}
	return &ComposedRunVerifier{
		run: run, decision: decision, execution: execution, capability: capability,
	}, nil
}

func validRuntimeIdentity(value string) bool {
	return value != "" && len(value) <= 255 &&
		strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t")
}

func (v *ComposedRunVerifier) VerifySubmission(
	ctx context.Context, principal Principal, submission action.ActionSubmission,
) error {
	if v == nil || nilAuthority(v.run) || nilAuthority(v.decision) ||
		nilAuthority(v.execution) || nilAuthority(v.capability) || ctx == nil {
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

	// Always ask Runtime for the current Run, including on duplicate submission
	// keys. No caller-provided snapshot or previously accepted state is reused.
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
	const maxInt64 = uint64(1<<63 - 1)
	if snapshot.BreakerEpoch > maxInt64 || snapshot.BreakerVersion > maxInt64 {
		return ErrForbidden
	}

	// Decision is a provenance verifier only. Its Attempt/Turn values are
	// selectors and cannot authorize an action or replace Runtime authority.
	receipt, err := v.decision.VerifyDecisionPlanStepReceipt(ctx, principal, snapshot, submission)
	if err != nil {
		return verifyAuthorityFailure("Decision/Plan/Step", err)
	}
	if receipt.RunID != submission.RunID ||
		!canonicalSafetyRunID.MatchString(receipt.RunID) ||
		!canonicalSafetyRunID.MatchString(receipt.RunAttemptID) ||
		!canonicalSafetyRunID.MatchString(receipt.TurnID) {
		return ErrForbidden
	}

	// Independently resolve the exact Run/Attempt/Turn from Runtime. Compare
	// all immutable principal and breaker fields with the first Run snapshot.
	execution, err := v.execution.GetGuardExecutionAuthority(
		ctx, principal.TenantID, submission.RunID, receipt.TurnID,
	)
	if err != nil {
		return verifyAuthorityFailure("Runtime Attempt/Turn", err)
	}
	if err := execution.validate(principal.TenantID, submission.RunID, receipt.TurnID); err != nil {
		return err
	}
	if execution.RunAttemptID != receipt.RunAttemptID ||
		execution.AgentID != snapshot.AgentID ||
		execution.AgentReleaseID != snapshot.AgentReleaseID ||
		execution.SessionID != snapshot.SessionID ||
		execution.Status != snapshot.Status ||
		execution.BreakerState != snapshot.BreakerState ||
		execution.BreakerEpoch != int64(snapshot.BreakerEpoch) ||
		execution.BreakerVersion != int64(snapshot.BreakerVersion) {
		return ErrForbidden
	}

	// ACP policy is checked only after the canonical Runtime Attempt/Turn
	// pair is established. It is not allowed to supply or change that pair.
	if err := v.capability.VerifyCapabilityAccess(ctx, principal, snapshot, submission); err != nil {
		return verifyAuthorityFailure("ACP capability/policy", err)
	}

	// Postflight both authority reads. This narrows (but cannot eliminate) a
	// distributed TOCTOU window; the later Permit issuer and Executor PEP must
	// still fence the exact effect atomically at the protected boundary.
	postflight, err := v.run.GetRunSafetySnapshot(ctx, principal.TenantID, submission.RunID)
	if err != nil {
		return verifyAuthorityFailure("Runtime Run postflight", err)
	}
	if postflight != snapshot {
		return ErrForbidden
	}
	postflightExecution, err := v.execution.GetGuardExecutionAuthority(
		ctx, principal.TenantID, submission.RunID, receipt.TurnID,
	)
	if err != nil {
		return verifyAuthorityFailure("Runtime Attempt/Turn postflight", err)
	}
	if err := postflightExecution.validate(principal.TenantID, submission.RunID, receipt.TurnID); err != nil {
		return err
	}
	if postflightExecution != execution {
		return ErrForbidden
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: postflight context canceled: %w", ErrAuthorityUnavailable, err)
	}
	return nil
}

func verifyAuthorityFailure(phase string, err error) error {
	if errors.Is(err, ErrForbidden) {
		return ErrForbidden
	}
	return fmt.Errorf("%w: %s: %w", ErrAuthorityUnavailable, phase, err)
}
