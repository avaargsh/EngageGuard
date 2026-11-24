package admission

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/EngageGuard/internal/action"
)

type testDecisionPlanReceiptAuthority struct {
	receipt DecisionPlanReceipt
	err     error
	calls   int
}

func (a *testDecisionPlanReceiptAuthority) VerifyDecisionPlanStepReceipt(
	_ context.Context, _ Principal, _ RunSafetySnapshot, _ action.ActionSubmission,
) (DecisionPlanReceipt, error) {
	a.calls++
	return a.receipt, a.err
}

type testRuntimeExecutionAuthority struct {
	snapshots []RuntimeExecutionAuthoritySnapshot
	errs      []error
	calls     int
	tenant    string
	runID     string
	turnID    string
}

func (a *testRuntimeExecutionAuthority) GetGuardExecutionAuthority(
	_ context.Context, tenant, runID, turnID string,
) (RuntimeExecutionAuthoritySnapshot, error) {
	i := a.calls
	a.calls++
	a.tenant, a.runID, a.turnID = tenant, runID, turnID
	if i < len(a.errs) && a.errs[i] != nil {
		return RuntimeExecutionAuthoritySnapshot{}, a.errs[i]
	}
	if len(a.snapshots) == 0 {
		return RuntimeExecutionAuthoritySnapshot{}, ErrAuthorityUnavailable
	}
	if i >= len(a.snapshots) {
		i = len(a.snapshots) - 1
	}
	return a.snapshots[i], nil
}

func trustedRuntimeRunForExecutionBinding() RunSafetySnapshot {
	s := trustedRuntimeRun()
	s.RunID = safetyRun
	s.BreakerEpoch = 1
	s.BreakerVersion = 1
	return s
}

func trustedRuntimeExecutionBinding(s RunSafetySnapshot) RuntimeExecutionAuthoritySnapshot {
	return RuntimeExecutionAuthoritySnapshot{
		SchemaVersion:       runtimeExecutionAuthoritySchema,
		TenantID:            s.TenantID,
		RunID:               s.RunID,
		AgentID:             s.AgentID,
		AgentReleaseID:      s.AgentReleaseID,
		SessionID:           s.SessionID,
		WorkflowID:          "agent-run/v1/" + s.RunID,
		TemporalExecutionID: runtimeGuardExecution,
		RunAttemptID:        runtimeGuardAttempt,
		TurnID:              runtimeGuardTurn,
		InvocationID:        runtimeGuardTurn,
		TurnIndex:           1,
		AttemptGeneration:   1,
		AttemptBreakerEpoch: 1,
		Status:              "RUNNING",
		BreakerState:        "CLOSED",
		BreakerEpoch:        1,
		BreakerVersion:      1,
	}
}

func trustedRuntimeExecutionAuthority(s RunSafetySnapshot) *testRuntimeExecutionAuthority {
	snapshot := trustedRuntimeExecutionBinding(s)
	return &testRuntimeExecutionAuthority{snapshots: []RuntimeExecutionAuthoritySnapshot{snapshot, snapshot}}
}

func trustedDecisionPlanReceipt(s RunSafetySnapshot) DecisionPlanReceipt {
	return DecisionPlanReceipt{
		RunID:               s.RunID,
		RunAttemptID:        runtimeGuardAttempt,
		TurnID:              runtimeGuardTurn,
	}
}

func executionBindingSubmission(t *testing.T) action.ActionSubmission {
	t.Helper()
	submission := testGuardSubmission(t)
	submission.RunID = safetyRun
	return submission
}

func TestComposedRunVerifierRequiresDecisionSelectorsAndIndependentRuntimeBinding(t *testing.T) {
	safety := trustedRuntimeRunForExecutionBinding()
	submission := executionBindingSubmission(t)
	decision := &testDecisionPlanReceiptAuthority{receipt: trustedDecisionPlanReceipt(safety)}
	executionSnapshot := trustedRuntimeExecutionBinding(safety)
	execution := &testRuntimeExecutionAuthority{snapshots: []RuntimeExecutionAuthoritySnapshot{executionSnapshot, executionSnapshot}}
	capability := &testCapabilityAuthority{}
	reader := &testRunAuthority{snapshot: safety}

	verifier, err := NewComposedRunVerifier(reader, decision, capability, execution)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifySubmission(context.Background(), boundRuntime(), submission); err != nil {
		t.Fatalf("exact Runtime Attempt/Turn binding rejected: %v", err)
	}
	if reader.calls != 2 || decision.calls != 1 || execution.calls != 2 || capability.calls != 1 {
		t.Fatalf("wrong authority order: Run=%d Decision=%d RuntimeExecution=%d ACP=%d",
			reader.calls, decision.calls, execution.calls, capability.calls)
	}
	if execution.tenant != safety.TenantID || execution.runID != submission.RunID || execution.turnID != runtimeGuardTurn {
		t.Fatalf("Runtime execution selectors were not tenant/run/Decision receipt bound: %+v", execution)
	}
}

func TestComposedRunVerifierRejectsMissingDecisionAttemptOrTurnBeforeRuntime(t *testing.T) {
	safety := trustedRuntimeRunForExecutionBinding()
	for _, tc := range []struct {
		name   string
		mutate func(*DecisionPlanReceipt)
	}{
		{"missing Attempt", func(r *DecisionPlanReceipt) { r.RunAttemptID = "" }},
		{"missing Turn", func(r *DecisionPlanReceipt) { r.TurnID = "" }},
		{"noncanonical Attempt", func(r *DecisionPlanReceipt) { r.RunAttemptID = "attempt-1" }},
		{"noncanonical Turn", func(r *DecisionPlanReceipt) { r.TurnID = "turn-1" }},
		{"different Run", func(r *DecisionPlanReceipt) { r.RunID = "99999999-9999-4999-8999-999999999999" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receipt := trustedDecisionPlanReceipt(safety)
			tc.mutate(&receipt)
			decision := &testDecisionPlanReceiptAuthority{receipt: receipt}
			execution := &testRuntimeExecutionAuthority{snapshots: []RuntimeExecutionAuthoritySnapshot{trustedRuntimeExecutionBinding(safety)}}
			capability := &testCapabilityAuthority{}
			verifier, err := NewComposedRunVerifier(
				&testRunAuthority{snapshot: safety}, decision, capability, execution,
			)
			if err != nil {
				t.Fatal(err)
			}
			err = verifier.VerifySubmission(context.Background(), boundRuntime(), executionBindingSubmission(t))
			if !errors.Is(err, ErrForbidden) {
				t.Fatalf("invalid Decision selectors accepted: %v", err)
			}
			if execution.calls != 0 || capability.calls != 0 {
				t.Fatalf("invalid selectors reached Runtime or ACP: Runtime=%d ACP=%d", execution.calls, capability.calls)
			}
		})
	}
}

func TestComposedRunVerifierRequiresExactRuntimeAttemptTurnAndFences(t *testing.T) {
	safety := trustedRuntimeRunForExecutionBinding()
	for _, tc := range []struct {
		name   string
		mutate func(*RuntimeExecutionAuthoritySnapshot)
	}{
		{"different Attempt", func(a *RuntimeExecutionAuthoritySnapshot) { a.RunAttemptID = "55555555-5555-4555-8555-555555555555" }},
		{"different Turn", func(a *RuntimeExecutionAuthoritySnapshot) { a.TurnID = "55555555-5555-4555-8555-555555555555" }},
		{"different Invocation", func(a *RuntimeExecutionAuthoritySnapshot) { a.InvocationID = "55555555-5555-4555-8555-555555555555" }},
		{"different Agent", func(a *RuntimeExecutionAuthoritySnapshot) { a.AgentID = "other-agent" }},
		{"different Release", func(a *RuntimeExecutionAuthoritySnapshot) { a.AgentReleaseID = "other-release" }},
		{"different Session", func(a *RuntimeExecutionAuthoritySnapshot) { a.SessionID = "other-session" }},
		{"generation drift", func(a *RuntimeExecutionAuthoritySnapshot) { a.AttemptGeneration = 2 }},
		{"Attempt breaker epoch drift", func(a *RuntimeExecutionAuthoritySnapshot) { a.AttemptBreakerEpoch = 2 }},
		{"breaker epoch drift", func(a *RuntimeExecutionAuthoritySnapshot) { a.BreakerEpoch = 2 }},
		{"breaker version drift", func(a *RuntimeExecutionAuthoritySnapshot) { a.BreakerVersion = 2 }},
		{"breaker open", func(a *RuntimeExecutionAuthoritySnapshot) { a.BreakerState = "OPEN" }},
		{"terminal Run", func(a *RuntimeExecutionAuthoritySnapshot) { a.Status = "CANCELLED" }},
		{"wrong workflow", func(a *RuntimeExecutionAuthoritySnapshot) { a.WorkflowID = "other-workflow" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := trustedRuntimeExecutionBinding(safety)
			tc.mutate(&bad)
			decision := &testDecisionPlanReceiptAuthority{receipt: trustedDecisionPlanReceipt(safety)}
			execution := &testRuntimeExecutionAuthority{snapshots: []RuntimeExecutionAuthoritySnapshot{bad}}
			capability := &testCapabilityAuthority{}
			verifier, err := NewComposedRunVerifier(
				&testRunAuthority{snapshot: safety}, decision, capability, execution,
			)
			if err != nil {
				t.Fatal(err)
			}
			err = verifier.VerifySubmission(context.Background(), boundRuntime(), executionBindingSubmission(t))
			if !errors.Is(err, ErrForbidden) {
				t.Fatalf("mismatched Runtime execution authority accepted: %v", err)
			}
			if capability.calls != 0 || execution.calls != 1 {
				t.Fatalf("mismatched execution reached ACP: Runtime=%d ACP=%d", execution.calls, capability.calls)
			}
		})
	}
}

func TestComposedRunVerifierRejectsTurnSupersededDuringACPRead(t *testing.T) {
	safety := trustedRuntimeRunForExecutionBinding()
	first := trustedRuntimeExecutionBinding(safety)
	second := first
	second.TurnID = "55555555-5555-4555-8555-555555555555"
	second.InvocationID = second.TurnID
	second.TurnIndex = 2
	decision := &testDecisionPlanReceiptAuthority{receipt: trustedDecisionPlanReceipt(safety)}
	execution := &testRuntimeExecutionAuthority{snapshots: []RuntimeExecutionAuthoritySnapshot{first, second}}
	capability := &testCapabilityAuthority{}
	verifier, err := NewComposedRunVerifier(
		&testRunAuthority{snapshot: safety}, decision, capability, execution,
	)
	if err != nil {
		t.Fatal(err)
	}
	err = verifier.VerifySubmission(context.Background(), boundRuntime(), executionBindingSubmission(t))
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("superseded Turn accepted after ACP read: %v", err)
	}
	if execution.calls != 2 || capability.calls != 1 {
		t.Fatalf("missing postflight execution authority read: Runtime=%d ACP=%d", execution.calls, capability.calls)
	}
}

func TestComposedRunVerifierFailsClosedWhenRuntimeExecutionAuthorityUnavailable(t *testing.T) {
	safety := trustedRuntimeRunForExecutionBinding()
	for _, tc := range []struct {
		name   string
		err  error
		want error
	}{
		{"denied", ErrForbidden, ErrForbidden},
		{"unavailable", errors.New("Runtime execution authority timeout"), ErrAuthorityUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decision := &testDecisionPlanReceiptAuthority{receipt: trustedDecisionPlanReceipt(safety)}
			execution := &testRuntimeExecutionAuthority{errs: []error{tc.err}}
			capability := &testCapabilityAuthority{}
			verifier, err := NewComposedRunVerifier(
				&testRunAuthority{snapshot: safety}, decision, capability, execution,
			)
			if err != nil {
				t.Fatal(err)
			}
			err = verifier.VerifySubmission(context.Background(), boundRuntime(), executionBindingSubmission(t))
			if !errors.Is(err, tc.want) {
				t.Fatalf("Runtime execution authority error was not preserved: %v want %v", err, tc.want)
			}
			if capability.calls != 0 {
				t.Fatalf("Runtime execution failure reached ACP capability authority: %d", capability.calls)
			}
		})
	}
}
