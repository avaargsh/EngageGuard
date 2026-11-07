package admission

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/avaargsh/EngageGuard/internal/action"
)

type testRunAuthority struct {
	snapshot RunSafetySnapshot
	err      error
	calls    int
	tenant   string
	run      string
}

func (a *testRunAuthority) GetRunSafetySnapshot(_ context.Context, tenantID, runID string) (RunSafetySnapshot, error) {
	a.calls++
	a.tenant, a.run = tenantID, runID
	return a.snapshot, a.err
}

type testDecisionPlanAuthority struct {
	err        error
	calls      int
	snapshot   RunSafetySnapshot
	principal  Principal
	submission action.ActionSubmission
}

func (a *testDecisionPlanAuthority) VerifyDecisionPlanStep(
	_ context.Context, principal Principal, run RunSafetySnapshot, submission action.ActionSubmission,
) error {
	a.calls++
	a.principal, a.snapshot, a.submission = principal, run, submission
	return a.err
}

type testCapabilityAuthority struct {
	err        error
	calls      int
	snapshot   RunSafetySnapshot
	submission action.ActionSubmission
}

func (a *testCapabilityAuthority) VerifyCapabilityAccess(
	_ context.Context, _ Principal, run RunSafetySnapshot, submission action.ActionSubmission,
) error {
	a.calls++
	a.snapshot, a.submission = run, submission
	return a.err
}

func trustedRuntimeRun() RunSafetySnapshot {
	return RunSafetySnapshot{
		TenantID: "tenant-verified", RunID: "run-1", AgentID: "agent-1",
		AgentReleaseID: "release-1", SessionID: "session-1", Status: "RUNNING",
		BreakerState: "CLOSED", BreakerEpoch: 3, BreakerVersion: 11,
	}
}

func testGuardSubmission(t *testing.T) action.ActionSubmission {
	t.Helper()
	result, err := action.ParseActionSubmission([]byte(goodBody()))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestComposedRunVerifierRequiresAllThreeAuthorities(t *testing.T) {
	reader := &testRunAuthority{snapshot: trustedRuntimeRun()}
	decision := &testDecisionPlanAuthority{}
	capability := &testCapabilityAuthority{}
	for _, tc := range []struct {
		name       string
		reader     RunSafetyAuthority
		decision   DecisionPlanAuthority
		capability CapabilityAuthority
	}{
		{"nil Runtime", nil, decision, capability},
		{"nil Decision", reader, nil, capability},
		{"nil Capability", reader, decision, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewComposedRunVerifier(tc.reader, tc.decision, tc.capability)
			if !errors.Is(err, ErrAuthorityUnavailable) {
				t.Fatalf("incomplete authority graph accepted: %v", err)
			}
		})
	}
}

func TestComposedRunVerifierBindsRuntimeTenantAndRunBeforeDecision(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*RunSafetySnapshot)
	}{
		{"different tenant", func(s *RunSafetySnapshot) { s.TenantID = "tenant-attacker" }},
		{"different run", func(s *RunSafetySnapshot) { s.RunID = "run-attacker" }},
		{"empty agent", func(s *RunSafetySnapshot) { s.AgentID = "" }},
		{"empty release", func(s *RunSafetySnapshot) { s.AgentReleaseID = "" }},
		{"empty session", func(s *RunSafetySnapshot) { s.SessionID = "" }},
		{"not running", func(s *RunSafetySnapshot) { s.Status = "SUCCEEDED" }},
		{"unknown status", func(s *RunSafetySnapshot) { s.Status = "UNKNOWN" }},
		{"breaker open", func(s *RunSafetySnapshot) { s.BreakerState = "OPEN" }},
		{"breaker half open", func(s *RunSafetySnapshot) { s.BreakerState = "HALF_OPEN" }},
		{"missing breaker epoch", func(s *RunSafetySnapshot) { s.BreakerEpoch = 0 }},
		{"missing breaker version", func(s *RunSafetySnapshot) { s.BreakerVersion = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := trustedRuntimeRun()
			tc.mutate(&snapshot)
			reader := &testRunAuthority{snapshot: snapshot}
			decision := &testDecisionPlanAuthority{}
			capability := &testCapabilityAuthority{}
			verifier, err := NewComposedRunVerifier(reader, decision, capability)
			if err != nil {
				t.Fatal(err)
			}
			err = verifier.VerifySubmission(context.Background(), boundRuntime(), testGuardSubmission(t))
			if !errors.Is(err, ErrForbidden) {
				t.Fatalf("untrusted Run snapshot not rejected: %v", err)
			}
			if reader.calls != 1 || reader.tenant != "tenant-verified" || reader.run != "run-1" ||
				decision.calls != 0 || capability.calls != 0 {
				t.Fatalf("unauthorized Run reached downstream authority: Run=%+v Decision=%d Capability=%d",
					reader, decision.calls, capability.calls)
			}
		})
	}
}

func TestComposedRunVerifierRequiresDecisionAndACPAuthority(t *testing.T) {
	for _, tc := range []struct {
		name            string
		readErr         error
		decisionErr     error
		capabilityErr   error
		want            error
		decisionCalls   int
		capabilityCalls int
	}{
		{"Runtime denied", ErrForbidden, nil, nil, ErrForbidden, 0, 0},
		{"Runtime unavailable", errors.New("backend down"), nil, nil, ErrAuthorityUnavailable, 0, 0},
		{"Decision denied", nil, ErrForbidden, nil, ErrForbidden, 1, 0},
		{"Decision unavailable", nil, errors.New("Decision unavailable"), nil, ErrAuthorityUnavailable, 1, 0},
		{"ACP capability denied", nil, nil, ErrForbidden, ErrForbidden, 1, 1},
		{"ACP capability unavailable", nil, nil, errors.New("ACP unavailable"), ErrAuthorityUnavailable, 1, 1},
		{"all authorities accept", nil, nil, nil, nil, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &testRunAuthority{snapshot: trustedRuntimeRun(), err: tc.readErr}
			decision := &testDecisionPlanAuthority{err: tc.decisionErr}
			capability := &testCapabilityAuthority{err: tc.capabilityErr}
			verifier, err := NewComposedRunVerifier(reader, decision, capability)
			if err != nil {
				t.Fatal(err)
			}
			submission := testGuardSubmission(t)
			err = verifier.VerifySubmission(context.Background(), boundRuntime(), submission)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v; expected %v", err, tc.want)
			}
			if reader.calls != 1 || decision.calls != tc.decisionCalls || capability.calls != tc.capabilityCalls {
				t.Fatalf("invalid authority invocation order: read=%d decision=%d capability=%d",
					reader.calls, decision.calls, capability.calls)
			}
			if tc.want == nil && (decision.snapshot != trustedRuntimeRun() ||
				capability.snapshot != trustedRuntimeRun() ||
				decision.principal != boundRuntime() ||
				decision.submission.RunID != submission.RunID ||
				capability.submission.StepID != submission.StepID) {
				t.Fatal("authorities did not receive the authenticated Principal, canonical Run snapshot and full action intent")
			}
		})
	}
}

func TestComposedRunVerifierReplayRevalidatesRunBreakerBeforeAccept(t *testing.T) {
	reader := &testRunAuthority{snapshot: trustedRuntimeRun()}
	decision := &testDecisionPlanAuthority{}
	capability := &testCapabilityAuthority{}
	verifier, err := NewComposedRunVerifier(reader, decision, capability)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{}
	resolver := &fakeResolver{principal: boundRuntime()}
	handler := NewHandler(resolver, verifier, store)
	first := exercise(handler, "guard-authority-key", goodBody())
	if first.Code != http.StatusCreated || store.calls != 1 {
		t.Fatalf("first admission rejected: status=%d writes=%d", first.Code, store.calls)
	}
	reader.snapshot.BreakerState = "OPEN"
	denied := exercise(handler, "guard-authority-key", goodBody())
	if denied.Code != http.StatusForbidden || store.calls != 1 ||
		reader.calls != 2 || decision.calls != 1 || capability.calls != 1 {
		t.Fatalf("replay bypassed current Run breaker: status=%d writes=%d calls=%d/%d/%d",
			denied.Code, store.calls, reader.calls, decision.calls, capability.calls)
	}
	reader.snapshot.BreakerState = "CLOSED"
	capability.err = errors.New("ACP policy unavailable")
	unavailable := exercise(handler, "guard-authority-key", goodBody())
	if unavailable.Code != http.StatusServiceUnavailable || store.calls != 1 {
		t.Fatalf("authority outage replay accepted: status=%d writes=%d", unavailable.Code, store.calls)
	}
}
