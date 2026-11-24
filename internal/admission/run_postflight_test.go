package admission

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// This fake authoritative Runtime changes between live reads. Assertions
// cover returned safety errors and persisted operation effects, not a mock
// call sequence in place of behavioral verification.
type postflightSafetyAuthority struct {
	first       RunSafetySnapshot
	second      RunSafetySnapshot
	secondError error
	calls       int
}

func (a *postflightSafetyAuthority) GetRunSafetySnapshot(_ context.Context, tenantID, runID string) (RunSafetySnapshot, error) {
	a.calls++
	if tenantID != "tenant-verified" || runID != safetyRun {
		return RunSafetySnapshot{}, ErrForbidden
	}
	if a.calls > 1 {
		return a.second, a.secondError
	}
	return a.first, nil
}

type flippingCapabilityAuthority struct{ calls int }

func (a *flippingCapabilityAuthority) VerifyCapabilityAccess(_ context.Context, _ Principal, s RunSafetySnapshot, _ action.ActionSubmission) error {
	a.calls++
	if s.Status != "RUNNING" || s.BreakerState != "CLOSED" {
		return ErrForbidden
	}
	return nil
}

// A successful initial safety read is not sufficient: Guard must observe
// the same authority generation after the independent Decision and ACP reads.
// This reduces a real TOCTOU window but does not create a distributed Permit.
func TestComposedVerifierPostflightRunSafetyCannotChangeDuringAuthorityReads(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*RunSafetySnapshot)
		err    error
		want   error
	}{
		{"unchanged", nil, nil, nil},
		{"breaker opened", func(s *RunSafetySnapshot) { s.BreakerState = "OPEN"; s.BreakerVersion++ }, nil, ErrForbidden},
		{"breaker epoch changed", func(s *RunSafetySnapshot) { s.BreakerEpoch++; s.BreakerVersion++ }, nil, ErrForbidden},
		{"breaker version changed", func(s *RunSafetySnapshot) { s.BreakerVersion++ }, nil, ErrForbidden},
		{"run canceled", func(s *RunSafetySnapshot) { s.Status = "CANCELLED" }, nil, ErrForbidden},
		{"agent release changed", func(s *RunSafetySnapshot) { s.AgentReleaseID = "release-other" }, nil, ErrForbidden},
		{"tenant changed", func(s *RunSafetySnapshot) { s.TenantID = "different-tenant" }, nil, ErrForbidden},
		{"network unavailable", nil, errors.New("safety RPC failed"), ErrAuthorityUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			initial := trustedRuntimeRun()
			after := initial
			if tc.mutate != nil {
				tc.mutate(&after)
			}
			reader := &postflightSafetyAuthority{first: initial, second: after, secondError: tc.err}
			decision := &testDecisionPlanAuthority{}
			capability := &flippingCapabilityAuthority{}
			verifier, err := NewComposedRunVerifier(reader, decision, capability, trustedRuntimeExecutionAuthority(initial))
			if err != nil {
				t.Fatal(err)
			}
			err = verifier.VerifySubmission(context.Background(), boundRuntime(), testGuardSubmission(t))
			if !errors.Is(err, tc.want) {
				t.Fatalf("postflight change %q resulted in %v; want %v", tc.name, err, tc.want)
			}
			if reader.calls != 2 || decision.calls != 1 || capability.calls != 1 {
				t.Fatalf("admission did not recheck in order: run=%d decision=%d capability=%d",
					reader.calls, decision.calls, capability.calls)
			}
		})
	}
}

func TestGuardHTTPNeverWritesAfterPostflightBreakerChange(t *testing.T) {
	before := trustedRuntimeRun()
	after := before
	after.BreakerState = "OPEN"
	after.BreakerEpoch++
	after.BreakerVersion++
	reader := &postflightSafetyAuthority{first: before, second: after}
	verifier, err := NewComposedRunVerifier(reader, &testDecisionPlanAuthority{}, &flippingCapabilityAuthority{}, trustedRuntimeExecutionAuthority(before))
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{}
	handler := NewHandler(&fakeResolver{principal: boundRuntime()}, verifier, store)
	res := exercise(handler, "postflight-flip", goodBody())
	if res.Code != http.StatusForbidden || store.calls != 0 || reader.calls != 2 {
		t.Fatalf("postflight stale acceptance: status=%d writes=%d safety-reads=%d",
			res.Code, store.calls, reader.calls)
	}
}
