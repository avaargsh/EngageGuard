package executorpep

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/EngageGuard/internal/action"
)

type cancelingPreflightAuthority struct {
	cancel context.CancelFunc
	calls  int
}

func (a *cancelingPreflightAuthority) VerifyCurrent(context.Context, string, string, string, action.WorkspaceWrite) error {
	a.calls++
	a.cancel()
	return nil
}

func TestExecutorPreEffectStopsAfterCanceledLiveRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ca := issueTestCA(t)
	ledger := &fakeLedger{}
	live := &cancelingPreflightAuthority{cancel: cancel}
	gate := makeGate(t, ca.cert, ledger, live)
	err := gate.Check(ctx, verifiedPeer(t, ca, goodExecutorID), testPermitID, testAttemptID, resolvedWorkspaceWrite())
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled preflight must be unavailable: %v", err)
	}
	if live.calls != 1 || ledger.calls != 0 {
		t.Fatalf("canceled preflight must not start another source read: live=%d ledger=%d", live.calls, ledger.calls)
	}
}
