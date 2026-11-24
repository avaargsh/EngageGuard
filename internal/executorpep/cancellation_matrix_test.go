package executorpep

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/EngageGuard/internal/action"
)

type cancelingLedgerRead struct {
	cancel   context.CancelFunc
	cancelAt int
	calls    int
}

func (l *cancelingLedgerRead) InspectPreEffectLedger(context.Context, string, string, action.WorkspaceWrite) error {
	l.calls++
	if l.calls == l.cancelAt {
		l.cancel()
	}
	return nil
}

func TestExecutorPreEffectCancellationAfterLedgerRead(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cancelAt int
	}{
		{"first ledger observation", 1},
		{"final ledger observation", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ca := issueTestCA(t)
			ledger := &cancelingLedgerRead{cancel: cancel, cancelAt: tc.cancelAt}
			live := &fakeLive{}
			gate := makeGate(t, ca.cert, ledger, live)
			err := gate.Check(ctx, verifiedPeer(t, ca, goodExecutorID), testPermitID, testAttemptID, resolvedWorkspaceWrite())
			if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled ledger observation must not pass: %v", err)
			}
			if ledger.calls != tc.cancelAt || live.calls != tc.cancelAt {
				t.Fatalf("unexpected reads after cancellation: ledger=%d live=%d", ledger.calls, live.calls)
			}
		})
	}
}

func TestExecutorPreEffectAlreadyCanceledContextStartsNoReads(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ca := issueTestCA(t)
	ledger, live := &fakeLedger{}, &fakeLive{}
	gate := makeGate(t, ca.cert, ledger, live)
	err := gate.Check(ctx, verifiedPeer(t, ca, goodExecutorID), testPermitID, testAttemptID, resolvedWorkspaceWrite())
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("already canceled request must be unavailable: %v", err)
	}
	if ledger.calls != 0 || live.calls != 0 {
		t.Fatalf("already canceled request started authority reads: ledger=%d live=%d", ledger.calls, live.calls)
	}
}
