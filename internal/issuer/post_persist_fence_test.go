package issuer

import (
	"context"
	"errors"
	"testing"
	"time"
)

type postPersistFenceLedger struct {
	afterPersist func()
	calls        int
}

func (l *postPersistFenceLedger) PersistIssuedPermit(_ context.Context, draft PermitDraft, _ time.Duration) (PersistedPermit, error) {
	l.calls++
	l.afterPersist()
	return PersistedPermit{PermitID: "10000000-0000-4000-8000-000000000010", Values: draft.Values()}, nil
}

func TestIssuerPostPersistFence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cancel bool
		delay  time.Duration
	}{
		{name: "canceled after durable write", cancel: true},
		{name: "expires during durable write", delay: 2 * time.Minute},
		{name: "expires before durable write returns", delay: 2*time.Minute + time.Microsecond},
		{name: "issuer clock regresses", delay: -time.Second},
		{name: "still valid after durable write", delay: time.Second},
		{name: "valid one microsecond before expiry", delay: 2*time.Minute - time.Microsecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 11, 24, 7, 0, 0, 0, time.UTC)
			resolved := resolvedActionRequest()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			authority := &actionRequestAuthority{result: authorizationForAction(t, resolved, now)}
			ledger := &postPersistFenceLedger{afterPersist: func() {
				now = now.Add(tc.delay)
				if tc.cancel {
					cancel()
				}
			}}
			service, err := New(Config{
				IssuerIdentity: "spiffe://platform.example/ns/guard/sa/issuer",
				MaxTTL:         5 * time.Minute,
				Now:            func() time.Time { return now },
			}, authority, ledger)
			if err != nil {
				t.Fatal(err)
			}
			permit, err := service.Issue(ctx, resolved)
			if ledger.calls != 1 {
				t.Fatalf("ledger calls=%d, want 1", ledger.calls)
			}
			switch {
			case tc.cancel:
				if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) || permit != (ScopedPermit{}) {
					t.Fatalf("canceled post-persist result: permit=%+v err=%v", permit, err)
				}
			case tc.delay >= 2*time.Minute || tc.delay < 0:
				if !errors.Is(err, ErrUnavailable) || permit != (ScopedPermit{}) {
					t.Fatalf("invalid post-persist result: permit=%+v err=%v", permit, err)
				}
			default:
				if err != nil || permit.PermitID == "" {
					t.Fatalf("valid post-persist result: permit=%+v err=%v", permit, err)
				}
			}
		})
	}
}
