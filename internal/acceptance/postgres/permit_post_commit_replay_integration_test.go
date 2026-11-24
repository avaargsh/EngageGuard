package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/EngageGuard/internal/issuer"
)

// Wrap the real PostgreSQL ledger, canceling only after its transaction
// commits. This models a lost response without changing ledger semantics.
type cancelAfterPermitCommit struct {
	ledger    *PermitIssuerLedger
	cancel    context.CancelFunc
	persisted issuer.PersistedPermit
}

func (l *cancelAfterPermitCommit) PersistIssuedPermit(ctx context.Context, draft issuer.PermitDraft, maxTTL time.Duration) (issuer.PersistedPermit, error) {
	got, err := l.ledger.PersistIssuedPermit(ctx, draft, maxTTL)
	if err == nil {
		l.persisted = got
		l.cancel()
	}
	return got, err
}

func TestPermitIssuerPostCommitCancellationPreservesReplayEvidence(t *testing.T) {
	store, db := integrationStore(t)
	_, authority, resolved := acceptedPermitIssuer(t, store)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ledger, err := NewPermitIssuerLedger(store)
	if err != nil {
		t.Fatal(err)
	}
	interrupted := &cancelAfterPermitCommit{ledger: ledger, cancel: cancel}
	cfg := issuer.Config{
		IssuerIdentity: "spiffe://platform.example/ns/guard/sa/issuer",
		MaxTTL:         5 * time.Minute,
		Now:            time.Now,
	}
	service, err := issuer.New(cfg, authority, interrupted)
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.Issue(ctx, resolved)
	if !errors.Is(err, issuer.ErrUnavailable) || !errors.Is(err, context.Canceled) || got != (issuer.ScopedPermit{}) {
		t.Fatalf("canceled response returned a usable Permit: got=%+v err=%v", got, err)
	}
	if interrupted.persisted.PermitID == "" {
		t.Fatal("test did not reach a successful real ledger commit")
	}

	// Use a fresh context: the original canceled caller must not prevent
	// inspection of the durable state or recovery by a restarted issuer.
	recoveryCtx := context.Background()
	assertDurableRows := func() {
		t.Helper()
		var permits, evidence int
		if err := db.QueryRowContext(recoveryCtx,
			"SELECT count(*) FROM guard_permits WHERE tenant_id=$1 AND operation_id=$2::uuid",
			resolved.TenantID, resolved.OperationID).Scan(&permits); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(recoveryCtx,
			"SELECT count(*) FROM guard_permit_authority_evidence WHERE tenant_id=$1 AND operation_id=$2::uuid",
			resolved.TenantID, resolved.OperationID).Scan(&evidence); err != nil {
			t.Fatal(err)
		}
		if permits != 1 || evidence != 1 {
			t.Fatalf("durable Permit/evidence cardinality=%d/%d; want 1/1", permits, evidence)
		}
	}
	assertDurableRows()

	recoveryLedger, err := NewPermitIssuerLedger(store)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := issuer.New(cfg, authority, recoveryLedger)
	if err != nil {
		t.Fatal(err)
	}
	authority.err = issuer.ErrDenied
	if got, err := recovery.Issue(recoveryCtx, resolved); !errors.Is(err, issuer.ErrDenied) || got != (issuer.ScopedPermit{}) {
		t.Fatalf("recovery bypassed current authority: got=%+v err=%v", got, err)
	}
	authority.err = nil
	originalRisk := authority.result.RiskRevision
	authority.result.RiskRevision = "risk-revised-after-commit"
	if got, err := recovery.Issue(recoveryCtx, resolved); !errors.Is(err, issuer.ErrConflict) || got != (issuer.ScopedPermit{}) {
		t.Fatalf("recovery accepted conflicting evidence: got=%+v err=%v", got, err)
	}
	authority.result.RiskRevision = originalRisk
	replayed, err := recovery.Issue(recoveryCtx, resolved)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.PermitID != interrupted.persisted.PermitID || replayed.Draft.Values() != interrupted.persisted.Values {
		t.Fatalf("recovery did not return the original durable Permit: got=%+v want=%+v", replayed, interrupted.persisted)
	}
	assertDurableRows()
}
