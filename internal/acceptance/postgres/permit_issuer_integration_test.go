package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avaargsh/EngageGuard/internal/issuer"
)

func acceptedPermitDraft(t *testing.T, store *Store) issuer.PermitDraft {
	t.Helper()
	op, created, err := store.Accept(context.Background(), "tenant-a", "issuer-ledger-source", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("accept source: created=%t err=%v", created, err)
	}
	now := time.Now().UTC()
	return issuer.PermitDraft{
		TenantID:          "tenant-a",
		OperationID:       op.OperationID,
		RunID:             "run-1",
		RuntimeAttemptID:  "run-attempt-1",
		TurnID:            "turn-1",
		ApprovalRef:       "approval-1",
		RiskRevision:      "risk-17",
		ActionHash:        strings.Repeat("a", 64),
		ToolBindingDigest: strings.Repeat("b", 64),
		PolicyVersion:     "policy-7",
		Audience:          "trusted-workspace-executor",
		IssuedBy:          "spiffe://platform.example/ns/guard/sa/issuer",
		IssuedAt:          now,
		ExpiresAt:         now.Add(2 * time.Minute),
	}
}

func TestPermitIssuerLedgerConcurrentReplayReturnsOneExactPermit(t *testing.T) {
	store, db := integrationStore(t)
	ledger, err := NewPermitIssuerLedger(store)
	if err != nil {
		t.Fatal(err)
	}
	draft := acceptedPermitDraft(t, store)

	const callers = 12
	type result struct {
		permit issuer.ScopedPermit
		err    error
	}
	results := make(chan result, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			permit, err := ledger.PersistIssuedPermit(context.Background(), draft)
			results <- result{permit: permit, err: err}
		}()
	}
	wg.Wait()
	close(results)

	var permitID string
	for got := range results {
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.permit.Draft != draft || got.permit.PermitID == "" {
			t.Fatalf("unbound Permit replay: %+v", got.permit)
		}
		if permitID != "" && got.permit.PermitID != permitID {
			t.Fatalf("same operation minted multiple Permit IDs: %s vs %s", permitID, got.permit.PermitID)
		}
		permitID = got.permit.PermitID
	}
	var permits, evidence int
	if err := db.QueryRowContext(context.Background(), "SELECT count(*) FROM guard_permits WHERE operation_id=$1::uuid", draft.OperationID).Scan(&permits); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(context.Background(), "SELECT count(*) FROM guard_permit_authority_evidence WHERE operation_id=$1::uuid", draft.OperationID).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	if permits != 1 || evidence != 1 {
		t.Fatalf("durable Permit/evidence rows=%d/%d; want 1/1", permits, evidence)
	}
}

func TestPermitIssuerLedgerRejectsConflictingAuthorityReplay(t *testing.T) {
	store, _ := integrationStore(t)
	ledger, err := NewPermitIssuerLedger(store)
	if err != nil {
		t.Fatal(err)
	}
	draft := acceptedPermitDraft(t, store)
	first, err := ledger.PersistIssuedPermit(context.Background(), draft)
	if err != nil {
		t.Fatal(err)
	}
	changed := draft
	changed.RiskRevision = "risk-18"
	if got, err := ledger.PersistIssuedPermit(context.Background(), changed); !errors.Is(err, issuer.ErrConflict) || got.PermitID != "" {
		t.Fatalf("conflicting authority replay result=%+v err=%v, want ErrConflict and no Permit", got, err)
	}
	replay, err := ledger.PersistIssuedPermit(context.Background(), draft)
	if err != nil || replay.PermitID != first.PermitID || replay.Draft != draft {
		t.Fatalf("exact replay did not recover original Permit: %+v err=%v", replay, err)
	}
}

func TestPermitIssuerAuthorityEvidenceIsImmutable(t *testing.T) {
	store, db := integrationStore(t)
	ledger, err := NewPermitIssuerLedger(store)
	if err != nil {
		t.Fatal(err)
	}
	draft := acceptedPermitDraft(t, store)
	permit, err := ledger.PersistIssuedPermit(context.Background(), draft)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), `
		UPDATE guard_permit_authority_evidence
		SET risk_revision='forged-risk'
		WHERE tenant_id=$1 AND permit_id=$2::uuid
	`, draft.TenantID, permit.PermitID); err == nil {
		t.Fatal("authority evidence UPDATE bypassed immutability")
	}
	var risk string
	if err := db.QueryRowContext(context.Background(), `
		SELECT risk_revision FROM guard_permit_authority_evidence
		WHERE tenant_id=$1 AND permit_id=$2::uuid
	`, draft.TenantID, permit.PermitID).Scan(&risk); err != nil || risk != draft.RiskRevision {
		t.Fatalf("authority evidence drifted: risk=%q err=%v", risk, err)
	}
}
