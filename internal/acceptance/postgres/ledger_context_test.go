package postgres

import (
	"context"
	"database/sql"
	"testing"
)

const (
	contextGuardTestTenant    = "tenant-a"
	contextGuardTestOperation = "11111111-1111-4111-8111-111111111111"
	contextGuardTestAttempt   = "22222222-2222-4222-8222-222222222222"
)

func TestGetDispatchStateRejectsNilContext(t *testing.T) {
	store := &Store{db: &sql.DB{}}
	if _, err := store.GetDispatchState(nil, contextGuardTestTenant, contextGuardTestOperation, contextGuardTestAttempt); err == nil {
		t.Fatal("nil context must be rejected before beginning a database transaction")
	}
}

func TestMarkDispatchUnknownRejectsNilContext(t *testing.T) {
	store := &Store{db: &sql.DB{}}
	if _, err := store.MarkDispatchUnknown(nil, contextGuardTestTenant, contextGuardTestOperation, contextGuardTestAttempt, "ACK_LOST"); err == nil {
		t.Fatal("nil context must be rejected before beginning a database transaction")
	}
}

func TestBeginLedgerTxRejectsNilContextAtStoreBoundary(t *testing.T) {
	store := &Store{db: &sql.DB{}}
	if _, err := store.beginLedgerTx(nil, true); err == nil || err.Error() != "Guard ledger context required" {
		t.Fatalf("nil context error = %v; want explicit Guard ledger context error", err)
	}
}

func TestBeginLedgerTxRejectsCanceledContextBeforeOpeningTransaction(t *testing.T) {
	store := &Store{db: &sql.DB{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.beginLedgerTx(ctx, true); err == nil || err.Error() != "Guard ledger context required: context canceled" {
		t.Fatalf("canceled context error = %v; want Guard context error wrapping context.Canceled", err)
	}
}
