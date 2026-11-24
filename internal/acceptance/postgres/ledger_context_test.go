package postgres

import (
	"database/sql"
	"testing"
)

const (
	contextGuardTestTenant   = "tenant-a"
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
