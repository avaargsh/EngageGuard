package postgres

import (
	"context"
	"errors"
	"testing"
)

func TestPermitClaimRequiresOperatorPinnedSchema(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	unpinned := New(store.db)

	if _, err := unpinned.ClaimAuthorizedIntent(context.Background(), permitID, resolved); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("unconfigured Store claim error = %v, want ErrSchemaDrift", err)
	}

	var state string
	if err := store.db.QueryRowContext(context.Background(),
		"SELECT state FROM guard_permits WHERE permit_id=$1::uuid", permitID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "ISSUED" {
		t.Fatalf("unconfigured Store changed Permit state to %q", state)
	}
	var intents int
	if err := store.db.QueryRowContext(context.Background(),
		"SELECT count(*) FROM guard_operation_intents WHERE permit_id=$1::uuid", permitID).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if intents != 0 {
		t.Fatalf("unconfigured Store created %d dispatch intents", intents)
	}
}

func TestPermitRevocationRequiresOperatorPinnedSchema(t *testing.T) {
	store, _, permitID := seededWorkspacePermit(t)
	unpinned := New(store.db)

	if _, err := unpinned.RevokeScopedPermit(context.Background(), "tenant-a", permitID,
		"security-event-1", "SECURITY_RESPONSE"); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("unconfigured Store revocation error = %v, want ErrSchemaDrift", err)
	}

	var revoked bool
	if err := store.db.QueryRowContext(context.Background(),
		"SELECT revoked_at IS NOT NULL FROM guard_permits WHERE permit_id=$1::uuid", permitID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked {
		t.Fatal("unconfigured Store revoked a Permit")
	}
	var journals int
	if err := store.db.QueryRowContext(context.Background(),
		"SELECT count(*) FROM guard_permit_revocations WHERE permit_id=$1::uuid", permitID).Scan(&journals); err != nil {
		t.Fatal(err)
	}
	if journals != 0 {
		t.Fatalf("unconfigured Store created %d revocation journal rows", journals)
	}
}

func TestDispatchInspectionRequiresOperatorPinnedSchema(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	intent, err := store.ClaimAuthorizedIntent(context.Background(), permitID, resolved)
	if err != nil {
		t.Fatal(err)
	}
	unpinned := New(store.db)

	if _, err := unpinned.GetDispatchState(context.Background(), resolved.TenantID,
		resolved.OperationID, intent.AttemptID); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("unconfigured Store inspection error = %v, want ErrSchemaDrift", err)
	}
}

func TestUnknownTransitionRequiresOperatorPinnedSchema(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	intent, err := store.ClaimAuthorizedIntent(context.Background(), permitID, resolved)
	if err != nil {
		t.Fatal(err)
	}
	unpinned := New(store.db)

	if _, err := unpinned.MarkDispatchUnknown(context.Background(), resolved.TenantID,
		resolved.OperationID, intent.AttemptID, "ACK_LOST"); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("unconfigured Store UNKNOWN transition error = %v, want ErrSchemaDrift", err)
	}

	var state string
	if err := store.db.QueryRowContext(context.Background(),
		"SELECT state FROM guard_operation_intents WHERE attempt_id=$1::uuid", intent.AttemptID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "DISPATCHING" {
		t.Fatalf("unconfigured Store changed Attempt state to %q", state)
	}
	var events int
	if err := store.db.QueryRowContext(context.Background(),
		"SELECT count(*) FROM guard_operation_unknown_events WHERE attempt_id=$1::uuid", intent.AttemptID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 0 {
		t.Fatalf("unconfigured Store created %d UNKNOWN events", events)
	}
}

func newPinnedStoreCopy(t *testing.T, store *Store) *Store {
	t.Helper()
	if store == nil {
		t.Fatal("cannot reconstruct a nil Guard Store")
	}
	reconstructed, err := NewWithTrustedSchema(store.db, store.trustedSchema)
	if err != nil {
		t.Fatal(err)
	}
	return reconstructed
}
