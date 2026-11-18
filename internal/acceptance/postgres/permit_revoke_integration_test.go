package postgres

import (
	"context"
	"errors"
	"testing"
)

// Permits are seeded ONLY by a local DB fixture. This proves internal
// revocation/claim fencing, not authenticated issuance or effect prevention.
func TestRevokeScopedPermitPreventsFirstClaimAndIsIdempotent(t *testing.T) {
	store, action, permit := seededWorkspacePermit(t)
	revoked, err := store.RevokeScopedPermit(context.Background(), action.TenantID, permit,
		"revocation-test-001", "POLICY_REVOKED")
	if err != nil || !revoked {
		t.Fatalf("initial revoke: %t %v", revoked, err)
	}
	replay, err := store.RevokeScopedPermit(context.Background(), action.TenantID, permit,
		"revocation-test-001", "POLICY_REVOKED")
	if err != nil || replay {
		t.Fatalf("revoke idempotency: %t %v", replay, err)
	}
	if _, err := store.ClaimAuthorizedIntent(context.Background(), permit, action); !errors.Is(err, ErrPermitUnavailable) {
		t.Fatalf("revoked Permit still claimable: %v", err)
	}
	if _, err := store.RevokeScopedPermit(context.Background(), action.TenantID, permit,
		"different-evidence", "POLICY_REVOKED"); !errors.Is(err, ErrPermitRevocationConflict) {
		t.Fatalf("immutable revocation overwritten: %v", err)
	}
	if _, err := store.RevokeScopedPermit(context.Background(), "foreign-tenant", permit,
		"revocation-test-001", "POLICY_REVOKED"); !errors.Is(err, ErrPermitUnavailable) {
		t.Fatalf("foreign-tenant revocation succeeded: %v", err)
	}
	var count int
	if err := store.db.QueryRow("SELECT count(*) FROM guard_permit_revocations WHERE permit_id=$1::uuid", permit).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate revocation evidence: %d %v", count, err)
	}
}

func TestRevokingClaimedPermitDoesNotUndoUnknownOrReDispatch(t *testing.T) {
	store, resolved, permit := seededWorkspacePermit(t)
	attempt, err := store.ClaimAuthorizedIntent(context.Background(), permit, resolved)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkDispatchUnknown(context.Background(), resolved.TenantID, resolved.OperationID, attempt.AttemptID, "ACK_LOST"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RevokeScopedPermit(context.Background(), resolved.TenantID, permit,
		"incident-001", "SECURITY_RESPONSE"); err != nil {
		t.Fatal(err)
	}
	outcome, err := store.GetDispatchState(context.Background(), resolved.TenantID, resolved.OperationID, attempt.AttemptID)
	if err != nil || outcome.State != "UNKNOWN" || outcome.AttemptID != attempt.AttemptID {
		t.Fatalf("revocation invented final outcome: %+v %v", outcome, err)
	}
	if _, err := store.ClaimAuthorizedIntent(context.Background(), permit, resolved); err == nil {
		t.Fatal("revoked and claimed Permit enabled a second dispatch")
	}
}

func TestRevocationJournalFailureRollsBackPermitFlag(t *testing.T) {
	store, action, permit := seededWorkspacePermit(t)
	if _, err := store.db.Exec("CREATE FUNCTION reject_revocation_insert() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''forced audit failure''; END;'"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("CREATE TRIGGER fail_revocation BEFORE INSERT ON guard_permit_revocations FOR EACH ROW EXECUTE FUNCTION reject_revocation_insert()"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RevokeScopedPermit(context.Background(), action.TenantID, permit, "failing-evidence", "POLICY_REVOKED"); err == nil {
		t.Fatal("revocation silently succeeded without durable evidence")
	}
	var revoked bool
	if err := store.db.QueryRow("SELECT revoked_at IS NOT NULL FROM guard_permits WHERE permit_id=$1::uuid", permit).Scan(&revoked); err != nil || revoked {
		t.Fatalf("partial revocation after evidence failure: %t %v", revoked, err)
	}
}
