package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// Real PostgreSQL only. The fixture's permit was seeded, not issued by a
// reviewed policy authority; these are ledger invariants, not execution proof.
func TestLostACKUnknownIsOneDurableAttemptAndNeverSecondDispatch(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	intent, err := store.ClaimAuthorizedIntent(context.Background(), permitID, resolved)
	if err != nil { t.Fatal(err) }
	const callers = 12
	var wg sync.WaitGroup
	failures := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.MarkDispatchUnknown(context.Background(), resolved.TenantID, resolved.OperationID, intent.AttemptID, "ACK_LOST")
			failures <- err
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil { t.Fatalf("same lost ACK must be idempotent: %v", err) }
	}
	observed, err := New(store.db).GetDispatchState(context.Background(), resolved.TenantID, resolved.OperationID, intent.AttemptID)
	if err != nil || observed.State != "UNKNOWN" || observed.AttemptID != intent.AttemptID ||
		observed.Reason != "ACK_LOST" || observed.PermitID != permitID {
		t.Fatalf("unknown not durable: %+v %v", observed, err)
	}
	if _, err := store.MarkDispatchUnknown(context.Background(), resolved.TenantID, resolved.OperationID, intent.AttemptID, "PROVIDER_TIMEOUT"); !errors.Is(err, ErrUnknownConflict) {
		t.Fatalf("contradictory lost ACK reason accepted: %v", err)
	}
	if _, err := store.ClaimAuthorizedIntent(context.Background(), permitID, resolved); !errors.Is(err, ErrPermitAlreadyClaimed) {
		t.Fatalf("UNKNOWN let Guard claim and dispatch again: %v", err)
	}
	var events, intents, audit int
	if err := store.db.QueryRow(`
		SELECT (SELECT count(*) FROM guard_operation_unknown_events),
		       (SELECT count(*) FROM guard_operation_intents),
		       (SELECT count(*) FROM guard_execution_audit)
	`).Scan(&events, &intents, &audit); err != nil || events != 1 || intents != 1 || audit != 1 {
		t.Fatalf("duplicate attempt/event or missing audit: %d/%d/%d %v", events, intents, audit, err)
	}
}

func TestUnknownCannotReconcileForeignTenantOrUncommittedAttempt(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	intent, err := store.ClaimAuthorizedIntent(context.Background(), permitID, resolved)
	if err != nil { t.Fatal(err) }
	for _, bad := range []struct{tenant, operation, attempt, cause string}{
		{"tenant-b", resolved.OperationID, intent.AttemptID, "ACK_LOST"},
		{resolved.TenantID, "11111111-1111-4111-8111-111111111111", intent.AttemptID, "ACK_LOST"},
		{resolved.TenantID, resolved.OperationID, "11111111-1111-4111-8111-111111111111", "ACK_LOST"},
		{resolved.TenantID, resolved.OperationID, intent.AttemptID, "SUCCEEDED"},
	} {
		if _, err := store.MarkDispatchUnknown(context.Background(), bad.tenant, bad.operation, bad.attempt, bad.cause); err == nil {
			t.Fatalf("untrusted or fabricated outcome accepted: %+v", bad)
		}
	}
	var count int
	if err := store.db.QueryRow("SELECT count(*) FROM guard_operation_unknown_events").Scan(&count); err != nil || count != 0 {
		t.Fatalf("foreign/fabricated UNKNOWN mutated journal: %d %v", count, err)
	}
}

func TestUnknownAuditFailureRollsBackStateTransition(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	intent, err := store.ClaimAuthorizedIntent(context.Background(), permitID, resolved)
	if err != nil { t.Fatal(err) }
	if _, err := store.db.Exec(`CREATE FUNCTION reject_unknown_insert() RETURNS trigger LANGUAGE plpgsql AS $ BEGIN RAISE EXCEPTION 'forced journal unavailable'; END; $`); err != nil { t.Fatal(err) }
	if _, err := store.db.Exec(`CREATE TRIGGER fail_unknown BEFORE INSERT ON guard_operation_unknown_events FOR EACH ROW EXECUTE FUNCTION reject_unknown_insert()`); err != nil { t.Fatal(err) }
	if _, err := store.MarkDispatchUnknown(context.Background(), resolved.TenantID, resolved.OperationID, intent.AttemptID, "ACK_LOST"); err == nil {
		t.Fatal("UNKNOWN transition committed without its journal evidence")
	}
	state, err := store.GetDispatchState(context.Background(), resolved.TenantID, resolved.OperationID, intent.AttemptID)
	if err != nil || state.State != "DISPATCHING" || state.Reason != "" {
		t.Fatalf("journal failure left partial state transition: %+v %v", state, err)
	}
}
