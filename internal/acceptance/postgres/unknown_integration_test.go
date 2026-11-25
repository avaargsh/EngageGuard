package postgres

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
)

// Real PostgreSQL only. The fixture's Permit was seeded, not issued by a
// reviewed authority; no effect or production execution is proven here.
func TestLostACKUnknownIsOneDurableAttemptAndNeverSecondDispatch(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	intent, err := store.ClaimAuthorizedIntent(context.Background(), permitID, resolved)
	if err != nil {
		t.Fatal(err)
	}
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
		if err != nil {
			t.Fatalf("same lost ACK must be idempotent: %v", err)
		}
	}
	reconstructed := newPinnedStoreCopy(t, store)
	observed, err := reconstructed.GetDispatchState(context.Background(), resolved.TenantID, resolved.OperationID, intent.AttemptID)
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
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct{ tenant, operation, attempt, cause string }{
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
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("CREATE FUNCTION reject_unknown_insert() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''forced journal unavailable''; END;'"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("CREATE TRIGGER fail_unknown BEFORE INSERT ON guard_operation_unknown_events FOR EACH ROW EXECUTE FUNCTION reject_unknown_insert()"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkDispatchUnknown(context.Background(), resolved.TenantID, resolved.OperationID, intent.AttemptID, "ACK_LOST"); err == nil {
		t.Fatal("UNKNOWN transition committed without its journal evidence")
	}
	state, err := store.GetDispatchState(context.Background(), resolved.TenantID, resolved.OperationID, intent.AttemptID)
	if err != nil || state.State != "DISPATCHING" || state.Reason != "" {
		t.Fatalf("journal failure left partial state transition: %+v %v", state, err)
	}
}

// Even a CLAIMED Permit must not turn a fabricated or damaged Intent into
// durable UNKNOWN evidence when its exact immutable dispatch audit is absent.
// A test-only superuser mutation simulates persistent ledger corruption;
// ordinary runtime roles must never be allowed to bypass immutable triggers.
func TestMarkDispatchUnknownRejectsClaimedAttemptMissingImmutableAudit(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	ctx := context.Background()
	intent, err := store.ClaimAuthorizedIntent(ctx, permitID, resolved)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt only this isolated test schema using a privileged migration
	// session. Audit immutability is ENABLE ALWAYS; replica mode cannot
	// bypass it. Disable that one row trigger inside the same transaction,
	// then restore ENABLE ALWAYS before COMMIT. Runtime roles must never
	// have this DDL privilege.
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		"ALTER TABLE guard_execution_audit DISABLE TRIGGER guard_execution_audit_immutable_row"); err != nil {
		t.Fatal(err)
	}
	result, err := tx.ExecContext(ctx,
		"DELETE FROM guard_execution_audit WHERE tenant_id=$1 AND attempt_id=$2::uuid",
		resolved.TenantID, intent.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		t.Fatalf("fixture did not delete exactly one audit row: affected=%d err=%v", affected, err)
	}
	if _, err := tx.ExecContext(ctx,
		"ALTER TABLE guard_execution_audit ENABLE ALWAYS TRIGGER guard_execution_audit_immutable_row"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetDispatchState(ctx, resolved.TenantID, resolved.OperationID, intent.AttemptID); !errors.Is(err, ErrUnknownConflict) {
		t.Fatalf("corrupt attempt was treated as inspected dispatch: %v", err)
	}
	if state, err := store.MarkDispatchUnknown(ctx, resolved.TenantID, resolved.OperationID,
		intent.AttemptID, "ACK_LOST"); !errors.Is(err, ErrUnknownConflict) || state.AttemptID != "" {
		t.Fatalf("missing immutable dispatch audit admitted UNKNOWN: state=%+v err=%v", state, err)
	}
	var state string
	if err := store.db.QueryRowContext(ctx,
		"SELECT state FROM guard_operation_intents WHERE tenant_id=$1 AND attempt_id=$2::uuid",
		resolved.TenantID, intent.AttemptID).Scan(&state); err != nil || state != "DISPATCHING" {
		t.Fatalf("rejected UNKNOWN mutated durable attempt: state=%q err=%v", state, err)
	}
	var events int
	if err := store.db.QueryRowContext(ctx,
		"SELECT count(*) FROM guard_operation_unknown_events WHERE tenant_id=$1 AND attempt_id=$2::uuid",
		resolved.TenantID, intent.AttemptID).Scan(&events); err != nil || events != 0 {
		t.Fatalf("rejected UNKNOWN forged a durable event: events=%d err=%v", events, err)
	}
}

// Revoking a Permit after dispatch has become uncertain must not erase or
// hide the already committed attempt. Revocation blocks new effects; it does
// not prove that an in-flight external effect did not happen.
func TestUnknownRemainsInspectableAfterPermitRevocation(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	ctx := context.Background()

	intent, err := store.ClaimAuthorizedIntent(ctx, permitID, resolved)
	if err != nil {
		t.Fatalf("claim Permit: %v", err)
	}
	unknown, err := store.MarkDispatchUnknown(
		ctx, resolved.TenantID, resolved.OperationID, intent.AttemptID, "ACK_LOST",
	)
	if err != nil || unknown.State != "UNKNOWN" {
		t.Fatalf("record lost ACK: state=%+v err=%v", unknown, err)
	}

	revoked, err := store.RevokeScopedPermit(
		ctx, resolved.TenantID, permitID, "incident-unknown-1", "SECURITY_RESPONSE",
	)
	if err != nil || !revoked {
		t.Fatalf("revoke Permit after UNKNOWN: revoked=%t err=%v", revoked, err)
	}

	observed, err := newPinnedStoreCopy(t, store).GetDispatchState(
		ctx, resolved.TenantID, resolved.OperationID, intent.AttemptID,
	)
	if err != nil || observed.State != "UNKNOWN" || observed.Reason != "ACK_LOST" ||
		observed.PermitID != permitID || observed.AttemptID != intent.AttemptID {
		t.Fatalf("revocation hid or rewrote the uncertain attempt: state=%+v err=%v", observed, err)
	}
	if err := store.InspectPreEffectLedger(ctx, permitID, intent.AttemptID, resolved); !errors.Is(err, ErrPreEffectBlocked) {
		t.Fatalf("revoked UNKNOWN attempt passed the necessary pre-effect ledger check: %v", err)
	}

	replayed, err := store.MarkDispatchUnknown(
		ctx, resolved.TenantID, resolved.OperationID, intent.AttemptID, "ACK_LOST",
	)
	if err != nil || replayed.State != "UNKNOWN" || replayed.Reason != "ACK_LOST" {
		t.Fatalf("same-reason UNKNOWN replay changed after revocation: state=%+v err=%v", replayed, err)
	}
	if _, err := store.MarkDispatchUnknown(
		ctx, resolved.TenantID, resolved.OperationID, intent.AttemptID, "PROVIDER_TIMEOUT",
	); !errors.Is(err, ErrUnknownConflict) {
		t.Fatalf("revocation allowed rewriting UNKNOWN reason: %v", err)
	}
	if _, err := store.ClaimAuthorizedIntent(ctx, permitID, resolved); !errors.Is(err, ErrPermitAlreadyClaimed) {
		t.Fatalf("revoked UNKNOWN Permit became claimable again: %v", err)
	}

	var state string
	var revokedAt sql.NullTime
	var events int
	if err := store.db.QueryRowContext(ctx, `
		SELECT p.state, p.revoked_at,
		       (SELECT count(*) FROM guard_operation_unknown_events e
		        WHERE e.tenant_id=p.tenant_id AND e.operation_id=p.operation_id
		          AND e.attempt_id=$3::uuid)
		FROM guard_permits p
		WHERE p.tenant_id=$1 AND p.permit_id=$2::uuid
	`, resolved.TenantID, permitID, intent.AttemptID).Scan(&state, &revokedAt, &events); err != nil {
		t.Fatal(err)
	}
	if state != "CLAIMED" || !revokedAt.Valid || events != 1 {
		t.Fatalf("revocation/UNKNOWN journal invariant drifted: state=%q revoked=%v events=%d", state, revokedAt.Valid, events)
	}
}
