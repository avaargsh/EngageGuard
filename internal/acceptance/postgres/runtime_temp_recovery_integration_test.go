package postgres

import (
	"context"
	"errors"
	"testing"
)

func createTempGuardTableLikePermanent(t *testing.T, store *Store, relation string) {
	t.Helper()
	var ddl string
	if err := store.db.QueryRowContext(context.Background(), `
		SELECT pg_catalog.format('CREATE TEMP TABLE %I (LIKE %I.%I INCLUDING ALL)', $1::text, current_schema(), $1::text)
	`, relation).Scan(&ddl); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), ddl); err != nil {
		t.Fatal(err)
	}
}

func copyPermanentGuardRowsToTemp(t *testing.T, store *Store, relation string) {
	t.Helper()
	var stmt string
	if err := store.db.QueryRowContext(context.Background(), `
		SELECT pg_catalog.format('INSERT INTO pg_temp.%I SELECT * FROM %I.%I',
			$1::text, current_schema(), $1::text)
	`, relation).Scan(&stmt); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), stmt); err != nil {
		t.Fatal(err)
	}
}

// Revocation and its evidence must be durable or denied. A session-local
// forged Permit and fake revocation journal cannot simulate a true revocation.
func TestPermitRevocationRejectsPostMigrationTemporaryLedgerShadows(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	store.db.SetMaxOpenConns(1)
	store.db.SetMaxIdleConns(1)
	for _, relation := range []string{"guard_permits", "guard_permit_revocations"} {
		createTempGuardTableLikePermanent(t, store, relation)
	}
	copyPermanentGuardRowsToTemp(t, store, "guard_permits")
	revoked, err := store.RevokeScopedPermit(context.Background(), resolved.TenantID,
		permitID, "security-test-shadow", "SECURITY_RESPONSE")
	if !errors.Is(err, ErrSchemaDrift) || revoked {
		t.Fatalf("temporary revocation journal produced success revoked=%t err=%v", revoked, err)
	}
	var ddl string
	if err := store.db.QueryRowContext(context.Background(), `SELECT pg_catalog.format(
		'SELECT count(*) FROM %I.guard_permit_revocations WHERE permit_id=$1::uuid', current_schema()
	)`).Scan(&ddl); err != nil {
		t.Fatal(err)
	}
	var persisted int
	if err := store.db.QueryRowContext(context.Background(), ddl, permitID).Scan(&persisted); err != nil || persisted != 0 {
		t.Fatalf("failed temporary revocation persisted authority unexpectedly: count=%d err=%v", persisted, err)
	}
}

// Recovery must never treat same-session pg_temp Intent, Permit, Audit and
// UNKNOWN rows as durable facts. Permanent state remains DISPATCHING.
func TestDispatchInspectionRejectsPostMigrationTemporaryUNKNOWNShadow(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	intent, err := store.ClaimAuthorizedIntent(context.Background(), permitID, resolved)
	if err != nil {
		t.Fatal(err)
	}
	store.db.SetMaxOpenConns(1)
	store.db.SetMaxIdleConns(1)
	for _, relation := range []string{
		"guard_permits", "guard_operation_intents",
		"guard_execution_audit", "guard_operation_unknown_events",
	} {
		createTempGuardTableLikePermanent(t, store, relation)
		if relation != "guard_operation_unknown_events" {
			copyPermanentGuardRowsToTemp(t, store, relation)
		}
	}
	if _, err := store.db.ExecContext(context.Background(), `
		UPDATE pg_temp.guard_operation_intents SET state='UNKNOWN' WHERE attempt_id=$1::uuid
	`, intent.AttemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `
		INSERT INTO pg_temp.guard_operation_unknown_events
			(tenant_id,operation_id,permit_id,attempt_id,action_hash,reason)
		SELECT tenant_id,operation_id,permit_id,attempt_id,action_hash,'ACK_LOST'
		FROM pg_temp.guard_operation_intents WHERE attempt_id=$1::uuid
	`, intent.AttemptID); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.GetDispatchState(context.Background(),
		resolved.TenantID, resolved.OperationID, intent.AttemptID)
	if !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("temporary UNKNOWN recovery journal trusted: snapshot=%+v err=%v", snapshot, err)
	}
}
