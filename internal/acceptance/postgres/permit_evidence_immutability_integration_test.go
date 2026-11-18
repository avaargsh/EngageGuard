package postgres

import (
	"context"
	"errors"
	"testing"
)

// Real PostgreSQL: no ordinary writer may rewrite or erase authorization
// or uncertain-dispatch evidence, including through TRUNCATE.
func TestGuardEvidenceJournalsAreImmutable(t *testing.T) {
	store, resolved, permit := seededWorkspacePermit(t)
	ctx := context.Background()
	intent, err := store.ClaimAuthorizedIntent(ctx, permit, resolved)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkDispatchUnknown(ctx, resolved.TenantID, resolved.OperationID, intent.AttemptID, "ACK_LOST"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RevokeScopedPermit(ctx, resolved.TenantID, permit, "incident-immutable-001", "SECURITY_RESPONSE"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"guard_execution_audit", "guard_operation_unknown_events", "guard_permit_revocations"} {
		t.Run(table, func(t *testing.T) {
			for _, statement := range []string{
				"UPDATE " + table + " SET tenant_id=tenant_id",
				"DELETE FROM " + table,
				"TRUNCATE " + table,
			} {
				if _, err := store.db.ExecContext(ctx, statement); err == nil {
					t.Fatalf("mutable Guard evidence: %s", statement)
				}
			}
			var count int
			if err := store.db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != 1 {
				t.Fatalf("lost evidence in %s: count=%d err=%v", table, count, err)
			}
		})
	}
	current, err := store.GetDispatchState(ctx, resolved.TenantID, resolved.OperationID, intent.AttemptID)
	if err != nil || current.State != "UNKNOWN" || current.Reason != "ACK_LOST" {
		t.Fatalf("UNKNOWN was changed: %+v %v", current, err)
	}
	if _, err := store.ClaimAuthorizedIntent(ctx, permit, resolved); err == nil {
		t.Fatal("revocation enabled another claim")
	}
}

func TestGuardEvidenceCatalogRejectsDisabledTruncateFence(t *testing.T) {
	for _, table := range []string{"guard_execution_audit", "guard_operation_unknown_events", "guard_permit_revocations"} {
		t.Run(table, func(t *testing.T) {
			store, _ := integrationStore(t)
			if _, err := store.db.Exec("ALTER TABLE " + table + " DISABLE TRIGGER " + table + "_immutable_truncate"); err != nil {
				t.Fatal(err)
			}
			if err := Migrate(context.Background(), store.db); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("disabled evidence fence was accepted: %v", err)
			}
		})
	}
}
