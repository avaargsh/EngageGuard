package postgres

import (
	"context"
	"errors"
	"testing"
)

// Exact foreign keys and immutable rows do not establish cardinality.
// Startup must reject removal or weakening of the one-time ledger keys.
func TestPermitCatalogRejectsOneTimeUniqueConstraintDrift(t *testing.T) {
	for _, target := range []struct {
		table, name, weakened string
	}{
		{"guard_permits", "guard_permit_operation_unique", "tenant_id,operation_id,permit_id"},
		{"guard_operation_intents", "guard_intent_one_per_operation", "tenant_id,operation_id,attempt_id"},
		{"guard_operation_intents", "guard_intent_one_per_permit", "tenant_id,permit_id,attempt_id"},
		{"guard_execution_audit", "guard_audit_one_dispatch_event", "tenant_id,operation_id,event_type,event_id"},
		{"guard_operation_unknown_events", "guard_unknown_once_per_attempt", "tenant_id,attempt_id,event_id"},
		{"guard_permit_revocations", "guard_revocation_one_per_permit", "tenant_id,permit_id,revocation_id"},
	} {
		for _, mode := range []string{"missing", "weakened"} {
			t.Run(target.name+"/"+mode, func(t *testing.T) {
				store, _ := integrationStore(t)
				ctx := context.Background()
				if _, err := store.db.ExecContext(ctx, "ALTER TABLE "+target.table+" DROP CONSTRAINT "+target.name); err != nil {
					t.Fatalf("isolated uniqueness drift setup: %v", err)
				}
				if mode == "weakened" {
					if _, err := store.db.ExecContext(ctx, "ALTER TABLE "+target.table+
						" ADD CONSTRAINT "+target.name+" UNIQUE ("+target.weakened+")"); err != nil {
						t.Fatalf("isolated weaker uniqueness setup: %v", err)
					}
				}
				if err := Migrate(ctx, store.db); !errors.Is(err, ErrSchemaDrift) {
					t.Fatalf("one-time ledger uniqueness drift accepted: %v", err)
				}
			})
		}
	}
}
