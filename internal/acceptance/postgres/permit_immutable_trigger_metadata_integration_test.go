package postgres

import (
	"context"
	"errors"
	"testing"
)

// Preserve trigger name, event bitmask, function and ENABLE ALWAYS while
// varying metadata that changes which writes the immutable fence covers.
func TestPermitEvidenceStartupRejectsImmutableTriggerMetadataDrift(t *testing.T) {
	for _, target := range []struct {
		table, trigger, function string
	}{
		{"guard_execution_audit", "guard_execution_audit_immutable_row", "guard_reject_snapshot_mutation"},
		{"guard_operation_unknown_events", "guard_operation_unknown_events_immutable_row", "guard_reject_snapshot_mutation"},
		{"guard_permit_revocations", "guard_permit_revocations_immutable_row", "guard_reject_snapshot_mutation"},
		{"guard_permits", "guard_permit_immutable_row_v9", "guard_permit_immutable_row_v9"},
	} {
		for _, tc := range []struct {
			name, events, when, args string
		}{
			{name: "conditional", events: "UPDATE OR DELETE", when: " WHEN (false)"},
			{name: "column-filter", events: "UPDATE OF tenant_id OR DELETE"},
			{name: "argument", events: "UPDATE OR DELETE", args: "'unexpected'"},
		} {
			t.Run(target.table+"/"+tc.name, func(t *testing.T) {
				store, _ := integrationStore(t)
				ctx := context.Background()
				for _, stmt := range []string{
					"DROP TRIGGER " + target.trigger + " ON " + target.table,
					"CREATE TRIGGER " + target.trigger + " BEFORE " + tc.events +
						" ON " + target.table + " FOR EACH ROW" + tc.when +
						" EXECUTE FUNCTION " + target.function + "(" + tc.args + ")",
					"ALTER TABLE " + target.table + " ENABLE ALWAYS TRIGGER " + target.trigger,
				} {
					if _, err := store.db.ExecContext(ctx, stmt); err != nil {
						t.Fatalf("isolated immutable trigger drift setup: %v", err)
					}
				}
				if err := Migrate(ctx, store.db); !errors.Is(err, ErrSchemaDrift) {
					t.Fatalf("immutable trigger metadata drift passed startup attestation: %v", err)
				}
			})
		}
	}
}

// Statement-level TRUNCATE fences also have an exact zero-argument contract.
func TestPermitEvidenceStartupRejectsTruncateTriggerArgumentDrift(t *testing.T) {
	for _, target := range []struct {
		table, trigger string
	}{
		{"guard_execution_audit", "guard_execution_audit_immutable_truncate"},
		{"guard_operation_unknown_events", "guard_operation_unknown_events_immutable_truncate"},
		{"guard_permit_revocations", "guard_permit_revocations_immutable_truncate"},
		{"guard_permits", "guard_permit_immutable_truncate_v9"},
	} {
		t.Run(target.table, func(t *testing.T) {
			store, _ := integrationStore(t)
			ctx := context.Background()
			for _, stmt := range []string{
				"DROP TRIGGER " + target.trigger + " ON " + target.table,
				"CREATE TRIGGER " + target.trigger + " BEFORE TRUNCATE ON " + target.table +
					" FOR EACH STATEMENT EXECUTE FUNCTION guard_reject_snapshot_mutation('unexpected')",
				"ALTER TABLE " + target.table + " ENABLE ALWAYS TRIGGER " + target.trigger,
			} {
				if _, err := store.db.ExecContext(ctx, stmt); err != nil {
					t.Fatalf("isolated truncate trigger drift setup: %v", err)
				}
			}
			if err := Migrate(ctx, store.db); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("truncate trigger argument drift passed startup attestation: %v", err)
			}
		})
	}
}
