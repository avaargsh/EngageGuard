package postgres

import (
	"context"
	"errors"
	"testing"
)

// The v2/v3 snapshot fence is also shared by the later Permit evidence
// journals. Matching function text and trigger names alone is insufficient.
func TestSnapshotMigrationRejectsMutationFunctionAttributeDrift(t *testing.T) {
	for _, tc := range []struct {
		name, ddl string
	}{
		{"security-definer", "ALTER FUNCTION guard_reject_snapshot_mutation() SECURITY DEFINER"},
		{"function-config", "ALTER FUNCTION guard_reject_snapshot_mutation() SET search_path TO pg_catalog"},
		{"volatility", "ALTER FUNCTION guard_reject_snapshot_mutation() STABLE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := unmigratedDatabase(t)
			ctx := context.Background()
			if err := Migrate(ctx, db); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx, tc.ddl); err != nil {
				t.Fatalf("isolated function attribute drift setup: %v", err)
			}
			if err := Migrate(ctx, db); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("snapshot mutation function attribute drift accepted: %v", err)
			}
		})
	}
}

func TestSnapshotMigrationRejectsTriggerArgumentDrift(t *testing.T) {
	for _, tc := range []struct {
		name, events, level string
	}{
		{"guard_snapshot_immutable_row", "UPDATE OR DELETE", "ROW"},
		{"guard_snapshot_immutable_truncate", "TRUNCATE", "STATEMENT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := unmigratedDatabase(t)
			ctx := context.Background()
			if err := Migrate(ctx, db); err != nil {
				t.Fatal(err)
			}
			const table = "guard_accepted_submission_snapshots"
			for _, ddl := range []string{
				"DROP TRIGGER " + tc.name + " ON " + table,
				"CREATE TRIGGER " + tc.name + " BEFORE " + tc.events + " ON " + table +
					" FOR EACH " + tc.level + " EXECUTE FUNCTION guard_reject_snapshot_mutation('unexpected')",
				"ALTER TABLE " + table + " ENABLE ALWAYS TRIGGER " + tc.name,
			} {
				if _, err := db.ExecContext(ctx, ddl); err != nil {
					t.Fatalf("isolated trigger argument drift setup: %v", err)
				}
			}
			if err := Migrate(ctx, db); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("snapshot trigger argument drift accepted: %v", err)
			}
		})
	}
}
