package postgres

import (
	"context"
	"errors"
	"testing"
)

// A same-name, enabled BEFORE UPDATE OR DELETE trigger is not a valid
// immutability guard if its WHEN predicate prevents every invocation.
func TestSnapshotMigrationRejectsDisabledByWhenFalseTrigger(t *testing.T) {
	db := unmigratedDatabase(t)
	ctx := context.Background()
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DROP TRIGGER guard_snapshot_immutable_row ON guard_accepted_submission_snapshots`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		CREATE TRIGGER guard_snapshot_immutable_row
		BEFORE UPDATE OR DELETE ON guard_accepted_submission_snapshots
		FOR EACH ROW WHEN (FALSE)
		EXECUTE FUNCTION guard_reject_snapshot_mutation()
	`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("same-name, same-function disabled-by-WHEN trigger bypassed attestation: %v", err)
	}
}
