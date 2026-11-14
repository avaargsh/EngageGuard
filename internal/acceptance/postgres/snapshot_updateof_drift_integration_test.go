package postgres

import (
	"context"
	"errors"
	"testing"
)

// An UPDATE OF trigger is insufficient when the snapshot has other mutable columns.
func TestSnapshotMigrationRejectsNarrowedUpdateOfTrigger(t *testing.T) {
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
		BEFORE UPDATE OF submission_digest OR DELETE ON guard_accepted_submission_snapshots
		FOR EACH ROW EXECUTE FUNCTION guard_reject_snapshot_mutation()
	`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("same-name update-column-restricted trigger bypassed attestation: %v", err)
	}
}
