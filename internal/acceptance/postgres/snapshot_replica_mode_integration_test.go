package postgres

import (
	"context"
	"testing"
)

// Database immutability must not depend on a privileged session remaining in
// origin replication mode. A direct SQL caller granted the parameter privilege
// can disable ordinary (origin-only) triggers without altering the catalog.
// Replica-mode fault injection is isolated to a rolled-back PostgreSQL txn.
func TestAcceptedSnapshotRejectsReplicaModeMutation(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	op, created, err := store.Accept(ctx, "tenant-a", "replica-immutable", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("persist original accepted intent: created=%t err=%v", created, err)
	}
	for _, tc := range []struct {
		name, statement string
	}{
		{"UPDATE", "UPDATE guard_accepted_submission_snapshots SET persisted_at=clock_timestamp() WHERE operation_id=$1"},
		{"DELETE", "DELETE FROM guard_accepted_submission_snapshots WHERE operation_id=$1"},
		{"TRUNCATE", "TRUNCATE TABLE guard_accepted_submission_snapshots"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err := tx.ExecContext(ctx, "SET LOCAL session_replication_role=replica"); err != nil {
				t.Fatal(err)
			}
			args := []any{op.OperationID}
			if tc.name == "TRUNCATE" {
				args = nil
			}
			if _, err := tx.ExecContext(ctx, tc.statement, args...); err == nil {
				t.Fatalf("%s bypassed immutable Guard snapshot under replica mode", tc.name)
			}
		})
	}
}
