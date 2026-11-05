package postgres

import (
    "bytes"
    "context"
    "errors"
    "testing"
)

func TestAcceptedSubmissionSnapshotSurvivesRecreationAndReplay(t *testing.T) {
    store, db := integrationStore(t)
    ctx := context.Background()
    raw := sampleSubmission()
    first, created, err := store.Accept(ctx, "tenant-a", "key-durable-snapshot", raw)
    if err != nil || !created { t.Fatalf("first acceptance: created=%v err=%v", created, err) }
    restarted := New(db)
    recovered, err := restarted.ReadAcceptedSubmission(ctx, "tenant-a", first.OperationID)
    if err != nil { t.Fatalf("read after store recreation: %v", err) }
    if recovered.Operation.OperationID != first.OperationID ||
        recovered.Operation.SubmissionDigest != first.SubmissionDigest ||
        !bytes.Equal(recovered.Raw, raw) {
        t.Fatalf("readback is not exact accepted bytes: operation=%+v bytes=%q", recovered.Operation, recovered.Raw)
    }
    replay, created, err := restarted.Accept(ctx, "tenant-a", "key-durable-snapshot", raw)
    if err != nil || created || replay.OperationID != first.OperationID {
        t.Fatalf("unstable replay: %+v created=%v err=%v", replay, created, err)
    }
    if _, err := restarted.ReadAcceptedSubmission(ctx, "tenant-b", first.OperationID); !errors.Is(err, ErrSnapshotMissing) {
        t.Fatalf("cross-tenant snapshot read: %v", err)
    }
}

func TestAcceptedSnapshotIsImmutableInDatabase(t *testing.T) {
    store, db := integrationStore(t)
    ctx := context.Background()
    op, _, err := store.Accept(ctx, "tenant-a", "key-immutable", sampleSubmission())
    if err != nil { t.Fatal(err) }
    for _, sql := range []string{
        "UPDATE guard_accepted_submission_snapshots SET submission_bytes = '\\x7b7d'::bytea WHERE operation_id=$1",
        "DELETE FROM guard_accepted_submission_snapshots WHERE operation_id=$1",
    } {
        if _, err := db.ExecContext(ctx, sql, op.OperationID); err == nil {
            t.Fatalf("mutation of original snapshot succeeded: %s", sql)
        }
    }
    recovered, err := New(db).ReadAcceptedSubmission(ctx, "tenant-a", op.OperationID)
    if err != nil || !bytes.Equal(recovered.Raw, sampleSubmission()) {
        t.Fatalf("database mutation changed accepted intent: err=%v", err)
    }
}

func TestAcceptedSnapshotCannotBeMissingOnReplay(t *testing.T) {
    store, db := integrationStore(t)
    ctx := context.Background()
    op, _, err := store.Accept(ctx, "tenant-a", "key-missing", sampleSubmission())
    if err != nil { t.Fatal(err) }
    // Simulate privileged catalog damage. This is not a supported live workflow.
    if _, err := db.ExecContext(ctx, "DROP TABLE guard_accepted_submission_snapshots CASCADE"); err != nil { t.Fatal(err) }
    if _, _, err := store.Accept(ctx, "tenant-a", "key-missing", sampleSubmission()); err == nil {
        t.Fatal("replay succeeded after immutable snapshot disappeared")
    }
    if _, err := store.ReadAcceptedSubmission(ctx, "tenant-a", op.OperationID); err == nil {
        t.Fatal("read succeeded after immutable snapshot disappeared")
    }
}

func TestAcceptedSubmissionSnapshotTruncateDenied(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	op, _, err := store.Accept(ctx, "tenant-a", "key-protect-truncate", sampleSubmission())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "TRUNCATE guard_accepted_submission_snapshots"); err == nil {
		t.Fatal("TRUNCATE bypassed immutable accepted submission retention")
	}
	recovered, err := New(db).ReadAcceptedSubmission(ctx, "tenant-a", op.OperationID)
	if err != nil || !bytes.Equal(recovered.Raw, sampleSubmission()) {
		t.Fatalf("TRUNCATE damaged retained accepted intent: %v", err)
	}
}
