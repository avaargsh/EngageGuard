package postgres

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// A digest match inside session-local Operation and Snapshot copies is not
// authoritative evidence. Both copied rows can be changed consistently while
// the original accepted submission remains immutable in the permanent schema.
func TestAcceptedSubmissionRejectsPostMigrationTemporaryOperationSnapshotShadows(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	op, created, err := store.Accept(ctx, "tenant-a", "accepted-shadow-source", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("create trusted accepted source: created=%t err=%v", created, err)
	}
	original, err := store.ReadAcceptedSubmission(ctx, op.TenantID, op.OperationID)
	if err != nil || !bytes.Equal(original.Raw, sampleSubmission()) {
		t.Fatalf("permanent original accepted bytes missing: err=%v", err)
	}

	forged := []byte(strings.Replace(string(sampleSubmission()), "docs/a.txt", "docs/forged.txt", 1))
	forgedDigest, err := action.SubmissionDigest(forged)
	if err != nil || forgedDigest == original.Operation.SubmissionDigest {
		t.Fatalf("invalid independent forged content fixture: err=%v", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	for _, table := range []string{"guard_action_operations", "guard_accepted_submission_snapshots"} {
		createTempGuardTableLikePermanent(t, store, table)
		copyPermanentGuardRowsToTemp(t, store, table)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE pg_temp.guard_action_operations SET submission_digest=$1
		WHERE tenant_id=$2 AND operation_id=$3::uuid
	`, forgedDigest, op.TenantID, op.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE pg_temp.guard_accepted_submission_snapshots
		SET submission_digest=$1, submission_bytes=$2
		WHERE tenant_id=$3 AND operation_id=$4::uuid
	`, forgedDigest, forged, op.TenantID, op.OperationID); err != nil {
		t.Fatal(err)
	}
	record, err := store.ReadAcceptedSubmission(ctx, op.TenantID, op.OperationID)
	if !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("accepted-snapshot reader trusted jointly forged pg_temp bytes: %+v err=%v; want ErrSchemaDrift", record, err)
	}

	var permanentQuery string
	if err := db.QueryRowContext(ctx, `
		SELECT pg_catalog.format(
			'SELECT submission_bytes FROM %I.guard_accepted_submission_snapshots WHERE tenant_id=$1 AND operation_id=$2::uuid',
			pg_catalog.current_schema())
	`).Scan(&permanentQuery); err != nil {
		t.Fatal(err)
	}
	var permanent []byte
	if err := db.QueryRowContext(ctx, permanentQuery, op.TenantID, op.OperationID).Scan(&permanent); err != nil || !bytes.Equal(permanent, sampleSubmission()) {
		t.Fatalf("temporary forgery modified immutable permanent submission: err=%v", err)
	}
}
