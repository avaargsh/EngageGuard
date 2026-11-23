package postgres

import (
	"context"
	"errors"
	"testing"
)

// A migration/initial role audit does not bind a subsequent pooled session.
// This is the accepted source for the protected issuance preflight: a forged
// temporary Operation/Snapshot pair must not be mistaken for durable Guard
// acceptance just because its exact submission digest is internally valid.
func TestReadAcceptedSubmissionRejectsTempOnlyAuthoritativeSource(t *testing.T) {
	store, db := integrationStore(t)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ctx := context.Background()
	op, created, err := store.Accept(ctx, "tenant-a", "snapshot-source-shadow", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("seed authentic acceptance: created=%t err=%v", created, err)
	}
	const tempOnlyID = "11111111-1111-4111-8111-111111111112"
	var schema string
	if err := db.QueryRowContext(ctx, "SELECT pg_catalog.current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"guard_action_operations", "guard_accepted_submission_snapshots"} {
		var cloneDDL, copyDML string
		if err := db.QueryRowContext(ctx, `
			SELECT pg_catalog.format(
				'CREATE TEMP TABLE %I (LIKE %I.%I INCLUDING ALL)', $1::text, $2::text, $1::text
			), pg_catalog.format(
				'INSERT INTO pg_temp.%I SELECT * FROM %I.%I', $1::text, $2::text, $1::text
			)
		`, name, schema).Scan(&cloneDDL, &copyDML); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, cloneDDL); err != nil {
			t.Fatalf("clone %s: %v", name, err)
		}
		if _, err := db.ExecContext(ctx, copyDML); err != nil {
			t.Fatalf("copy %s: %v", name, err)
		}
	}
	for _, name := range []string{"guard_action_operations", "guard_accepted_submission_snapshots"} {
		var change string
		if err := db.QueryRowContext(ctx, `
			SELECT pg_catalog.format(
				'UPDATE pg_temp.%I SET operation_id=$1::uuid WHERE operation_id=$2::uuid',
				$1::text
			)
		`, name).Scan(&change); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, change, tempOnlyID, op.OperationID); err != nil {
			t.Fatal(err)
		}
	}
	var lookup string
	if err := db.QueryRowContext(ctx, `
		SELECT pg_catalog.format(
			'SELECT count(*) FROM %I.guard_action_operations WHERE operation_id=$1::uuid',
			$1::text)
	`, schema).Scan(&lookup); err != nil {
		t.Fatal(err)
	}
	var actual int
	if err := db.QueryRowContext(ctx, lookup, tempOnlyID).Scan(&actual); err != nil || actual != 0 {
		t.Fatalf("test-only accepted Operation unexpectedly durable: count=%d err=%v", actual, err)
	}
	rec, err := store.ReadAcceptedSubmission(ctx, "tenant-a", tempOnlyID)
	if !errors.Is(err, ErrSchemaDrift) || rec.Operation.OperationID != "" || len(rec.Raw) != 0 {
		t.Fatalf("temporary-only accepted source trusted: op=%+v bytes=%d err=%v; want ErrSchemaDrift",
			rec.Operation, len(rec.Raw), err)
	}
}
