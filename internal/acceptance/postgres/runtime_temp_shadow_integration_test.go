package postgres

import (
	"context"
	"errors"
	"testing"
)

// Migrator attestation occurs on a migration session, but database/sql pools
// may later lend a session in which a privileged component created pg_temp
// lookalikes. Accept must not report committed admission or outbox evidence
// when its transaction resolves names to session-local tables.
func TestAcceptRejectsPostMigrationTemporaryOperationAndOutboxShadows(t *testing.T) {
	store, db := integrationStore(t)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ctx := context.Background()
	var schema string
	if err := db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	for _, relation := range []string{
		"guard_action_operations",
		"guard_accepted_submission_snapshots",
		"guard_outbox_events",
	} {
		var ddl string
		if err := db.QueryRowContext(ctx, `
			SELECT pg_catalog.format('CREATE TEMP TABLE %I (LIKE %I.%I INCLUDING ALL)', $1::text, $2::text, $1::text)
		`, relation, schema).Scan(&ddl); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, ddl); err != nil {
			t.Fatalf("create authentic-shape temporary %s: %v", relation, err)
		}
	}
	op, created, err := store.Accept(ctx, "tenant-a", "runtime-shadow-test", sampleSubmission())
	if !errors.Is(err, ErrSchemaDrift) || created || op.OperationID != "" {
		t.Fatalf("temporary admission/outbox shadow accepted: created=%t operation=%+v err=%v; want ErrSchemaDrift", created, op, err)
	}
	var query string
	if err := db.QueryRowContext(ctx, `
		SELECT pg_catalog.format('SELECT count(*) FROM %I.guard_action_operations', $1::text)
	`, schema).Scan(&query); err != nil {
		t.Fatal(err)
	}
	var permanent int
	if err := db.QueryRowContext(ctx, query).Scan(&permanent); err != nil || permanent != 0 {
		t.Fatalf("rejected write unexpectedly persisted to authoritative schema: permanent=%d err=%v", permanent, err)
	}
}
