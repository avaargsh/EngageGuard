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

// A trusted worker must not claim a Permit and report a dispatch journal when
// its pooled database session only wrote matching temporary tables.
func TestPermitClaimRejectsPostMigrationTemporaryLedgerShadows(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	store.db.SetMaxOpenConns(1)
	store.db.SetMaxIdleConns(1)
	ctx := context.Background()
	var schema string
	if err := store.db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	for _, relation := range []string{"guard_permits", "guard_operation_intents", "guard_execution_audit"} {
		var ddl string
		if err := store.db.QueryRowContext(ctx, `SELECT pg_catalog.format(
			'CREATE TEMP TABLE %I (LIKE %I.%I INCLUDING ALL)', $1::text, $2::text, $1::text
		)`, relation, schema).Scan(&ddl); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	var seed string
	if err := store.db.QueryRowContext(ctx, `SELECT pg_catalog.format(
		'INSERT INTO pg_temp.guard_permits SELECT * FROM %I.guard_permits', $1::text
	)`, schema).Scan(&seed); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, seed); err != nil {
		t.Fatal(err)
	}
	intent, err := store.ClaimAuthorizedIntent(ctx, permitID, resolved)
	if !errors.Is(err, ErrSchemaDrift) || intent.AttemptID != "" {
		t.Fatalf("temporary Permit/Intent/Audit session returned dispatch intent=%+v err=%v", intent, err)
	}
	var sqlState string
	if err := store.db.QueryRowContext(ctx, `SELECT pg_catalog.format(
		'SELECT state FROM %I.guard_permits WHERE permit_id=$1::uuid', $1::text
	)`, schema).Scan(&sqlState); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := store.db.QueryRowContext(ctx, sqlState, permitID).Scan(&state); err != nil || state != "ISSUED" {
		t.Fatalf("rejected claim modified permanent Permit: state=%q err=%v", state, err)
	}
}
