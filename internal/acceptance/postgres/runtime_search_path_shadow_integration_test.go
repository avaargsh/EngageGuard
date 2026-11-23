package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// The per-transaction OID check must not accept a different first
// search_path schema that contains a complete copy of every Guard relation.
// Such lookalikes are not the durable schema selected at connection startup.
func TestRuntimeRejectsPostMigrationWritableSchemaPathShadow(t *testing.T) {
	store, db := integrationStore(t)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ctx := context.Background()

	var trusted, resetPath string
	if err := db.QueryRowContext(ctx, `
		SELECT pg_catalog.current_schema(),
		       (SELECT reset_val FROM pg_catalog.pg_settings WHERE name='search_path')
	`).Scan(&trusted, &resetPath); err != nil {
		t.Fatal(err)
	}
	if trusted == "" || resetPath == "" {
		t.Fatalf("test connection lacks known schema startup path: schema=%q reset=%q", trusted, resetPath)
	}
	shadow := fmt.Sprintf("guard_untrusted_%d", time.Now().UnixNano())
	var createSchema, dropSchema, restorePath, activatePath string
	for _, item := range []struct {
		lookup string
		args   []any
		dest   *string
	}{
		{"SELECT pg_catalog.format('CREATE SCHEMA %I', $1::text)", []any{shadow}, &createSchema},
		{"SELECT pg_catalog.format('DROP SCHEMA %I CASCADE', $1::text)", []any{shadow}, &dropSchema},
		{"SELECT pg_catalog.format('SET search_path TO %I', $1::text)", []any{trusted}, &restorePath},
		{"SELECT pg_catalog.format('SET search_path TO %I', $1::text)", []any{shadow}, &activatePath},
	} {
		if err := db.QueryRowContext(ctx, item.lookup, item.args...).Scan(item.dest); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, createSchema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), restorePath)
		_, _ = db.ExecContext(context.Background(), dropSchema)
	})

	for _, relation := range []string{
		"guard_schema_migrations",
		"guard_action_operations",
		"guard_outbox_events",
		"guard_accepted_submission_snapshots",
		"guard_permits",
		"guard_operation_intents",
		"guard_execution_audit",
		"guard_operation_unknown_events",
		"guard_permit_revocations",
	} {
		var ddl string
		if err := db.QueryRowContext(ctx, `
			SELECT pg_catalog.format(
				'CREATE TABLE %I.%I (LIKE %I.%I INCLUDING ALL)',
				$1::text, $2::text, $3::text, $2::text)
		`, shadow, relation, trusted).Scan(&ddl); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, ddl); err != nil {
			t.Fatalf("clone %s into alternate schema: %v", relation, err)
		}
	}
	var indexDDL string
	if err := db.QueryRowContext(ctx, `
		SELECT pg_catalog.format(
			'CREATE INDEX guard_outbox_unpublished_idx ON %I.guard_outbox_events (tenant_id)',
			$1::text)
	`, shadow).Scan(&indexDDL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, indexDDL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, activatePath); err != nil {
		t.Fatal(err)
	}

	var active string
	if err := db.QueryRowContext(ctx, "SELECT pg_catalog.current_schema()").Scan(&active); err != nil || active != shadow {
		t.Fatalf("alternate schema not active: schema=%q err=%v", active, err)
	}
	// This is a complete-looking permanent *but unauthorized* schema.
	// Runtime must not report success just because its own OID checks
	// all resolve consistently under the attacker-selected search_path.
	op, created, err := store.Accept(ctx, "tenant-a", "search-path-shadow", sampleSubmission())
	if !errors.Is(err, ErrSchemaDrift) || created || op.OperationID != "" {
		t.Fatalf("non-authoritative search_path accepted: created=%t op=%+v err=%v", created, op, err)
	}
	if _, err := db.ExecContext(ctx, restorePath); err != nil {
		t.Fatal(err)
	}
	var permanent int
	if err := db.QueryRowContext(ctx,
		"SELECT count(*) FROM guard_action_operations WHERE submission_key='search-path-shadow'",
	).Scan(&permanent); err != nil || permanent != 0 {
		t.Fatalf("real Guard schema modified despite unsafe path: rows=%d err=%v", permanent, err)
	}
}
