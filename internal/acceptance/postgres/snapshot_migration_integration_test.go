package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func installOnlyOriginalV1ForUpgradeTest(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	_, err := db.ExecContext(ctx, `
		CREATE TABLE guard_schema_migrations (
			version BIGINT PRIMARY KEY,
			checksum TEXT NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range strings.Split(initialSchema, ";") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(initialSchema)))
	if _, err := db.ExecContext(ctx,
		"INSERT INTO guard_schema_migrations(version,checksum) VALUES (1,$1)", digest); err != nil {
		t.Fatal(err)
	}
}

func TestV2MigrationUpgradesEmptyV1WithoutRewritingOriginalChecksum(t *testing.T) {
	db := unmigratedDatabase(t)
	installOnlyOriginalV1ForUpgradeTest(t, db)
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("upgrade clean v1 to v2: %v", err)
	}
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("repeat exact v2 migration: %v", err)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM guard_schema_migrations").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected two immutable migration ledger rows, got %d", count)
	}
}

func TestV2MigrationRejectsExistingUnsnapshottedV1Operations(t *testing.T) {
	db := unmigratedDatabase(t)
	installOnlyOriginalV1ForUpgradeTest(t, db)
	if _, err := db.Exec(`
		INSERT INTO guard_action_operations(tenant_id,submission_key,submission_digest)
		VALUES ('tenant-a','old-key',$1)
	`, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	err := Migrate(context.Background(), db)
	if !errors.Is(err, ErrSnapshotBackfillRequired) {
		t.Fatalf("v1 accepted operations silently adopted without exact bytes: %v", err)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM guard_schema_migrations").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("failed v2 migration was stamped: count=%d", count)
	}
}

func TestV2MigrationRejectsSnapshotCatalogIntegrityLoss(t *testing.T) {
	for _, tc := range []struct {
		name string
		sql  string
	}{
		{"detached composite FK", "ALTER TABLE guard_accepted_submission_snapshots DROP CONSTRAINT guard_snapshot_operation_binding_fk"},
		{"disabled immutable trigger", "ALTER TABLE guard_accepted_submission_snapshots DISABLE TRIGGER guard_snapshot_immutable_row"},
		{"origin-only immutable trigger", "ALTER TABLE guard_accepted_submission_snapshots ENABLE TRIGGER guard_snapshot_immutable_row"},
		{"origin-only truncate trigger", "ALTER TABLE guard_accepted_submission_snapshots ENABLE TRIGGER guard_snapshot_immutable_truncate"},
		{"removed digest tuple unique", "ALTER TABLE guard_accepted_submission_snapshots DROP CONSTRAINT guard_accepted_submission_snapshots_pkey CASCADE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := unmigratedDatabase(t)
			if err := Migrate(context.Background(), db); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(tc.sql); err != nil {
				t.Fatal(err)
			}
			if err := Migrate(context.Background(), db); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("v2 catalog drift accepted: %v", err)
			}
		})
	}
}

func TestSnapshotMigrationRejectsSameNameWeakenedCheckAndTriggerBody(t *testing.T) {
	for _, tc := range []struct {
		name string
		ddl  []string
	}{
		{"snapshot byte bounds replaced with CHECK TRUE", []string{
			"ALTER TABLE guard_accepted_submission_snapshots DROP CONSTRAINT guard_snapshot_bytes_length_check",
			"ALTER TABLE guard_accepted_submission_snapshots ADD CONSTRAINT guard_snapshot_bytes_length_check CHECK (TRUE)",
		}},
		{"snapshot immutable trigger function replaced", []string{
			`CREATE OR REPLACE FUNCTION guard_reject_snapshot_mutation() RETURNS trigger
			   LANGUAGE plpgsql AS $unsafe$ BEGIN RETURN NEW; END; $unsafe$`,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := unmigratedDatabase(t)
			if err := Migrate(context.Background(), db); err != nil {
				t.Fatal(err)
			}
			for _, statement := range tc.ddl {
				if _, err := db.ExecContext(context.Background(), statement); err != nil {
					t.Fatal(err)
				}
			}
			if err := Migrate(context.Background(), db); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("checksum-matched weakened snapshot catalog bypassed guard: %v", err)
			}
		})
	}
}
