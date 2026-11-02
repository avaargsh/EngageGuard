package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func installLegacyV1ForUpgradeTest(t *testing.T) *Store {
	t.Helper()
	db := unmigratedDatabase(t)
	_, err := db.Exec(`CREATE TABLE guard_schema_migrations (
		version BIGINT PRIMARY KEY,
		checksum TEXT NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range strings.Split(initialSchema, ";") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(initialSchema)))
	if _, err := db.Exec("INSERT INTO guard_schema_migrations(version,checksum) VALUES (1,$1)", sum); err != nil {
		t.Fatal(err)
	}
	return New(db)
}

func TestMigrateUpgradesExistingVersionOneWithoutRewritingItsChecksum(t *testing.T) {
	store := installLegacyV1ForUpgradeTest(t)
	ctx := context.Background()
	if err := Migrate(ctx, store.db); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, store.db); err != nil {
		t.Fatalf("repeated migration: %v", err)
	}
	var count int
	if err := store.db.QueryRow("SELECT count(*) FROM guard_schema_migrations").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("migration history count=%d, want three immutable versions", count)
	}
	var sum string
	if err := store.db.QueryRow("SELECT checksum FROM guard_schema_migrations WHERE version=2").Scan(&sum); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%x", sha256.Sum256([]byte(permitSchema)))
	if sum != want {
		t.Fatalf("v2 checksum=%q, want %q", sum, want)
	}
	if err := store.db.QueryRow("SELECT checksum FROM guard_schema_migrations WHERE version=3").Scan(&sum); err != nil {
		t.Fatal(err)
	}
	want = fmt.Sprintf("%x", sha256.Sum256([]byte(ledgerIntegritySchema)))
	if sum != want {
		t.Fatalf("v3 checksum=%q, want %q", sum, want)
	}
}

func TestMigrateRejectsUnknownOrTamperedVersionTwo(t *testing.T) {
	for _, tc := range []struct{ name, change string }{
		{"tampered checksum", "UPDATE guard_schema_migrations SET checksum=repeat('0',64) WHERE version=2"},
		{"unknown future version", "INSERT INTO guard_schema_migrations(version,checksum) VALUES(4,repeat('a',64))"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := unmigratedDatabase(t)
			if err := Migrate(context.Background(), db); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(tc.change); err != nil {
				t.Fatal(err)
			}
			if err := Migrate(context.Background(), db); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("drift accepted: %v", err)
			}
		})
	}
}

func TestMigrateVersionTwoFailureRollsBackOnlyNewTablesAndMarker(t *testing.T) {
	store := installLegacyV1ForUpgradeTest(t)
	// PostgreSQL creates a composite relation type for every table; a
	// conflicting pre-existing type forces v2 to fail after earlier DDL.
	if _, err := store.db.Exec("CREATE TYPE guard_execution_audit AS (marker integer)"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(context.Background(), store.db); err == nil {
		t.Fatal("expected v2 DDL failure")
	}
	for _, table := range []string{"guard_permits", "guard_operation_intents"} {
		var exists bool
		if err := store.db.QueryRow("SELECT to_regclass($1) IS NOT NULL", table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Fatalf("failed v2 migration left behind %s", table)
		}
	}
	var count int
	if err := store.db.QueryRow("SELECT count(*) FROM guard_schema_migrations").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("failed v2 migration stamped history: %d", count)
	}
}
