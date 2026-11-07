package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Each migration test owns an empty schema; tests never mutate shared state.
func unmigratedDatabase(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("GUARD_PG_DSN")
	if dsn == "" {
		t.Skip("GUARD_PG_DSN required for real PostgreSQL integration")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin := stdlib.OpenDB(*config)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("guard_migration_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*config)
	db.SetMaxOpenConns(20)
	t.Cleanup(func() {
		_ = db.Close()
		_, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close()
	})
	return db
}

func TestMigrateConcurrentFirstInstallAndChecksumReplay(t *testing.T) {
	db := unmigratedDatabase(t)
	const workers = 12
	var wg sync.WaitGroup
	results := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			results <- Migrate(ctx, db)
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent Migrate() error = %v", err)
		}
	}
	var count int
	var checksum string
	if err := db.QueryRow("SELECT count(*), max(checksum) FROM guard_schema_migrations WHERE version = 1").Scan(&count, &checksum); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%x", sha256.Sum256([]byte(initialSchema)))
	if count != 1 || checksum != want {
		t.Fatalf("versioned installation = (%d,%q), want (1,%q)", count, checksum, want)
	}
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("idempotent Migrate() error = %v", err)
	}
	if _, err := db.Exec("UPDATE guard_schema_migrations SET checksum=$1 WHERE version=1", strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(context.Background(), db); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("modified migration checksum accepted: %v, want ErrSchemaDrift", err)
	}
}

func TestMigrateFailedDDLDoesNotLeavePartialSchema(t *testing.T) {
	db := unmigratedDatabase(t)
	// A pre-existing type (not a table/view) conflicts with the composite
	// type PostgreSQL creates for the second table. This fails after the
	// operation table was created inside the transaction; rollback must
	// remove that partial installation as well as the migration ledger.
	if _, err := db.Exec("CREATE TYPE guard_outbox_events AS (marker integer)"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(context.Background(), db); err == nil {
		t.Fatal("expected migration to fail on conflicting composite type")
	}
	for _, relation := range []string{"guard_action_operations", "guard_schema_migrations"} {
		var exists bool
		if err := db.QueryRow("SELECT to_regclass($1) IS NOT NULL", relation).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Fatalf("failed migration left behind %s", relation)
		}
	}
}

func TestMigrateRejectsUnversionedExistingTables(t *testing.T) {
	db := unmigratedDatabase(t)
	if _, err := db.Exec("CREATE TABLE guard_action_operations (unsafe_id integer)"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(context.Background(), db); !errors.Is(err, ErrUnversionedSchema) {
		t.Fatalf("unversioned preexisting schema accepted: %v, want ErrUnversionedSchema", err)
	}
	var exists bool
	if err := db.QueryRow("SELECT to_regclass('guard_schema_migrations') IS NOT NULL").Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("rejected unversioned schema was stamped as migrated")
	}
}
