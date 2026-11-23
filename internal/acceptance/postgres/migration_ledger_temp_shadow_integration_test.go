package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A valid-looking pg_temp copy must never substitute for the authoritative
// permanent migration history. The historical checksum is intentionally
// corrupted *only* in a disposable isolated PostgreSQL schema.
func TestMigrationRejectsPermanentChecksumDriftBehindTempLedgerShadow(t *testing.T) {
	_, db := integrationStore(t)
	db.SetMaxOpenConns(1) // force the same physical PostgreSQL session
	db.SetMaxIdleConns(1)
	ctx := context.Background()

	var sqlCopy string
	if err := db.QueryRowContext(ctx, `
		SELECT pg_catalog.format(
			'CREATE TEMP TABLE guard_schema_migrations AS SELECT version,checksum,applied_at FROM %I.guard_schema_migrations',
			current_schema()
		)
	`).Scan(&sqlCopy); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, sqlCopy); err != nil {
		t.Fatal(err)
	}
	var fakeRows int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM pg_temp.guard_schema_migrations").Scan(&fakeRows); err != nil || fakeRows != 13 {
		t.Fatalf("temporary migration ledger fixture not populated: rows=%d err=%v", fakeRows, err)
	}

	var sqlDamage string
	if err := db.QueryRowContext(ctx, `
		SELECT pg_catalog.format(
			'UPDATE %I.guard_schema_migrations SET checksum=$1 WHERE version=13',
			current_schema()
		)
	`).Scan(&sqlDamage); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, sqlDamage, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	// The unqualified table name resolves to the fake, intact temp table,
	// whereas the actual migration ledger now has an invalid v13 checksum.
	var isShadowed bool
	if err := db.QueryRowContext(ctx, `
		SELECT pg_catalog.to_regclass('guard_schema_migrations') =
		       pg_catalog.to_regclass('pg_temp.guard_schema_migrations')
	`).Scan(&isShadowed); err != nil || !isShadowed {
		t.Fatalf("test did not establish migration-ledger shadow: shadowed=%t err=%v", isShadowed, err)
	}
	if err := Migrate(ctx, db); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("permanent v13 checksum drift concealed by pg_temp ledger: got %v, want ErrSchemaDrift", err)
	}
}
