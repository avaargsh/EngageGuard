package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
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
	// After quarantining the attacker-controlled temporary objects, the
	// same pooled session must resume reading the original durable source.
	// This is a recovery-positive control, not permission to use temp data.
	for _, name := range []string{"guard_accepted_submission_snapshots", "guard_action_operations"} {
		var ddl string
		if err := db.QueryRowContext(ctx,
			"SELECT pg_catalog.format('DROP TABLE pg_temp.%I', $1::text)", name,
		).Scan(&ddl); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, ddl); err != nil {
			t.Fatalf("remove temp-only source %s: %v", name, err)
		}
	}
	clean, err := store.ReadAcceptedSubmission(ctx, "tenant-a", op.OperationID)
	if err != nil || clean.Operation.OperationID != op.OperationID || len(clean.Raw) == 0 {
		t.Fatalf("original accepted source did not recover: op=%+v bytes=%d err=%v",
			clean.Operation, len(clean.Raw), err)
	}
}

// A schema verified at startup can be weakened later without changing
// its relation OIDs or name resolution. Crash-unsafe accepted evidence or
// a crash-unsafe migration ledger must never be used as a source authority.
func TestReadAcceptedSubmissionRejectsPostMigrationUnloggedSource(t *testing.T) {
	for _, table := range []string{
		"guard_accepted_submission_snapshots",
		"guard_schema_migrations",
	} {
		t.Run(table, func(t *testing.T) {
			store, db := integrationStore(t)
			ctx := context.Background()
			op, created, err := store.Accept(ctx, "tenant-a", "unlogged-source", sampleSubmission())
			if err != nil || !created {
				t.Fatalf("seed accepted submission: created=%t err=%v", created, err)
			}
			if _, err := store.ReadAcceptedSubmission(ctx, op.TenantID, op.OperationID); err != nil {
				t.Fatalf("read original permanent source: %v", err)
			}
			if _, err := db.ExecContext(ctx, "ALTER TABLE "+table+" SET UNLOGGED"); err != nil {
				t.Fatalf("test-only migration-role drift fixture: %v", err)
			}
			value, err := store.ReadAcceptedSubmission(ctx, op.TenantID, op.OperationID)
			if !errors.Is(err, ErrSchemaDrift) || value.Operation.OperationID != "" || len(value.Raw) != 0 {
				t.Fatalf("post-migration crash-unsafe %s accepted: record=%+v err=%v", table, value.Operation, err)
			}
		})
	}
}

// The initial search_path can itself be a complete attacker-writable
// lookalike schema. A stable session.reset_val is not a deployment trust
// anchor. The accepted-source API must refuse a database Store that has no
// independently configured authoritative schema identity.
func TestAcceptedSubmissionRejectsMaliciousStartupSchema(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	op, created, err := store.Accept(ctx, "tenant-a", "startup-schema-source", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("seed original accepted operation: created=%t err=%v", created, err)
	}
	var trustedSchema string
	if err := db.QueryRowContext(ctx, "SELECT pg_catalog.current_schema()").Scan(&trustedSchema); err != nil {
		t.Fatal(err)
	}
	decoy := fmt.Sprintf("guard_startup_decoy_%d", time.Now().UnixNano())
	if _, err := db.ExecContext(ctx, "CREATE SCHEMA "+decoy); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP SCHEMA "+decoy+" CASCADE")
	})
	for _, name := range []string{"guard_schema_migrations", "guard_action_operations", "guard_accepted_submission_snapshots"} {
		var ddl, dml string
		if err := db.QueryRowContext(ctx, `
			SELECT pg_catalog.format('CREATE TABLE %I.%I (LIKE %I.%I INCLUDING ALL)',
				$1::text, $2::text, $3::text, $2::text),
			       pg_catalog.format('INSERT INTO %I.%I SELECT * FROM %I.%I',
				$1::text, $2::text, $3::text, $2::text)
		`, decoy, name, trustedSchema).Scan(&ddl, &dml); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, ddl); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, dml); err != nil {
			t.Fatal(err)
		}
	}
	dsn := os.Getenv("GUARD_PG_DSN")
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = decoy
	wrongDB := stdlib.OpenDB(*config)
	wrongDB.SetMaxOpenConns(1)
	wrongDB.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = wrongDB.Close() })
	var active, reset string
	if err := wrongDB.QueryRowContext(ctx, `
		SELECT pg_catalog.current_schema(),
		       (SELECT reset_val FROM pg_catalog.pg_settings WHERE name='search_path')
	`).Scan(&active, &reset); err != nil || active != decoy || reset != decoy {
		t.Fatalf("test requires malicious initial/reset schema: current=%q reset=%q err=%v", active, reset, err)
	}
	// A default Store without an independently pinned schema may serve
	// ordinary admission writes but must not attest accepted-source bytes.
	rec, err := New(wrongDB).ReadAcceptedSubmission(ctx, "tenant-a", op.OperationID)
	if !errors.Is(err, ErrSchemaDrift) || len(rec.Raw) != 0 {
		t.Fatalf("untrusted startup schema accepted forged original source: op=%+v err=%v", rec.Operation, err)
	}
	// Even a valid configured Store must reject the adversarial connection:
	// its startup/reset path is a complete-looking permanent clone, but
	// differs from the independently provisioned authoritative namespace.
	pinnedWrong, err := NewWithTrustedSchema(wrongDB, trustedSchema)
	if err != nil {
		t.Fatal(err)
	}
	if record, err := pinnedWrong.ReadAcceptedSubmission(ctx, "tenant-a", op.OperationID); !errors.Is(err, ErrSchemaDrift) || len(record.Raw) != 0 {
		t.Fatalf("operator-pinned trusted schema bypassed by decoy startup path: op=%+v err=%v", record.Operation, err)
	}
	// Positive control: the trusted Store continues to read the original
	// immutable bytes from the separately provisioned schema.
	original, err := store.ReadAcceptedSubmission(ctx, "tenant-a", op.OperationID)
	if err != nil || len(original.Raw) == 0 {
		t.Fatalf("trusted permanent accepted source became unreadable: err=%v", err)
	}
}

// A fully migrated alternate PostgreSQL schema has all Guard indexes and
// v13 Permit tables, so the generic runtime relation checker alone can accept
// it when that schema is selected at connection startup. Only the separate,
// operator-pinned accepted-source namespace can reject this source substitution.
func TestReadAcceptedSubmissionRejectsFullyMigratedDecoyStartupSchema(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	real, created, err := store.Accept(ctx, "tenant-a", "complete-decoy-source", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("seed real durable source: created=%t err=%v", created, err)
	}
	var trusted string
	if err := db.QueryRowContext(ctx, "SELECT pg_catalog.current_schema()").Scan(&trusted); err != nil {
		t.Fatal(err)
	}
	decoy := fmt.Sprintf("guard_complete_decoy_%d", time.Now().UnixNano())
	if _, err := db.ExecContext(ctx, "CREATE SCHEMA "+decoy); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP SCHEMA "+decoy+" CASCADE")
	})
	config, err := pgx.ParseConfig(os.Getenv("GUARD_PG_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = decoy
	wrongDB := stdlib.OpenDB(*config)
	wrongDB.SetMaxOpenConns(1)
	wrongDB.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = wrongDB.Close() })
	if err := Migrate(ctx, wrongDB); err != nil {
		t.Fatalf("install independently complete decoy migration catalog: %v", err)
	}
	var fullyMigrated bool
	if err := wrongDB.QueryRowContext(ctx, `
		SELECT pg_catalog.current_schema()=$1::text
		       AND pg_catalog.to_regclass('guard_permits') IS NOT NULL
		       AND pg_catalog.to_regclass('guard_execution_audit') IS NOT NULL
		       AND (SELECT max(version) FROM guard_schema_migrations) >= 13
	`, decoy).Scan(&fullyMigrated); err != nil || !fullyMigrated {
		t.Fatalf("test precondition: decoy is not a full v13 Guard installation: migrated=%t err=%v", fullyMigrated, err)
	}
	fake, created, err := New(wrongDB).Accept(ctx, "tenant-a", "complete-decoy-source", sampleSubmission())
	if err != nil || !created || fake.OperationID == real.OperationID {
		t.Fatalf("test precondition: decoy must contain distinct authentic-shape acceptance: op=%+v created=%t err=%v", fake, created, err)
	}
	pinned, err := NewWithTrustedSchema(wrongDB, trusted)
	if err != nil {
		t.Fatal(err)
	}
	record, err := pinned.ReadAcceptedSubmission(ctx, fake.TenantID, fake.OperationID)
	if !errors.Is(err, ErrSchemaDrift) || record.Operation.OperationID != "" || len(record.Raw) != 0 {
		t.Fatalf("complete initial/reset schema substitution trusted: op=%+v bytes=%d err=%v", record.Operation, len(record.Raw), err)
	}
	original, err := store.ReadAcceptedSubmission(ctx, real.TenantID, real.OperationID)
	if err != nil || original.Operation.OperationID != real.OperationID || len(original.Raw) == 0 {
		t.Fatalf("real accepted source did not survive decoy: op=%+v err=%v", original.Operation, err)
	}
}
