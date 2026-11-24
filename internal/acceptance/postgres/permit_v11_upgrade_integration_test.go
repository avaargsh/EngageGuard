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

// Install the actual historical SQL in a fresh disposable schema instead of
// downgrading a v11 database or forging migration history.
func installPermitV10ForUpgradeTest(t *testing.T, db *sql.DB) {
	t.Helper()
	installOnlyOriginalV1ForUpgradeTest(t, db)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := applySnapshotMigration(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := applySnapshotReplicaMigration(ctx, tx); err != nil {
		t.Fatal(err)
	}
	sources := []string{
		permitClaimSchema, permitIdentitySchema, permitUnknownSchema,
		permitRevocationSchema, permitEvidenceFenceSchema,
		permitIdentityFenceSchema, permitCausalCommitSchema,
	}
	for i, source := range sources {
		version := i + 4
		delimiter := ";"
		if version >= 9 {
			delimiter = "-- statement break"
		}
		for _, stmt := range strings.Split(source, delimiter) {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("install historical v%d: %v", version, err)
			}
		}
		checksum := fmt.Sprintf("%x", sha256.Sum256([]byte(source)))
		if _, err := tx.ExecContext(ctx, "INSERT INTO guard_schema_migrations(version,checksum) VALUES ($1,$2)", version, checksum); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestPermitV11UpgradesAuthenticV10WithoutRewritingHistory(t *testing.T) {
	db := unmigratedDatabase(t)
	installPermitV10ForUpgradeTest(t, db)
	ctx := context.Background()
	var schema string
	if err := db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	store, err := NewWithTrustedSchema(db, schema)
	if err != nil {
		t.Fatal(err)
	}
	op, created, err := store.Accept(ctx, "tenant-a", "v10-upgrade", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("historical admission fixture: created=%t err=%v", created, err)
	}
	var oldOID, newOID string
	const lookup = "SELECT 'guard_claim_causal_commit_v10()'::regprocedure::oid::text"
	if err := db.QueryRowContext(ctx, lookup).Scan(&oldOID); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := Migrate(ctx, db); err != nil {
			t.Fatalf("v10 upgrade/restart: %v", err)
		}
	}
	if err := db.QueryRowContext(ctx, lookup).Scan(&newOID); err != nil || oldOID != newOID {
		t.Fatalf("causal function identity changed: old=%s new=%s err=%v", oldOID, newOID, err)
	}
	for i, source := range []string{
		initialSchema, snapshotSchema, snapshotReplicaSchema, permitClaimSchema,
		permitIdentitySchema, permitUnknownSchema, permitRevocationSchema,
		permitEvidenceFenceSchema, permitIdentityFenceSchema, permitCausalCommitSchema,
		permitCausalPinnedSchema,
	} {
		var actual string
		if err := db.QueryRowContext(ctx, "SELECT checksum FROM guard_schema_migrations WHERE version=$1", i+1).Scan(&actual); err != nil || actual != fmt.Sprintf("%x", sha256.Sum256([]byte(source))) {
			t.Fatalf("v%d checksum drift: %v", i+1, err)
		}
	}
	loaded, err := store.ReadAcceptedSubmission(ctx, "tenant-a", op.OperationID)
	if err != nil || loaded.Operation.OperationID != op.OperationID {
		t.Fatalf("historical accepted operation lost: %v", err)
	}
	var permits int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM guard_permits").Scan(&permits); err != nil || permits != 0 {
		t.Fatalf("migration manufactured permits: %d %v", permits, err)
	}
}

func TestPermitV11RejectsTamperedV10WithoutStampingUpgrade(t *testing.T) {
	for _, tc := range []struct {
		name string
		ddl  string
	}{
		{"function-body", "CREATE OR REPLACE FUNCTION guard_claim_causal_commit_v10() RETURNS trigger LANGUAGE plpgsql AS $guard$ BEGIN RETURN NULL; END; $guard$"},
		{"checksum", "UPDATE guard_schema_migrations SET checksum=repeat('0',64) WHERE version=10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := unmigratedDatabase(t)
			installPermitV10ForUpgradeTest(t, db)
			ctx := context.Background()
			if _, err := db.ExecContext(ctx, tc.ddl); err != nil {
				t.Fatal(err)
			}
			if err := Migrate(ctx, db); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("tampered v10 accepted: %v", err)
			}
			var count int
			if err := db.QueryRowContext(ctx, "SELECT count(*) FROM guard_schema_migrations WHERE version=11").Scan(&count); err != nil || count != 0 {
				t.Fatalf("rejected migration stamped v11: %d %v", count, err)
			}
		})
	}
}
