package postgres

import (
	"context"
	"strings"
	"testing"
)

// Reconstruct an actual v12 function body and checksum ledger in an isolated
// test schema. v13 must upgrade in place without rewriting any historical
// migration checksum, replacing the trigger OID or granting an effect.
func TestV13UpgradeFromHistoricalV12PreservesCausalTriggerAndChecksums(t *testing.T) {
	_, db := integrationStore(t)
	ctx := context.Background()
	var originalFunction, originalTrigger, originalV10Checksum string
	if err := db.QueryRowContext(ctx,
		"SELECT pg_catalog.to_regprocedure('guard_permit_causal_transition_v10()')::oid::text",
	).Scan(&originalFunction); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT t.oid::text FROM pg_catalog.pg_trigger t
		WHERE t.tgrelid='guard_permits'::regclass
		  AND t.tgname='guard_permit_causal_transition_v10'`).Scan(&originalTrigger); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx,
		"SELECT checksum FROM guard_schema_migrations WHERE version=10",
	).Scan(&originalV10Checksum); err != nil {
		t.Fatal(err)
	}
	oldSource := strings.SplitN(permitCausalFenceSchema, "-- statement break", 2)[0]
	oldSource = strings.Replace(oldSource,
		"CREATE FUNCTION guard_permit_causal_transition_v10()",
		"CREATE OR REPLACE FUNCTION guard_permit_causal_transition_v10()", 1)
	if _, err := db.ExecContext(ctx, oldSource); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM guard_schema_migrations WHERE version=13"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("historical v12 to v13 upgrade failed: %v", err)
	}
	var functionOID, triggerOID, checksum string
	var versions int
	if err := db.QueryRowContext(ctx,
		"SELECT pg_catalog.to_regprocedure('guard_permit_causal_transition_v10()')::oid::text",
	).Scan(&functionOID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT t.oid::text FROM pg_catalog.pg_trigger t
		WHERE t.tgrelid='guard_permits'::regclass
		  AND t.tgname='guard_permit_causal_transition_v10'`).Scan(&triggerOID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, "SELECT checksum FROM guard_schema_migrations WHERE version=10").Scan(&checksum); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM guard_schema_migrations").Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if originalFunction != functionOID || originalTrigger != triggerOID ||
		checksum != originalV10Checksum || versions != 13 {
		t.Fatalf("v13 upgraded destructively: function=%s/%s trigger=%s/%s v10-checksum=%s/%s versions=%d",
			originalFunction, functionOID, originalTrigger, triggerOID,
			originalV10Checksum, checksum, versions)
	}
}

// The same v10 function also attested Permit revocation through an
// unqualified table name. A temporary matching journal row must never
// authorize a permanent revoked_at transition without durable evidence.
func TestV13CausalRevocationFenceRejectsTemporaryFakeJournal(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	ctx := context.Background()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		"CREATE TEMP TABLE guard_permit_revocations (tenant_id text,permit_id uuid,prior_state text)"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO pg_temp.guard_permit_revocations VALUES ($1,$2::uuid,'ISSUED')",
		resolved.TenantID, permitID); err != nil {
		t.Fatal(err)
	}
	var ddl string
	if err := tx.QueryRowContext(ctx,
		"SELECT pg_catalog.format('UPDATE %I.guard_permits SET revoked_at=clock_timestamp() WHERE permit_id=$1::uuid',current_schema())",
	).Scan(&ddl); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, ddl, permitID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err == nil {
		t.Fatal("deferred revocation trigger accepted temporary journal as committed evidence")
	}
	var revocations int
	if err := store.db.QueryRowContext(ctx,
		"SELECT count(*) FROM guard_permit_revocations WHERE permit_id=$1::uuid", permitID,
	).Scan(&revocations); err != nil || revocations != 0 {
		t.Fatalf("rejected revocation wrote permanent history: count=%d err=%v", revocations, err)
	}
}
