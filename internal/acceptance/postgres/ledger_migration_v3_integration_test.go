package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Install a real pre-v3 ledger with matching immutable v1/v2 checksums.
func legacyV2Store(t *testing.T) *Store {
	t.Helper()
	store := installLegacyV1ForUpgradeTest(t)
	for _, statement := range strings.Split(permitSchema, ";") {
		if strings.TrimSpace(statement) == "" {
			continue
		}
		if _, err := store.db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(permitSchema)))
	if _, err := store.db.Exec(
		"INSERT INTO guard_schema_migrations(version,checksum) VALUES(2,$1)", sum,
	); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestLedgerV3UpgradeRejectsExistingCrossOperationRows(t *testing.T) {
	store := legacyV2Store(t)
	ctx := context.Background()
	first, created, err := store.Accept(ctx, "tenant-a", "legacy-key-1", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("first legacy acceptance: created=%v err=%v", created, err)
	}
	second, created, err := store.Accept(ctx, "tenant-a", "legacy-key-2", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("second legacy acceptance: created=%v err=%v", created, err)
	}
	var permitID, attemptID string
	if err := store.db.QueryRow(`
		INSERT INTO guard_permits
		    (tenant_id, operation_id, action_hash, binding_digest, audience,
		     policy_version, issued_by, expires_at)
		VALUES ($1,$2::uuid,$3,$4,$5,$6,$7,$8)
		RETURNING permit_id::text
	`, "tenant-a", first.OperationID, strings.Repeat("a", 64), strings.Repeat("b", 64),
		"workspace-executor", "policy-1", "legacy-test-issuer", time.Now().Add(time.Hour)).Scan(&permitID); err != nil {
		t.Fatal(err)
	}
	// Pre-v3 FKs verify operation and permit separately; this inconsistent row
	// is accepted by the legacy ledger but MUST block a production upgrade.
	if err := store.db.QueryRow(`
		INSERT INTO guard_operation_intents
			(tenant_id, operation_id, permit_id, action_hash, binding_digest, state)
		VALUES ('tenant-a',$1::uuid,$2::uuid,$3,$4,'DISPATCHING')
		RETURNING attempt_id::text
	`, second.OperationID, permitID, strings.Repeat("a", 64), strings.Repeat("b", 64)).Scan(&attemptID); err != nil {
		t.Fatalf("expected legacy v2 vulnerability fixture to be insertable: %v", err)
	}
	if attemptID == "" {
		t.Fatal("missing legacy attempt ID")
	}
	if err := Migrate(ctx, store.db); err == nil {
		t.Fatal("v3 migration accepted inconsistent legacy operation bindings")
	}
	var versions int
	if err := store.db.QueryRow("SELECT count(*) FROM guard_schema_migrations").Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions != 2 {
		t.Fatalf("failed migration incorrectly stamped history: %d", versions)
	}
	// Operator-managed remediation must precede v3; do not auto-rewrite evidence.
	if _, err := store.db.Exec("DELETE FROM guard_operation_intents WHERE attempt_id=$1::uuid", attemptID); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, store.db); err != nil {
		t.Fatalf("clean legacy ledger should upgrade: %v", err)
	}
	if err := store.db.QueryRow("SELECT count(*) FROM guard_schema_migrations").Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions != 3 {
		t.Fatalf("upgraded history = %d, expected 3", versions)
	}
}

func TestLedgerV3ChecksumDriftFailsClosed(t *testing.T) {
	db := unmigratedDatabase(t)
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE guard_schema_migrations SET checksum=repeat('0',64) WHERE version=3"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(context.Background(), db); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("modified v3 checksum accepted: %v", err)
	}
}
