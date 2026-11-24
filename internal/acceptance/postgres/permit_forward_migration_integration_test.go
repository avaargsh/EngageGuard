package postgres

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
)

// The canonical admission v1/v2/v3 bytes are already deployed. A Permit
// ledger must be introduced by additive migrations beginning at v4; reusing
// the old experimental Permit v2/v3 is a destructive history conflict.
func TestForwardPermitLedgerPreservesAdmissionMigrationHistory(t *testing.T) {
	db := unmigratedDatabase(t)
	ctx := context.Background()
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	for version, source := range []string{initialSchema, snapshotSchema, snapshotReplicaSchema, permitClaimSchema, permitIdentitySchema, permitUnknownSchema, permitRevocationSchema, permitEvidenceFenceSchema, permitIdentityFenceSchema, permitCausalCommitSchema, permitCausalPinnedSchema, permitExpiryFenceSchema, permitInitialStateSchema, permitRevocationCausalSchema, permitUnknownCausalSchema, permitAuthorityEvidenceSchema, permitActionRequestEvidenceSchema} {
		var actual string
		if err := db.QueryRowContext(ctx, "SELECT checksum FROM guard_schema_migrations WHERE version=$1", version+1).Scan(&actual); err != nil {
			t.Fatal(err)
		}
		if actual != fmt.Sprintf("%x", sha256.Sum256([]byte(source))) {
			t.Fatalf("changed authoritative migration v%d", version+1)
		}
	}
	var versions int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM guard_schema_migrations").Scan(&versions); err != nil || versions != 17 {
		t.Fatalf("Permit migration must append v4-v17: count=%d %v", versions, err)
	}
	for _, table := range []string{
		"guard_accepted_submission_snapshots",
		"guard_permits", "guard_operation_intents", "guard_execution_audit",
		"guard_operation_unknown_events", "guard_permit_revocations",
		"guard_permit_authority_evidence",
	} {
		var exists bool
		if err := db.QueryRowContext(ctx, "SELECT to_regclass($1) IS NOT NULL", table).Scan(&exists); err != nil || !exists {
			t.Fatalf("missing forward-only relation %s: %v", table, err)
		}
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("repeated forward migration failed: %v", err)
	}
}

// A deployment with v3 only must upgrade without losing the exact captured
// admission snapshot. Migration does not create a Permit from that snapshot.
func TestForwardPermitMigrationDoesNotIssueFromAcceptedSubmission(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	accepted, created, err := store.Accept(ctx, "tenant-a", "permit-upgrade-no-issuer", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("accept existing immutable submission: %v", err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.ReadAcceptedSubmission(ctx, "tenant-a", accepted.OperationID)
	if err != nil || loaded.Operation.OperationID != accepted.OperationID {
		t.Fatalf("admission snapshot not durable across Permit migrations: %v", err)
	}
	var permits int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM guard_permits").Scan(&permits); err != nil || permits != 0 {
		t.Fatalf("migration fabricated Permit issuance: %d %v", permits, err)
	}
}
