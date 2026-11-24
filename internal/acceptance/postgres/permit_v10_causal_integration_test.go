package postgres

import (
	"context"
	"errors"
	"testing"
)

// A claimed Permit alone is not proof of a dispatch. A normal SQL writer
// must be unable to commit CLAIMED without both its exact Intent and its
// immutable pre-dispatch Audit, even when bypassing the Go claim helper.
// These are test-only seeded Permits, NOT trusted production issuance.
func TestPermitClaimedRequiresCompleteCausalJournalAtCommit(t *testing.T) {
	for _, tc := range []struct {
		name       string
		withIntent bool
	}{
		{name: "claimed-without-intent-or-audit"},
		{name: "claimed-with-intent-but-no-audit", withIntent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, resolved, permitID := seededWorkspacePermit(t)
			ctx := context.Background()
			tx, err := store.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err := tx.ExecContext(ctx, `
				UPDATE guard_permits
				SET state='CLAIMED', claimed_at=clock_timestamp()
				WHERE tenant_id=$1 AND permit_id=$2::uuid
			`, resolved.TenantID, permitID); err != nil {
				t.Fatalf("staging a state transition should be checked at commit: %v", err)
			}
			if tc.withIntent {
				if _, err := tx.ExecContext(ctx, `
					INSERT INTO guard_operation_intents
						(tenant_id, operation_id, permit_id, action_hash, binding_digest, state)
					SELECT tenant_id, operation_id, permit_id, action_hash,
					       binding_digest, 'DISPATCHING'
					FROM guard_permits
					WHERE tenant_id=$1 AND permit_id=$2::uuid
				`, resolved.TenantID, permitID); err != nil {
					t.Fatalf("staging an Intent without Audit should be checked at commit: %v", err)
				}
			}
			if err := tx.Commit(); err == nil {
				t.Fatal("CLAIMED Permit committed without complete immutable Intent/Audit")
			}
			var state string
			if err := store.db.QueryRowContext(ctx, `
				SELECT state FROM guard_permits WHERE tenant_id=$1 AND permit_id=$2::uuid
			`, resolved.TenantID, permitID).Scan(&state); err != nil || state != "ISSUED" {
				t.Fatalf("failed causal commit changed Permit state: %s, %v", state, err)
			}
			for _, table := range []string{"guard_operation_intents", "guard_execution_audit"} {
				var count int
				if err := store.db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != 0 {
					t.Fatalf("failed causal commit persisted %d rows in %s: %v", count, table, err)
				}
			}
		})
	}
}

// The same Commit fence must reject independently inserted Intents that do
// not belong to a CLAIMED Permit. Foreign keys alone bind the identity but
// do not establish the causal state transition.
func TestPermitIntentCannotCommitAgainstUnclaimedPermit(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	ctx := context.Background()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO guard_operation_intents
			(tenant_id, operation_id, permit_id, action_hash, binding_digest, state)
		SELECT tenant_id, operation_id, permit_id, action_hash,
		       binding_digest, 'DISPATCHING'
		FROM guard_permits
		WHERE tenant_id=$1 AND permit_id=$2::uuid
	`, resolved.TenantID, permitID); err != nil {
		t.Fatalf("staging Intent must reach deferred causal gate: %v", err)
	}
	if err := tx.Commit(); err == nil {
		t.Fatal("orphan Intent committed while Permit was still ISSUED")
	}
	var count int
	if err := store.db.QueryRowContext(ctx,
		"SELECT count(*) FROM guard_operation_intents").Scan(&count); err != nil || count != 0 {
		t.Fatalf("orphan Intent persisted after rejected commit: %d, %v", count, err)
	}
}

// A matching migration checksum alone must not accept a disabled deferred
// constraint trigger. Startup is a reader of actual PostgreSQL enforcement.
func TestPermitV10StartupRejectsDisabledCausalTrigger(t *testing.T) {
	store, _, _ := seededWorkspacePermit(t)
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx,
		"ALTER TABLE guard_permits DISABLE TRIGGER guard_permit_causal_commit_v10"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, store.db); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("disabled v10 causal trigger was approved: %v", err)
	}
}

// Simulate a privileged owner bypassing the v10 trigger during a write,
// restoring it, and leaving an already-committed v9-style orphan. Ordinary
// runtime roles must not have such DDL privileges. Startup must still HOLD.
func TestPermitV10StartupRejectsHistoricalOrphanAfterOwnerTamper(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	ctx := context.Background()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// This fixture simulates a privileged owner bypassing both deferred
	// fences. Disable them before the UPDATE so no pending trigger events
	// prevent restoring the catalog in this same transaction.
	for _, trigger := range []string{"guard_permit_causal_commit_v10", "guard_permit_claim_expiry_v12", "guard_permit_revocation_commit_v14"} {
		if _, err := tx.ExecContext(ctx, "ALTER TABLE guard_permits DISABLE TRIGGER "+trigger); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE guard_permits
		SET state='CLAIMED', claimed_at=clock_timestamp()
		WHERE tenant_id=$1 AND permit_id=$2::uuid
	`, resolved.TenantID, permitID); err != nil {
		t.Fatal(err)
	}
	for _, trigger := range []string{"guard_permit_causal_commit_v10", "guard_permit_claim_expiry_v12", "guard_permit_revocation_commit_v14"} {
		if _, err := tx.ExecContext(ctx, "ALTER TABLE guard_permits ENABLE ALWAYS TRIGGER "+trigger); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, store.db); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("historical orphan CLAIMED Permit passed startup attestation: %v", err)
	}
}

// A CREATE OR REPLACE FUNCTION preserves the function OID and trigger
// attachment. Startup must attest the actual v10 body, not only its name.
func TestPermitV10StartupRejectsReplacedCausalFunctionBody(t *testing.T) {
	store, _, _ := seededWorkspacePermit(t)
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, `
		CREATE OR REPLACE FUNCTION guard_claim_causal_commit_v10()
		RETURNS trigger LANGUAGE plpgsql AS $guard$
		BEGIN
			RETURN NULL;
		END;
		$guard$
	`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, store.db); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("replaced v10 causal function body passed startup attestation: %v", err)
	}
}

// Startup must reject trigger definition drift even when the function OID,
// event bitmask, enabled state and deferred properties remain unchanged.
func TestPermitV10StartupRejectsCausalTriggerMetadataDrift(t *testing.T) {
	for _, tc := range []struct {
		name   string
		events string
		when   string
		args   string
	}{
		{name: "conditional", events: "INSERT OR UPDATE", when: " WHEN (false)"},
		{name: "column-filter", events: "INSERT OR UPDATE OF revoked_at"},
		{name: "unexpected-argument", events: "INSERT OR UPDATE", args: "'unexpected'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, _, _ := seededWorkspacePermit(t)
			ctx := context.Background()
			for _, stmt := range []string{
				"DROP TRIGGER guard_permit_causal_commit_v10 ON guard_permits",
				"CREATE CONSTRAINT TRIGGER guard_permit_causal_commit_v10 AFTER " + tc.events +
					" ON guard_permits DEFERRABLE INITIALLY DEFERRED FOR EACH ROW" + tc.when +
					" EXECUTE FUNCTION guard_claim_causal_commit_v10(" + tc.args + ")",
				"ALTER TABLE guard_permits ENABLE ALWAYS TRIGGER guard_permit_causal_commit_v10",
			} {
				if _, err := store.db.ExecContext(ctx, stmt); err != nil {
					t.Fatalf("isolated trigger drift setup: %v", err)
				}
			}
			if err := Migrate(ctx, store.db); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("v10 causal trigger metadata drift passed startup attestation: %v", err)
			}
		})
	}
}
