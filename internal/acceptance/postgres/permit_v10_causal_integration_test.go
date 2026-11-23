package postgres

import (
	"context"
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
