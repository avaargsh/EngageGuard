package postgres

import (
	"context"
	"testing"
)

// A deferred PL/pgSQL constraint trigger runs in the caller's session.
// An attacker with TEMP privilege must not satisfy the durable causal-claim
// fence by providing fabricated pg_temp Intent/Audit rows. All statements in
// this test use an isolated migrated PostgreSQL schema; no provider is called.
func TestPermitCausalFenceRejectsTempIntentAndAuditForPermanentClaim(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	ctx := context.Background()
	var hash, binding string
	if err := store.db.QueryRowContext(ctx,
		"SELECT action_hash,binding_digest FROM guard_permits WHERE permit_id=$1::uuid", permitID,
	).Scan(&hash, &binding); err != nil {
		t.Fatal(err)
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, ddl := range []string{
		"CREATE TEMP TABLE guard_operation_intents (tenant_id text, operation_id uuid, permit_id uuid, attempt_id uuid, action_hash text, binding_digest text)",
		"CREATE TEMP TABLE guard_execution_audit (tenant_id text, operation_id uuid, permit_id uuid, attempt_id uuid, action_hash text, event_type text)",
	} {
		if _, err := tx.ExecContext(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	attemptID := "33333333-3333-4333-8333-333333333333"
	if _, err := tx.ExecContext(ctx, `INSERT INTO pg_temp.guard_operation_intents
		(tenant_id,operation_id,permit_id,attempt_id,action_hash,binding_digest)
		VALUES ($1,$2::uuid,$3::uuid,$4::uuid,$5,$6)`,
		resolved.TenantID, resolved.OperationID, permitID, attemptID, hash, binding); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO pg_temp.guard_execution_audit
		(tenant_id,operation_id,permit_id,attempt_id,action_hash,event_type)
		VALUES ($1,$2::uuid,$3::uuid,$4::uuid,$5,'guard.operation.dispatching.v1')`,
		resolved.TenantID, resolved.OperationID, permitID, attemptID, hash); err != nil {
		t.Fatal(err)
	}
	// Update only the REAL Guard Permit table, not its temp namesake.
	var update string
	if err := tx.QueryRowContext(ctx,
		"SELECT pg_catalog.format('UPDATE %I.guard_permits SET state=''CLAIMED'',claimed_at=clock_timestamp() WHERE permit_id=$1::uuid',current_schema())",
	).Scan(&update); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, update, permitID); err != nil {
		t.Fatal(err)
	}
	// No permanent Intent or Audit was written. Commit MUST reject the forged
	// claim, even if the user session supplies matching temporary rows.
	if err := tx.Commit(); err == nil {
		t.Fatal("deferred Guard causal-claim trigger accepted pg_temp fabricated Intent/Audit rows")
	}
	var state string
	if err := store.db.QueryRowContext(ctx, "SELECT state FROM guard_permits WHERE permit_id=$1::uuid", permitID).Scan(&state); err != nil || state != "ISSUED" {
		t.Fatalf("rejected claim must roll back: state=%q err=%v", state, err)
	}
}
