package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// Direct SQL, NOT Guard's application ClaimAuthorizedIntent: it confirms that
// even a writer which checked expiry BEFORE the final durable journal write
// cannot COMMIT an already-expired CLAIMED Permit. No provider is involved.
func TestDeferredExpiryFenceRejectsLateCommitWithExactCausalEvidence(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	op, created, err := store.Accept(ctx, "tenant-a", "deferred-expiry-1", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("accept: %v, created=%t", err, created)
	}
	resolved := action.WorkspaceWrite{
		SchemaVersion: "v0.1", TenantID: "tenant-a",
		SubjectID: "verified-runtime-subject", AgentID: "verified-agent",
		OperationID: op.OperationID, CapabilityID: "workspace.write",
		ToolBindingDigest: strings.Repeat("a", 64), PolicyVersion: "signed-policy-7",
		Audience: "trusted-workspace-executor", WorkspaceID: "workspace-1",
		RelativePath: "docs/output.md", ContentDigest: strings.Repeat("b", 64),
	}
	hash, err := action.Hash(resolved)
	if err != nil {
		t.Fatal(err)
	}
	var permitID string
	err = db.QueryRowContext(ctx, `INSERT INTO guard_permits
		(tenant_id,operation_id,action_hash,binding_digest,audience,
		policy_version,issued_by,expires_at)
		VALUES ($1,$2::uuid,$3,$4,$5,$6,'test-only-issuer',
		clock_timestamp()+interval '2 seconds')
		RETURNING permit_id::text`,
		resolved.TenantID, resolved.OperationID, hash,
		resolved.ToolBindingDigest, resolved.Audience, resolved.PolicyVersion).
		Scan(&permitID)
	if err != nil {
		t.Fatal(err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	changed, err := tx.ExecContext(ctx, `UPDATE guard_permits
		SET state='CLAIMED', claimed_at=clock_timestamp()
		WHERE tenant_id=$1 AND permit_id=$2::uuid
		  AND state='ISSUED' AND revoked_at IS NULL
		  AND expires_at > clock_timestamp()`, resolved.TenantID, permitID)
	if err != nil {
		t.Fatal(err)
	}
	n, err := changed.RowsAffected()
	if err != nil || n != 1 {
		t.Fatalf("test fixture did not claim before expiry: rows=%d, err=%v", n, err)
	}
	var attemptID string
	err = tx.QueryRowContext(ctx, `INSERT INTO guard_operation_intents
		(tenant_id,operation_id,permit_id,action_hash,binding_digest,state)
		VALUES ($1,$2::uuid,$3::uuid,$4,$5,'DISPATCHING')
		RETURNING attempt_id::text`,
		resolved.TenantID, resolved.OperationID, permitID, hash,
		resolved.ToolBindingDigest).Scan(&attemptID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO guard_execution_audit
		(tenant_id,operation_id,permit_id,attempt_id,event_type,action_hash)
		VALUES ($1,$2::uuid,$3::uuid,$4::uuid,'guard.operation.dispatching.v1',$5)`,
		resolved.TenantID, resolved.OperationID, permitID, attemptID, hash)
	if err != nil {
		t.Fatal(err)
	}

	// The v10 causal trigger must have both exact rows. Waiting after those
	// writes bypasses the v46 application's SQL-before-commit freshness test
	// and should be rejected by a v11 deferred transaction-end check.
	if _, err = tx.ExecContext(ctx, "SELECT pg_sleep(3.5)"); err != nil {
		t.Fatal(err)
	}
	var expired bool
	if err = tx.QueryRowContext(ctx,
		"SELECT expires_at <= clock_timestamp() FROM guard_permits WHERE permit_id=$1::uuid",
		permitID).Scan(&expired); err != nil || !expired {
		t.Fatalf("fixture did not cross Permit expiry: expired=%t err=%v", expired, err)
	}
	if err = tx.Commit(); err == nil {
		t.Fatal("expired CLAIMED Permit committed with matching Intent and Audit")
	}
	var state string
	var claimed bool
	if err = db.QueryRowContext(ctx,
		"SELECT state,claimed_at IS NOT NULL FROM guard_permits WHERE permit_id=$1::uuid",
		permitID).Scan(&state, &claimed); err != nil || state != "ISSUED" || claimed {
		t.Fatalf("late claim committed partial Permit: state=%s claimed=%t err=%v", state, claimed, err)
	}
	var intents, audits int
	if err = db.QueryRowContext(ctx,
		"SELECT (SELECT count(*) FROM guard_operation_intents),(SELECT count(*) FROM guard_execution_audit)").
		Scan(&intents, &audits); err != nil || intents != 0 || audits != 0 {
		t.Fatalf("late claim left durable intent/audit: %d/%d err=%v", intents, audits, err)
	}
}

func TestPermitExpiryDeferredFenceCannotBeDisabledUndetected(t *testing.T) {
	store, _ := seededWorkspacePermit(t)
	if _, err := store.db.Exec(
		"ALTER TABLE guard_permits DISABLE TRIGGER guard_permit_claim_expiry_v11",
	); err != nil {
		t.Fatal("expected installed v11 trigger:", err)
	}
	if err := Migrate(context.Background(), store.db); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("disabled deferred expiry trigger accepted by migration catalog: %v", err)
	}
}
