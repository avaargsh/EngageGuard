package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// A Permit can be valid at the original UPDATE but expire while committing
// the Intent and immutable Audit. The late DB clock must be checked before
// the transaction commits; an expired grant is never a dispatch receipt.
func TestPermitCannotClaimAfterAuditInsertWaitsPastExpiry(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	op, created, err := store.Accept(ctx, "tenant-a", "permit-late-expiry", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("accept: %v created=%t", err, created)
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
	// Expiry is set by PostgreSQL AFTER database migration and admission, to
	// avoid accidentally expiring before the first claim UPDATE.
	err = db.QueryRowContext(ctx, `INSERT INTO guard_permits
		(tenant_id, operation_id, action_hash, binding_digest, audience,
		 policy_version, issued_by, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,'test-only-issuer',
		 clock_timestamp() + interval '2 seconds')
		RETURNING permit_id::text`,
		resolved.TenantID, op.OperationID, hash, resolved.ToolBindingDigest,
		resolved.Audience, resolved.PolicyVersion).Scan(&permitID)
	if err != nil {
		t.Fatal(err)
	}
	// This trigger runs only AFTER the claimed update and attempted Intent
	// insertion. Its sleep deterministically crosses the original Permit TTL.
	_, err = db.ExecContext(ctx, `CREATE FUNCTION guard_test_delay_dispatch_audit() RETURNS trigger LANGUAGE plpgsql AS
		$$ BEGIN PERFORM pg_sleep(3.5); RETURN NEW; END; $$`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `CREATE TRIGGER guard_test_slow_dispatch_audit
		BEFORE INSERT ON guard_execution_audit
		FOR EACH ROW EXECUTE FUNCTION guard_test_delay_dispatch_audit()`)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = store.ClaimAuthorizedIntent(ctx, permitID, resolved)
	if time.Since(started) < 3*time.Second {
		t.Fatalf("late-expiry fixture did not reach the delayed audit insertion: elapsed=%s claimErr=%v",
			time.Since(started), err)
	}
	if !errors.Is(err, ErrPermitUnavailable) {
		t.Fatalf("Permit expired while journal persisted yet claim was accepted: err=%v", err)
	}
	var state string
	var claimed bool
	if err := db.QueryRowContext(ctx, `SELECT state, claimed_at IS NOT NULL
		FROM guard_permits WHERE permit_id=$1::uuid`, permitID).Scan(&state, &claimed); err != nil {
		t.Fatal(err)
	}
	if state != "ISSUED" || claimed {
		t.Fatalf("expired claim left a partial Permit state: %s claimed=%t", state, claimed)
	}
	var intents, audits int
	if err := db.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM guard_operation_intents),
		(SELECT count(*) FROM guard_execution_audit)`).Scan(&intents, &audits); err != nil {
		t.Fatal(err)
	}
	if intents != 0 || audits != 0 {
		t.Fatalf("expired claim committed partial journal: intents=%d audit=%d", intents, audits)
	}
}
