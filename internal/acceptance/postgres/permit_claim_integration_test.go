package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// This fixture stands in ONLY for future trusted PEP/approval issuance.
// There is no public API to issue an action Permit in this slice.
func seededWorkspacePermit(t *testing.T) (*Store, action.WorkspaceWrite, string) {
	t.Helper()
	store, db := integrationStore(t)
	op, created, err := store.Accept(context.Background(), "tenant-a", "key-1", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("accept: %v, created=%v", err, created)
	}
	resolved := action.WorkspaceWrite{
		SchemaVersion:     "v0.1",
		TenantID:          "tenant-a",
		SubjectID:         "verified-runtime-subject",
		AgentID:           "verified-agent",
		OperationID:       op.OperationID,
		CapabilityID:      "workspace.write",
		ToolBindingDigest: strings.Repeat("a", 64),
		PolicyVersion:     "signed-policy-7",
		Audience:          "trusted-workspace-executor",
		WorkspaceID:       "workspace-1",
		RelativePath:      "docs/output.md",
		ContentDigest:     strings.Repeat("b", 64),
	}
	hash, err := action.Hash(resolved)
	if err != nil {
		t.Fatal(err)
	}
	var permitID string
	err = db.QueryRow(`INSERT INTO guard_permits
			(tenant_id, operation_id, action_hash, binding_digest, audience,
			 policy_version, issued_by, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			RETURNING permit_id::text`,
		resolved.TenantID, resolved.OperationID, hash,
		resolved.ToolBindingDigest, resolved.Audience, resolved.PolicyVersion,
		"test-only-trusted-issuer", time.Now().UTC().Add(time.Hour),
	).Scan(&permitID)
	if err != nil {
		t.Fatal(err)
	}
	return store, resolved, permitID
}

func TestClaimPermitAndIntentAreAtomicAndOneTimeUnderConcurrency(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	const clients = 16
	type result struct {
		intent DispatchIntent
		err    error
	}
	results := make(chan result, clients)
	var wg sync.WaitGroup
	for range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			intent, err := store.ClaimAuthorizedIntent(context.Background(), permitID, resolved)
			results <- result{intent, err}
		}()
	}
	wg.Wait()
	close(results)
	successes, alreadyClaimed := 0, 0
	for got := range results {
		switch {
		case got.err == nil:
			successes++
			if got.intent.PermitID != permitID || got.intent.OperationID != resolved.OperationID ||
				got.intent.AttemptID == "" || got.intent.State != "DISPATCHING" {
				t.Fatalf("unbound intent: %+v", got.intent)
			}
		case errors.Is(got.err, ErrPermitAlreadyClaimed):
			alreadyClaimed++
		default:
			t.Fatalf("unexpected claim error: %v", got.err)
		}
	}
	if successes != 1 || alreadyClaimed != clients-1 {
		t.Fatalf("claimed=%d already-claimed=%d; want 1 and %d", successes, alreadyClaimed, clients-1)
	}
	if _, err := New(store.db).ClaimAuthorizedIntent(context.Background(), permitID, resolved); !errors.Is(err, ErrPermitAlreadyClaimed) {
		t.Fatalf("reconstructed store replay = %v, want explicit already-claimed fence", err)
	}
	var claimed, intents, audits int
	err := store.db.QueryRow(`SELECT count(*) FROM guard_permits
		WHERE permit_id=$1::uuid AND state='CLAIMED'`, permitID).Scan(&claimed)
	if err != nil {
		t.Fatal(err)
	}
	err = store.db.QueryRow(`SELECT count(*) FROM guard_operation_intents WHERE permit_id=$1::uuid`, permitID).Scan(&intents)
	if err != nil {
		t.Fatal(err)
	}
	err = store.db.QueryRow(`SELECT count(*) FROM guard_execution_audit WHERE permit_id=$1::uuid AND event_type='guard.operation.dispatching.v1'`, permitID).Scan(&audits)
	if err != nil {
		t.Fatal(err)
	}
	if claimed != 1 || intents != 1 || audits != 1 {
		t.Fatalf("atomic claim/intents/audit = %d/%d/%d; want 1/1/1", claimed, intents, audits)
	}
}

func TestClaimRejectsActionDriftAndWrongTenantBeforeAnyWrite(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*action.WorkspaceWrite)
	}{
		{"modified content", func(a *action.WorkspaceWrite) { a.ContentDigest = strings.Repeat("c", 64) }},
		{"modified binding", func(a *action.WorkspaceWrite) { a.ToolBindingDigest = strings.Repeat("c", 64) }},
		{"modified target path", func(a *action.WorkspaceWrite) { a.RelativePath = "docs/other.md" }},
		{"wrong audience", func(a *action.WorkspaceWrite) { a.Audience = "unknown-executor" }},
		{"cross tenant", func(a *action.WorkspaceWrite) { a.TenantID = "tenant-b" }},
		{"wrong operation", func(a *action.WorkspaceWrite) { a.OperationID = "6a9ff43e-366e-451b-8c7f-37f5870b0ef3" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, resolved, permitID := seededWorkspacePermit(t)
			tc.change(&resolved)
			if _, err := store.ClaimAuthorizedIntent(context.Background(), permitID, resolved); err == nil {
				t.Fatal("changed action was able to claim original permit")
			}
			var state string
			if err := store.db.QueryRow("SELECT state FROM guard_permits WHERE permit_id=$1::uuid", permitID).Scan(&state); err != nil {
				t.Fatal(err)
			}
			if state != "ISSUED" {
				t.Fatalf("incorrectly claimed permit: %s", state)
			}
			var count int
			if err := store.db.QueryRow("SELECT count(*) FROM guard_operation_intents").Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatalf("invalid claim created %d intents", count)
			}
		})
	}
}

func TestClaimRejectsExpiredOrRevokedPermit(t *testing.T) {
	for _, tc := range []struct{ name, update string }{
		{"expired", "UPDATE guard_permits SET expires_at=now()-interval '1 second' WHERE permit_id=$1::uuid"},
		{"revoked", "UPDATE guard_permits SET revoked_at=now() WHERE permit_id=$1::uuid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, resolved, permitID := seededWorkspacePermit(t)
			if _, err := store.db.Exec(tc.update, permitID); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ClaimAuthorizedIntent(context.Background(), permitID, resolved); !errors.Is(err, ErrPermitUnavailable) {
				t.Fatalf("expired or revoked permit claim error=%v, want ErrPermitUnavailable", err)
			}
		})
	}
}

func TestClaimAuditFailureRollsBackPermitAndIntent(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	_, err := store.db.Exec(`CREATE FUNCTION reject_dispatch_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected audit failure'; END; $$`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.db.Exec(`CREATE TRIGGER reject_dispatch_audit BEFORE INSERT ON guard_execution_audit FOR EACH ROW EXECUTE FUNCTION reject_dispatch_audit()`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimAuthorizedIntent(context.Background(), permitID, resolved); err == nil {
		t.Fatal("claim committed despite audit failure")
	}
	var state string
	if err := store.db.QueryRow("SELECT state FROM guard_permits WHERE permit_id=$1::uuid", permitID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "ISSUED" {
		t.Fatalf("partially committed claim: %s", state)
	}
	for _, table := range []string{"guard_operation_intents", "guard_execution_audit"} {
		var count int
		if err := store.db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("partial write left %d rows in %s", count, table)
		}
	}
}
