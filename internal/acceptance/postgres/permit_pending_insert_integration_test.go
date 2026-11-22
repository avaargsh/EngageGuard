package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
)

func pendingPermitFixture(t *testing.T) (*Store, pendingPermitWrite) {
	t.Helper()
	store, _ := integrationStore(t)
	original, err := action.ParseActionSubmission(sampleSubmission())
	if err != nil {
		t.Fatal(err)
	}
	accepted, created, err := store.Accept(context.Background(), "tenant-a", "pending-issue-key", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("accept immutable original: created=%t err=%v", created, err)
	}
	return store, pendingPermitWrite{
		Submission: original,
		Resolved: action.WorkspaceWrite{
			SchemaVersion: "v0.1", TenantID: "tenant-a", SubjectID: "source-verified-subject",
			AgentID: "source-verified-agent", OperationID: accepted.OperationID,
			CapabilityID: "workspace.write", ToolBindingDigest: strings.Repeat("a", 64),
			PolicyVersion: "source-verified-policy", Audience: "workspace-executor",
			WorkspaceID: "workspace-1", RelativePath: "docs/a.txt",
			ContentDigest: strings.Repeat("b", 64),
		},
		Issuer:    "test-only-issuer",
		ExpiresAt: time.Now().UTC().Add(30 * time.Second).Truncate(time.Microsecond),
	}
}

func TestPendingPermitInsertAcceptsOnlyExactDurableOperationAndRejectsReplay(t *testing.T) {
	store, req := pendingPermitFixture(t)
	ctx := context.Background()
	id, err := store.insertPendingPermit(ctx, req)
	if err != nil || !validDispatchUUID(id) {
		t.Fatalf("single pending Permit INSERT failed: id=%q err=%v", id, err)
	}
	var state, issuedBy, actionHash, digest string
	var issuedAt, expiresAt time.Time
	err = store.db.QueryRowContext(ctx, `
		SELECT state, issued_by, action_hash, binding_digest, issued_at, expires_at
		FROM guard_permits WHERE tenant_id=$1 AND operation_id=$2::uuid AND permit_id=$3::uuid
	`, req.Resolved.TenantID, req.Resolved.OperationID, id).
		Scan(&state, &issuedBy, &actionHash, &digest, &issuedAt, &expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := action.Hash(req.Resolved)
	if err != nil {
		t.Fatal(err)
	}
	if state != "ISSUED" || issuedBy != req.Issuer || actionHash != hash ||
		digest != req.Resolved.ToolBindingDigest || !expiresAt.Equal(req.ExpiresAt) ||
		!issuedAt.Before(expiresAt) {
		t.Fatalf("pending Permit fields are unbound: state=%q issuer=%q actionHash=%q binding=%q expiry=%v",
			state, issuedBy, actionHash, digest, expiresAt)
	}
	for _, table := range []string{"guard_operation_intents", "guard_execution_audit"} {
		var count int
		if err := store.db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("pending Permit unexpectedly dispatched: table=%s count=%d err=%v", table, count, err)
		}
	}
	if _, err := store.insertPendingPermit(ctx, req); !errors.Is(err, ErrPermitAlreadyIssued) {
		t.Fatalf("same-operation replay minted an additional Permit: %v", err)
	}
	if _, err := New(store.db).insertPendingPermit(ctx, req); !errors.Is(err, ErrPermitAlreadyIssued) {
		t.Fatalf("restarted store minted a duplicate Permit: %v", err)
	}
	var count int
	if err := store.db.QueryRowContext(ctx,
		"SELECT count(*) FROM guard_permits WHERE tenant_id=$1 AND operation_id=$2::uuid",
		req.Resolved.TenantID, req.Resolved.OperationID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("replay produced %d permits, err=%v", count, err)
	}
}

func TestPendingPermitInsertConcurrentSameOperationHasOneWinner(t *testing.T) {
	store, req := pendingPermitFixture(t)
	const callers = 12
	var wg sync.WaitGroup
	results := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.insertPendingPermit(context.Background(), req)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	var issued, duplicates int
	for err := range results {
		switch {
		case err == nil:
			issued++
		case errors.Is(err, ErrPermitAlreadyIssued):
			duplicates++
		default:
			t.Fatalf("unexpected concurrent issuer error: %v", err)
		}
	}
	if issued != 1 || duplicates != callers-1 {
		t.Fatalf("issued=%d duplicate=%d want 1/%d", issued, duplicates, callers-1)
	}
}

func TestPendingPermitInsertFailsClosedOnUntrustedSourceAndExpiredProof(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*pendingPermitWrite)
	}{
		{"changed original Run", func(r *pendingPermitWrite) { r.Submission.RunID = "another-run" }},
		{"changed original Decision", func(r *pendingPermitWrite) { r.Submission.DecisionID = "another-decision" }},
		{"changed original arguments", func(r *pendingPermitWrite) {
			r.Submission.Arguments = json.RawMessage(`{"path":"docs/a.txt","content":"changed"}`)
		}},
		{"wrong authenticated tenant", func(r *pendingPermitWrite) { r.Resolved.TenantID = "tenant-other" }},
		{"wrong original operation", func(r *pendingPermitWrite) { r.Resolved.OperationID = "33333333-3333-4333-8333-333333333333" }},
		{"wrong original workspace", func(r *pendingPermitWrite) { r.Submission.ResourceRef = "workspace-2" }},
		{"expired DB permit", func(r *pendingPermitWrite) { r.ExpiresAt = time.Now().UTC().Add(-time.Second) }},
		{"excessive lifespan", func(r *pendingPermitWrite) { r.ExpiresAt = time.Now().UTC().Add(2 * time.Minute) }},
		{"untrusted issuer identity", func(r *pendingPermitWrite) { r.Issuer = "test-only-issuer;DROP TABLE guard_permits" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, req := pendingPermitFixture(t)
			tc.mutate(&req)
			if _, err := store.insertPendingPermit(context.Background(), req); err == nil {
				t.Fatalf("invalid issuance request %s minted a Permit", tc.name)
			}
			var count int
			if err := store.db.QueryRowContext(context.Background(),
				"SELECT count(*) FROM guard_permits").Scan(&count); err != nil || count != 0 {
				t.Fatalf("denied insertion left Permit rows=%d err=%v", count, err)
			}
		})
	}
}

func TestPendingPermitInsertRollsBackOnDatabaseFailure(t *testing.T) {
	store, req := pendingPermitFixture(t)
	_, err := store.db.ExecContext(context.Background(),
		`CREATE FUNCTION deny_pending_insert() RETURNS trigger LANGUAGE plpgsql AS $guard$
		BEGIN RAISE EXCEPTION 'injected pending Permit write failure'; END;
		$guard$;`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(),
		"CREATE TRIGGER deny_pending_insert BEFORE INSERT ON guard_permits FOR EACH ROW EXECUTE FUNCTION deny_pending_insert()"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.insertPendingPermit(context.Background(), req); err == nil {
		t.Fatal("injected Permit insert failure returned success")
	}
	var count int
	if err := store.db.QueryRowContext(context.Background(),
		"SELECT count(*) FROM guard_permits").Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed Permit insert left %d rows err=%v", count, err)
	}
	if _, err := store.db.ExecContext(context.Background(), "DROP TRIGGER deny_pending_insert ON guard_permits"); err != nil {
		t.Fatal(err)
	}
	// Failed statement is not a spendable idempotency receipt. A later
	// independently authorized attempt can still create exactly one row.
	if _, err := New(store.db).insertPendingPermit(context.Background(), req); err != nil {
		t.Fatalf("failure recovery cannot issue new pending Permit: %v", err)
	}
}
