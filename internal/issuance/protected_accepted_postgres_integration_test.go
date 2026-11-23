package issuance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/avaargsh/EngageGuard/internal/acceptance/postgres"
	"github.com/avaargsh/EngageGuard/internal/approval"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func signFixtureForResolvedOperation(t *testing.T, f *preflightFixture) {
	t.Helper()
	binding := approval.ExecutionBinding{
		RunID:          f.decision.step.RunID,
		AttemptID:      f.decision.step.AttemptID,
		TurnID:         f.decision.step.TurnID,
		AgentReleaseID: f.decision.step.AgentReleaseID,
		DecisionID:     f.decision.step.DecisionID,
		PlanHash:       f.decision.step.PlanHash,
		StepID:         f.decision.step.StepID,
	}
	scope, err := approval.ScopeForResolvedWorkspace(f.actions.resolved, binding)
	if err != nil {
		t.Fatal(err)
	}
	evidence := approval.Evidence{
		SchemaVersion: "engageguard.approval-evidence.v1",
		ApprovalID:    "approval-pg-fixture",
		Decision:      "APPROVED",
		Scope:         scope,
		IssuedAt:      f.now.Add(-time.Minute),
		ExpiresAt:     f.now.Add(time.Minute),
	}
	payload, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(f.pub)
	signature := ed25519.Sign(f.privateKey, append([]byte("engageguard/approval-proof/v1\x00"), payload...))
	f.signed, err = json.Marshal(approval.SignedEvidence{
		KeyID:     hex.EncodeToString(fingerprint[:]),
		Payload:   payload,
		Signature: signature,
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Real Guard PostgreSQL source + simulated, source-separated remote authorities.
// No trusted issuer, provider execution, approval service or Permit writer.
func TestProtectedPreflightBindsRealPostgresAcceptedOperation(t *testing.T) {
	dsn := os.Getenv("GUARD_PG_DSN")
	if dsn == "" {
		t.Skip("GUARD_PG_DSN required for real PostgreSQL acceptance integration")
	}
	ctx := context.Background()
	adminConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin := stdlib.OpenDB(*adminConfig)
	if err := admin.PingContext(ctx); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := fmt.Sprintf("guard_issue_source_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*config)
	db.SetMaxOpenConns(8)
	t.Cleanup(func() {
		db.Close()
		_, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
	})
	if err := postgres.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	// The accepted source is tied to the independently provisioned test schema,
	// not to a borrowed database session's search_path.
	store, err := postgres.NewWithTrustedSchema(db, schema)
	if err != nil {
		t.Fatal(err)
	}
	f := makePreflightFixture(t)
	raw := append([]byte(nil), f.accepted.snapshot.Raw...)
	op, created, err := store.Accept(ctx, f.principal.TenantID, "accepted-original", raw)
	if err != nil || !created {
		t.Fatalf("accept immutable original submission: created=%v err=%v", created, err)
	}
	f.actions.resolved.OperationID = op.OperationID
	signFixtureForResolvedOperation(t, f)
	g := f.gate(t)
	g.deps.Accepted = store
	if err := g.Verify(ctx, f.principal, f.submission, f.signed); err != nil {
		t.Fatalf("real accepted source with correct signed scope failed: %v", err)
	}

	// A second legitimately accepted but different Run submission may not
	// borrow the original Decision/Approval to acquire an execution right.
	otherRaw := bytes.Replace(raw, []byte(f.submission.RunID),
		[]byte("33333333-3333-4333-8333-333333333333"), 1)
	if bytes.Equal(raw, otherRaw) {
		t.Fatal("invalid test fixture: accepted Run did not change")
	}
	other, created, err := store.Accept(ctx, f.principal.TenantID, "accepted-other-run", otherRaw)
	if err != nil || !created {
		t.Fatalf("accept distinct immutable Run: created=%v err=%v", created, err)
	}
	f.actions.resolved.OperationID = other.OperationID
	signFixtureForResolvedOperation(t, f)
	if err := g.Verify(ctx, f.principal, f.submission, f.signed); !errors.Is(err, ErrDenied) {
		t.Fatalf("different durable accepted Run reused another Run's authorization: %v", err)
	}

	// Same RunID is not a blanket approval. Every immutable Plan, Step,
	// Decision, target and argument change must map to its own signed
	// and source-matched operation; borrowing another submission fails.
	for i, tc := range []struct {
		name   string
		before string
		after  string
	}{
		{"same run changed decision", `"decision_id":"decision-1"`, `"decision_id":"decision-2"`},
		{"same run changed plan", `"plan_id":"plan-1"`, `"plan_id":"plan-2"`},
		{"same run changed step", `"step_id":"step-1"`, `"step_id":"step-2"`},
		{"same run changed workspace", `"resource_ref":"workspace-1"`, `"resource_ref":"workspace-2"`},
		{"same run changed arguments", `"path":"docs/output.md"`, `"path":"docs/other.md"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modified := bytes.Replace(raw, []byte(tc.before), []byte(tc.after), 1)
			if bytes.Equal(modified, raw) {
				t.Fatalf("fixture failed to modify accepted source for %s", tc.name)
			}
			other, created, err := store.Accept(ctx, f.principal.TenantID,
				fmt.Sprintf("accepted-drift-%d", i), modified)
			if err != nil || !created {
				t.Fatalf("accept separate immutable operation: created=%v err=%v", created, err)
			}
			f.actions.resolved.OperationID = other.OperationID
			signFixtureForResolvedOperation(t, f)
			if err := g.Verify(ctx, f.principal, f.submission, f.signed); !errors.Is(err, ErrDenied) {
				t.Fatalf("accepted %s borrowed a different immutable submission: %v", tc.name, err)
			}
		})
	}

	// Preflight is still necessary-only; no Permit/dispatch effect is minted.
	var permitCount int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM guard_permits").Scan(&permitCount); err != nil || permitCount != 0 {
		t.Fatalf("preflight created Permit: count=%d err=%v", permitCount, err)
	}
}
