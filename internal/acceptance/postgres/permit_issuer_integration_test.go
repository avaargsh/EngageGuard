package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
	"github.com/avaargsh/EngageGuard/internal/issuer"
)

type permitTestAuthority struct {
	result issuer.Authorization
	err    error
}

func (a *permitTestAuthority) VerifyIssue(_ context.Context, _ action.ActionRequest) (issuer.Authorization, error) {
	return a.result, a.err
}

func acceptedPermitIssuer(t *testing.T, store *Store) (*issuer.Service, *permitTestAuthority, action.ActionRequest) {
	t.Helper()
	raw := []byte(`{"schema_version":"action-submission.v1","run_id":"run-1","decision_id":"decision-1","plan_id":"plan-1","plan_hash":"` +
		strings.Repeat("f", 64) + `","step_id":"step-1","capability":{"id":"workspace.write","version":"1.0.0"},"resource_ref":"workspace-1","arguments":{"path":"docs/output.md","content_sha256":"` +
		strings.Repeat("c", 64) + `"}}`)
	op, created, err := store.Accept(context.Background(), "tenant-a", "issuer-ledger-source", raw)
	if err != nil || !created {
		t.Fatalf("accept source: created=%t err=%v", created, err)
	}
	resolved := action.ActionRequest{
		SchemaVersion: "action-request.v1",
		TenantID:      "tenant-a",
		SubjectID:     "verified-runtime-subject",
		ActorID:       "verified-actor",
		WorkloadID:    "verified-runtime",
		AgentID:       "verified-agent",
		RunID:         "run-1",
		DecisionID:    "decision-1",
		PlanID:        "plan-1",
		PlanHash:      strings.Repeat("f", 64),
		StepID:        "step-1",
		OperationID:   op.OperationID,
		Capability: action.ActionCapabilityRef{
			ID:             "workspace.write",
			Version:        "1.0.0",
			ContractSHA256: strings.Repeat("a", 64),
		},
		ResourceRef:       "workspace-1",
		Arguments:         []byte(`{"path":"docs/output.md","content_sha256":"` + strings.Repeat("c", 64) + `"}`),
		ToolBindingDigest: strings.Repeat("b", 64),
		PolicyVersion:     "policy-7",
		Audience:          "trusted-workspace-executor",
	}
	if err := resolved.Validate(); err != nil {
		t.Fatalf("validate resolved ActionRequest v1: %v", err)
	}
	hash, err := action.ActionHash(resolved)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	authority := &permitTestAuthority{result: issuer.Authorization{
		TenantID:                 resolved.TenantID,
		RunID:                    resolved.RunID,
		RuntimeAttemptID:         "run-attempt-1",
		TurnID:                   "turn-1",
		ApprovalRef:              "approval-1",
		RiskRevision:             "risk-17",
		DecisionID:               resolved.DecisionID,
		PlanID:                   resolved.PlanID,
		PlanHash:                 resolved.PlanHash,
		StepID:                   resolved.StepID,
		CapabilityID:             resolved.Capability.ID,
		CapabilityVersion:        resolved.Capability.Version,
		CapabilityContractSHA256: resolved.Capability.ContractSHA256,
		ActionHash:               hash,
		ToolBindingDigest:        resolved.ToolBindingDigest,
		PolicyVersion:            resolved.PolicyVersion,
		Audience:                 resolved.Audience,
		ValidUntil:               now.Add(2 * time.Minute),
	}}
	ledger, err := NewPermitIssuerLedger(store)
	if err != nil {
		t.Fatal(err)
	}
	service, err := issuer.New(issuer.Config{
		IssuerIdentity: "spiffe://platform.example/ns/guard/sa/issuer",
		MaxTTL:         5 * time.Minute,
		Now:            func() time.Time { return now },
	}, authority, ledger)
	if err != nil {
		t.Fatal(err)
	}
	return service, authority, resolved
}

func TestPermitIssuerLedgerConcurrentReplayReturnsOneExactPermit(t *testing.T) {
	store, db := integrationStore(t)
	service, _, resolved := acceptedPermitIssuer(t, store)

	const callers = 12
	type result struct {
		permit issuer.ScopedPermit
		err    error
	}
	results := make(chan result, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			permit, err := service.Issue(context.Background(), resolved)
			results <- result{permit: permit, err: err}
		}()
	}
	wg.Wait()
	close(results)

	var permitID string
	var draft issuer.PermitDraft
	for got := range results {
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.permit.Draft == (issuer.PermitDraft{}) || got.permit.PermitID == "" {
			t.Fatalf("unbound Permit replay: %+v", got.permit)
		}
		if permitID == "" {
			permitID, draft = got.permit.PermitID, got.permit.Draft
		} else if got.permit.PermitID != permitID || got.permit.Draft != draft {
			t.Fatalf("same operation returned inconsistent Permit: first=%+v got=%+v", draft, got.permit)
		}
	}
	values := draft.Values()
	var permits, evidence int
	if err := db.QueryRowContext(context.Background(), "SELECT count(*) FROM guard_permits WHERE operation_id=$1::uuid", resolved.OperationID).Scan(&permits); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(context.Background(), "SELECT count(*) FROM guard_permit_authority_evidence WHERE operation_id=$1::uuid", resolved.OperationID).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	if permits != 1 || evidence != 1 {
		t.Fatalf("durable Permit/evidence rows=%d/%d; want 1/1", permits, evidence)
	}
	if values.OperationID != resolved.OperationID || values.TenantID != resolved.TenantID {
		t.Fatalf("Permit evidence lost canonical operation binding: %+v", values)
	}
}

func TestPermitIssuerLedgerRejectsConflictingAuthorityReplay(t *testing.T) {
	store, _ := integrationStore(t)
	service, authority, resolved := acceptedPermitIssuer(t, store)
	first, err := service.Issue(context.Background(), resolved)
	if err != nil {
		t.Fatal(err)
	}
	authority.result.RiskRevision = "risk-18"
	if got, err := service.Issue(context.Background(), resolved); !errors.Is(err, issuer.ErrConflict) || got.PermitID != "" {
		t.Fatalf("conflicting authority replay result=%+v err=%v, want ErrConflict and no Permit", got, err)
	}
	authority.result.RiskRevision = "risk-17"
	replay, err := service.Issue(context.Background(), resolved)
	if err != nil || replay.PermitID != first.PermitID || replay.Draft != first.Draft {
		t.Fatalf("exact replay did not recover original Permit: %+v err=%v", replay, err)
	}
}

func TestPermitIssuerAuthorityEvidenceIsImmutable(t *testing.T) {
	store, db := integrationStore(t)
	service, _, resolved := acceptedPermitIssuer(t, store)
	permit, err := service.Issue(context.Background(), resolved)
	if err != nil {
		t.Fatal(err)
	}
	values := permit.Draft.Values()
	if _, err := db.ExecContext(context.Background(), `
		UPDATE guard_permit_authority_evidence
		SET risk_revision='forged-risk'
		WHERE tenant_id=$1 AND permit_id=$2::uuid
	`, values.TenantID, permit.PermitID); err == nil {
		t.Fatal("authority evidence UPDATE bypassed immutability")
	}
	var risk string
	if err := db.QueryRowContext(context.Background(), `
		SELECT risk_revision FROM guard_permit_authority_evidence
		WHERE tenant_id=$1 AND permit_id=$2::uuid
	`, values.TenantID, permit.PermitID).Scan(&risk); err != nil || risk != values.RiskRevision {
		t.Fatalf("authority evidence drifted: risk=%q err=%v", risk, err)
	}
}

// A Permit's maximum lifetime must be bounded by PostgreSQL's clock, not
// only by the issuer process clock. Otherwise host clock skew can extend a
// short-lived Permit or persist one that is already expired in the DB.
func TestPermitIssuerLedgerRejectsIssuerClockSkewAgainstPostgres(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset time.Duration
	}{
		{name: "issuer clock ahead", offset: 10 * time.Minute},
		{name: "issuer clock behind", offset: -10 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, db := integrationStore(t)
			_, authority, resolved := acceptedPermitIssuer(t, store)
			ctx := context.Background()
			var dbNow time.Time
			if err := db.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&dbNow); err != nil {
				t.Fatal(err)
			}
			issuerNow := dbNow.Add(tc.offset).UTC().Truncate(time.Microsecond)
			authority.result.ValidUntil = issuerNow.Add(2 * time.Minute)
			ledger, err := NewPermitIssuerLedger(store)
			if err != nil {
				t.Fatal(err)
			}
			service, err := issuer.New(issuer.Config{
				IssuerIdentity: "spiffe://platform.example/ns/guard/sa/issuer",
				MaxTTL:         5 * time.Minute,
				Now:            func() time.Time { return issuerNow },
			}, authority, ledger)
			if err != nil {
				t.Fatal(err)
			}
			got, err := service.Issue(ctx, resolved)
			if !errors.Is(err, issuer.ErrDenied) || got.PermitID != "" {
				t.Fatalf("issuer clock skew created or returned a Permit: permit=%+v err=%v", got, err)
			}
			var permits, evidence int
			if err := db.QueryRowContext(ctx,
				"SELECT count(*) FROM guard_permits WHERE operation_id=$1::uuid", resolved.OperationID).Scan(&permits); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRowContext(ctx,
				"SELECT count(*) FROM guard_permit_authority_evidence WHERE operation_id=$1::uuid", resolved.OperationID).Scan(&evidence); err != nil {
				t.Fatal(err)
			}
			if permits != 0 || evidence != 0 {
				t.Fatalf("clock-skew denial persisted ledger rows: permits=%d evidence=%d", permits, evidence)
			}
		})
	}
}


func TestPermitIssuerLedgerReplaysExistingPermitAfterIssuerClockAdvances(t *testing.T) {
	store, db := integrationStore(t)
	firstService, authority, resolved := acceptedPermitIssuer(t, store)
	first, err := firstService.Issue(context.Background(), resolved)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a retry after an issuer restart: the authority evidence and
	// operation are unchanged, but the new process has a later local clock.
	retryNow := first.Draft.Values().IssuedAt.Add(time.Second)
	ledger, err := NewPermitIssuerLedger(store)
	if err != nil {
		t.Fatal(err)
	}
	retryService, err := issuer.New(issuer.Config{
		IssuerIdentity: "spiffe://platform.example/ns/guard/sa/issuer",
		MaxTTL:         5 * time.Minute,
		Now:            func() time.Time { return retryNow },
	}, authority, ledger)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := retryService.Issue(context.Background(), resolved)
	if err != nil {
		t.Fatalf("valid replay after issuer clock advanced was rejected: %v", err)
	}
	if replayed.PermitID != first.PermitID || replayed.Draft != first.Draft {
		t.Fatalf("retry did not return the original persisted Permit: first=%+v replayed=%+v", first, replayed)
	}

	var permits, evidence int
	if err := db.QueryRowContext(context.Background(),
		"SELECT count(*) FROM guard_permits WHERE operation_id=$1::uuid", resolved.OperationID).Scan(&permits); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(context.Background(),
		"SELECT count(*) FROM guard_permit_authority_evidence WHERE operation_id=$1::uuid", resolved.OperationID).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	if permits != 1 || evidence != 1 {
		t.Fatalf("replay changed durable ledger cardinality: permits=%d evidence=%d, want 1/1", permits, evidence)
	}
}
