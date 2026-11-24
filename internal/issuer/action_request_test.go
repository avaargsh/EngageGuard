package issuer

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
)

type actionRequestAuthority struct {
	result Authorization
	err    error
}

func (a *actionRequestAuthority) VerifyIssue(_ context.Context, _ action.ActionRequest) (Authorization, error) {
	return a.result, a.err
}

type actionRequestLedger struct {
	last  PermitDraft
	calls int
	err   error
}

func (l *actionRequestLedger) PersistIssuedPermit(_ context.Context, draft PermitDraft) (ScopedPermit, error) {
	l.calls++
	l.last = draft
	if l.err != nil {
		return ScopedPermit{}, l.err
	}
	return ScopedPermit{PermitID: "10000000-0000-4000-8000-000000000010", Draft: draft}, nil
}

func resolvedActionRequest() action.ActionRequest {
	return action.ActionRequest{
		SchemaVersion: "action-request.v1",
		TenantID:      "tenant-a",
		SubjectID:     "subject-a",
		ActorID:       "actor-a",
		WorkloadID:    "runtime-a",
		AgentID:       "agent-a",
		RunID:         "run-1",
		DecisionID:    "decision-1",
		PlanID:        "plan-1",
		PlanHash:      strings.Repeat("f", 64),
		StepID:        "step-1",
		OperationID:   "10000000-0000-4000-8000-000000000003",
		Capability: action.ActionCapabilityRef{
			ID:             "workspace.write",
			Version:        "1.0.0",
			ContractSHA256: strings.Repeat("a", 64),
		},
		ResourceRef:       "workspace-a",
		Arguments:         []byte(`{"path":"docs/output.md","content_sha256":"` + strings.Repeat("b", 64) + `"}`),
		ToolBindingDigest: strings.Repeat("c", 64),
		PolicyVersion:     "policy-7",
		Audience:          "trusted-workspace-executor",
	}
}

func authorizationForAction(t *testing.T, resolved action.ActionRequest, now time.Time) Authorization {
	t.Helper()
	hash, err := action.ActionHash(resolved)
	if err != nil {
		t.Fatal(err)
	}
	return Authorization{
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
	}
}

func TestTrustedIssuerBindsActionRequestV1RunAndCapabilityVersion(t *testing.T) {
	now := time.Date(2026, 11, 24, 7, 0, 0, 0, time.UTC)
	resolved := resolvedActionRequest()
	authority := &actionRequestAuthority{result: authorizationForAction(t, resolved, now)}
	ledger := &actionRequestLedger{}
	service, err := New(Config{
		IssuerIdentity: "spiffe://platform.example/ns/guard/sa/issuer",
		MaxTTL:         5 * time.Minute,
		Now:            func() time.Time { return now },
	}, authority, ledger)
	if err != nil {
		t.Fatal(err)
	}

	permit, err := service.Issue(context.Background(), resolved)
	if err != nil {
		t.Fatalf("valid ActionRequest v1 denied: %v", err)
	}
	if permit.PermitID == "" || ledger.calls != 1 {
		t.Fatalf("valid ActionRequest was not persisted exactly once: permit=%q calls=%d", permit.PermitID, ledger.calls)
	}
	values := ledger.last.Values()
	if values.TenantID != resolved.TenantID ||
		values.OperationID != resolved.OperationID ||
		values.RunID != resolved.RunID ||
		values.DecisionID != resolved.DecisionID ||
		values.PlanID != resolved.PlanID ||
		values.PlanHash != resolved.PlanHash ||
		values.StepID != resolved.StepID ||
		values.CapabilityID != resolved.Capability.ID ||
		values.CapabilityVersion != resolved.Capability.Version ||
		values.CapabilityContractSHA256 != resolved.Capability.ContractSHA256 ||
		values.ResourceRef != resolved.ResourceRef {
		t.Fatalf("Permit draft lost resolved ActionRequest v1 bindings: %+v", values)
	}
}

func TestTrustedIssuerRejectsRunAndCapabilityVersionDrift(t *testing.T) {
	now := time.Date(2026, 11, 24, 7, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		change func(*Authorization)
	}{
		{"wrong tenant", func(a *Authorization) { a.TenantID = "tenant-b" }},
		{"wrong run", func(a *Authorization) { a.RunID = "run-other" }},
		{"wrong decision", func(a *Authorization) { a.DecisionID = "decision-other" }},
		{"wrong plan", func(a *Authorization) { a.PlanID = "plan-other" }},
		{"wrong plan hash", func(a *Authorization) { a.PlanHash = strings.Repeat("9", 64) }},
		{"wrong step", func(a *Authorization) { a.StepID = "step-other" }},
		{"wrong capability id", func(a *Authorization) { a.CapabilityID = "workspace.delete" }},
		{"wrong capability version", func(a *Authorization) { a.CapabilityVersion = "2.0.0" }},
		{"wrong capability contract", func(a *Authorization) { a.CapabilityContractSHA256 = strings.Repeat("d", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolved := resolvedActionRequest()
			authorization := authorizationForAction(t, resolved, now)
			tc.change(&authorization)
			authority := &actionRequestAuthority{result: authorization}
			ledger := &actionRequestLedger{}
			service, err := New(Config{
				IssuerIdentity: "spiffe://platform.example/ns/guard/sa/issuer",
				MaxTTL:         5 * time.Minute,
				Now:            func() time.Time { return now },
			}, authority, ledger)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Issue(context.Background(), resolved); !errors.Is(err, ErrDenied) {
				t.Fatalf("authority drift error=%v, want ErrDenied", err)
			}
			if ledger.calls != 0 {
				t.Fatalf("authority drift reached ledger: %d", ledger.calls)
			}
		})
	}
}
