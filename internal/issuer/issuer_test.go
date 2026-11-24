package issuer

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
)

type fakeAuthority struct {
	result Authorization
	err    error
	calls  int
}

func (f *fakeAuthority) VerifyIssue(_ context.Context, _ action.WorkspaceWrite) (Authorization, error) {
	f.calls++
	return f.result, f.err
}

type fakeLedger struct {
	last  PermitDraft
	calls int
	err   error
}

func (f *fakeLedger) PersistIssuedPermit(_ context.Context, draft PermitDraft) (ScopedPermit, error) {
	f.calls++
	f.last = draft
	if f.err != nil {
		return ScopedPermit{}, f.err
	}
	return ScopedPermit{PermitID: "10000000-0000-4000-8000-000000000010", Draft: draft}, nil
}

func resolvedAction() action.WorkspaceWrite {
	return action.WorkspaceWrite{
		SchemaVersion: "v0.1",
		TenantID: "tenant-a",
		SubjectID: "subject-a",
		AgentID: "agent-a",
		OperationID: "10000000-0000-4000-8000-000000000003",
		CapabilityID: "workspace.write",
		ToolBindingDigest: strings.Repeat("a", 64),
		PolicyVersion: "policy-7",
		Audience: "trusted-workspace-executor",
		WorkspaceID: "workspace-a",
		RelativePath: "docs/output.md",
		ContentDigest: strings.Repeat("b", 64),
	}
}

func validAuthorization(t *testing.T, a action.WorkspaceWrite, now time.Time) Authorization {
	t.Helper()
	hash, err := action.Hash(a)
	if err != nil {
		t.Fatal(err)
	}
	return Authorization{
		RunID: "run-1",
		RuntimeAttemptID: "run-attempt-1",
		TurnID: "turn-1",
		ApprovalRef: "approval-1",
		RiskRevision: "risk-17",
		ActionHash: hash,
		ToolBindingDigest: a.ToolBindingDigest,
		PolicyVersion: a.PolicyVersion,
		Audience: a.Audience,
		ValidUntil: now.Add(2 * time.Minute),
	}
}

func TestTrustedIssuerBindsCurrentAuthorityToExactResolvedAction(t *testing.T) {
	now := time.Date(2026, 11, 24, 5, 40, 0, 0, time.UTC)
	a := resolvedAction()
	auth := &fakeAuthority{result: validAuthorization(t, a, now)}
	ledger := &fakeLedger{}
	svc, err := New(Config{
		IssuerIdentity: "spiffe://platform.example/ns/guard/sa/issuer",
		MaxTTL: 5 * time.Minute,
		Now: func() time.Time { return now },
	}, auth, ledger)
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.Issue(context.Background(), a)
	if err != nil {
		t.Fatalf("valid current authority rejected: %v", err)
	}
	if got.PermitID == "" || ledger.calls != 1 || auth.calls != 1 {
		t.Fatalf("issuer did not persist exactly once: permit=%q ledger=%d authority=%d", got.PermitID, ledger.calls, auth.calls)
	}
	if ledger.last.TenantID != a.TenantID || ledger.last.OperationID != a.OperationID ||
		ledger.last.ActionHash != auth.result.ActionHash ||
		ledger.last.ToolBindingDigest != a.ToolBindingDigest ||
		ledger.last.PolicyVersion != a.PolicyVersion || ledger.last.Audience != a.Audience ||
		ledger.last.RunID != auth.result.RunID || ledger.last.RuntimeAttemptID != auth.result.RuntimeAttemptID ||
		ledger.last.TurnID != auth.result.TurnID || ledger.last.ApprovalRef != auth.result.ApprovalRef ||
		ledger.last.RiskRevision != auth.result.RiskRevision ||
		ledger.last.IssuedBy != "spiffe://platform.example/ns/guard/sa/issuer" {
		t.Fatalf("persisted Permit draft lost authority binding: %+v", ledger.last)
	}
	if !ledger.last.ExpiresAt.Equal(auth.result.ValidUntil) {
		t.Fatalf("expiry=%v want authority bound %v", ledger.last.ExpiresAt, auth.result.ValidUntil)
	}
}

func TestTrustedIssuerFailsClosedOnAuthorityOrActionDrift(t *testing.T) {
	now := time.Date(2026, 11, 24, 5, 40, 0, 0, time.UTC)
	base := resolvedAction()
	for _, tc := range []struct {
		name string
		change func(*Authorization)
		authErr error
	}{
		{"authority unavailable", nil, errors.New("runtime authority unavailable")},
		{"wrong action hash", func(a *Authorization) { a.ActionHash = strings.Repeat("c", 64) }, nil},
		{"binding drift", func(a *Authorization) { a.ToolBindingDigest = strings.Repeat("c", 64) }, nil},
		{"policy drift", func(a *Authorization) { a.PolicyVersion = "policy-8" }, nil},
		{"audience drift", func(a *Authorization) { a.Audience = "other-executor" }, nil},
		{"expired authority", func(a *Authorization) { a.ValidUntil = now }, nil},
		{"ttl over issuer maximum", func(a *Authorization) { a.ValidUntil = now.Add(6 * time.Minute) }, nil},
		{"missing run", func(a *Authorization) { a.RunID = "" }, nil},
		{"missing attempt", func(a *Authorization) { a.RuntimeAttemptID = "" }, nil},
		{"missing turn", func(a *Authorization) { a.TurnID = "" }, nil},
		{"missing approval", func(a *Authorization) { a.ApprovalRef = "" }, nil},
		{"missing risk revision", func(a *Authorization) { a.RiskRevision = "" }, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := base
			authorization := validAuthorization(t, a, now)
			if tc.change != nil {
				tc.change(&authorization)
			}
			auth := &fakeAuthority{result: authorization, err: tc.authErr}
			ledger := &fakeLedger{}
			svc, err := New(Config{
				IssuerIdentity: "spiffe://platform.example/ns/guard/sa/issuer",
				MaxTTL: 5 * time.Minute,
				Now: func() time.Time { return now },
			}, auth, ledger)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.Issue(context.Background(), a); err == nil {
				t.Fatal("unsafe authority state minted a Permit")
			}
			if ledger.calls != 0 {
				t.Fatalf("unsafe authority reached Permit persistence: %d", ledger.calls)
			}
		})
	}
}

func TestTrustedIssuerRejectsIncompleteConstruction(t *testing.T) {
	now := time.Date(2026, 11, 24, 5, 40, 0, 0, time.UTC)
	a := resolvedAction()
	auth := &fakeAuthority{result: validAuthorization(t, a, now)}
	ledger := &fakeLedger{}
	for _, tc := range []struct {
		name string
		cfg Config
		auth Authority
		ledger PermitLedger
	}{
		{"missing issuer identity", Config{MaxTTL: time.Minute, Now: func() time.Time { return now }}, auth, ledger},
		{"missing max ttl", Config{IssuerIdentity: "spiffe://platform.example/ns/guard/sa/issuer", Now: func() time.Time { return now }}, auth, ledger},
		{"missing clock", Config{IssuerIdentity: "spiffe://platform.example/ns/guard/sa/issuer", MaxTTL: time.Minute}, auth, ledger},
		{"missing authority", Config{IssuerIdentity: "spiffe://platform.example/ns/guard/sa/issuer", MaxTTL: time.Minute, Now: func() time.Time { return now }}, nil, ledger},
		{"missing ledger", Config{IssuerIdentity: "spiffe://platform.example/ns/guard/sa/issuer", MaxTTL: time.Minute, Now: func() time.Time { return now }}, auth, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg, tc.auth, tc.ledger); err == nil {
				t.Fatal("incomplete trusted issuer construction accepted")
			}
		})
	}
}
