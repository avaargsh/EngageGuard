package issuer

import (
	"context"
	"errors"
	"reflect"
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

func (f *fakeAuthority) VerifyIssue(_ context.Context, _ action.ActionRequest) (Authorization, error) {
	f.calls++
	return f.result, f.err
}

type fakeLedger struct {
	last   PermitDraft
	maxTTL time.Duration
	calls  int
	err    error
}

func (f *fakeLedger) PersistIssuedPermit(_ context.Context, draft PermitDraft, maxTTL time.Duration) (PersistedPermit, error) {
	f.calls++
	f.last = draft
	f.maxTTL = maxTTL
	if f.err != nil {
		return PersistedPermit{}, f.err
	}
	return PersistedPermit{PermitID: "10000000-0000-4000-8000-000000000010", Values: draft.Values()}, nil
}

func resolvedAction() action.ActionRequest {
	return resolvedActionRequest()
}

func validAuthorization(t *testing.T, a action.ActionRequest, now time.Time) Authorization {
	return authorizationForAction(t, a, now)
}

func TestTrustedIssuerBindsCurrentAuthorityToExactResolvedAction(t *testing.T) {
	now := time.Date(2026, 11, 24, 5, 40, 0, 0, time.UTC)
	a := resolvedAction()
	auth := &fakeAuthority{result: validAuthorization(t, a, now)}
	ledger := &fakeLedger{}
	svc, err := New(Config{
		IssuerIdentity: "spiffe://platform.example/ns/guard/sa/issuer",
		MaxTTL:         5 * time.Minute,
		Now:            func() time.Time { return now },
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
	if ledger.maxTTL != 5*time.Minute {
		t.Fatalf("issuer did not pass configured maximum TTL to ledger: %s", ledger.maxTTL)
	}
	last := ledger.last.Values()
	if last.TenantID != a.TenantID || last.OperationID != a.OperationID ||
		last.ActionHash != auth.result.ActionHash ||
		last.ToolBindingDigest != a.ToolBindingDigest ||
		last.PolicyVersion != a.PolicyVersion || last.Audience != a.Audience ||
		last.RunID != auth.result.RunID || last.RuntimeAttemptID != auth.result.RuntimeAttemptID ||
		last.TurnID != auth.result.TurnID || last.ApprovalRef != auth.result.ApprovalRef ||
		last.RiskRevision != auth.result.RiskRevision ||
		last.IssuedBy != "spiffe://platform.example/ns/guard/sa/issuer" {
		t.Fatalf("persisted Permit draft lost authority binding: %+v", last)
	}
	if !last.ExpiresAt.Equal(auth.result.ValidUntil) {
		t.Fatalf("expiry=%v want authority bound %v", last.ExpiresAt, auth.result.ValidUntil)
	}
	last.RiskRevision = "caller-mutated-copy"
	if got := ledger.last.Values().RiskRevision; got != auth.result.RiskRevision {
		t.Fatalf("mutating returned PermitDraftValues changed the opaque draft: %q", got)
	}
}

func TestTrustedIssuerFailsClosedOnAuthorityOrActionDrift(t *testing.T) {
	now := time.Date(2026, 11, 24, 5, 40, 0, 0, time.UTC)
	base := resolvedAction()
	for _, tc := range []struct {
		name    string
		change  func(*Authorization)
		authErr error
	}{
		{"authority unavailable", nil, errors.New("runtime authority unavailable")},
		{"wrong action hash", func(a *Authorization) { a.ActionHash = strings.Repeat("c", 64) }, nil},
		{"binding drift", func(a *Authorization) { a.ToolBindingDigest = strings.Repeat("d", 64) }, nil},
		{"policy drift", func(a *Authorization) { a.PolicyVersion = "policy-8" }, nil},
		{"audience drift", func(a *Authorization) { a.Audience = "other-executor" }, nil},
		{"expired authority", func(a *Authorization) { a.ValidUntil = now }, nil},
		{"ttl over issuer maximum", func(a *Authorization) { a.ValidUntil = now.Add(6 * time.Minute) }, nil},
		{"missing run", func(a *Authorization) { a.RunID = "" }, nil},
		{"missing attempt", func(a *Authorization) { a.RuntimeAttemptID = "" }, nil},
		{"missing turn", func(a *Authorization) { a.TurnID = "" }, nil},
		{"missing approval", func(a *Authorization) { a.ApprovalRef = "" }, nil},
		{"missing risk revision", func(a *Authorization) { a.RiskRevision = "" }, nil},
		{"run contains bidi control", func(a *Authorization) { a.RunID = "run-\u202e1" }, nil},
		{"attempt contains zero-width format", func(a *Authorization) { a.RuntimeAttemptID = "attempt-\u200b1" }, nil},
		{"approval contains C1 control", func(a *Authorization) { a.ApprovalRef = "approval-\u0085-1" }, nil},
		{"risk revision contains non-ASCII", func(a *Authorization) { a.RiskRevision = "risk-\u00e9" }, nil},
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
				MaxTTL:         5 * time.Minute,
				Now:            func() time.Time { return now },
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
		name   string
		cfg    Config
		auth   Authority
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

// PermitDraft crosses the issuer/ledger package boundary, but only the
// issuer service may construct trusted issuance evidence. Exported fields
// would let arbitrary in-process callers fabricate approval and risk claims.
func TestPermitDraftIsOpaqueToCallers(t *testing.T) {
	typ := reflect.TypeOf(PermitDraft{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath == "" {
			t.Fatalf("PermitDraft exposes writable field %q outside issuer package", field.Name)
		}
	}
}
func TestTrustedIssuerPreservesDenialAndConflictClassification(t *testing.T) {
	now := time.Date(2026, 11, 24, 5, 40, 0, 0, time.UTC)
	a := resolvedAction()
	valid := validAuthorization(t, a, now)

	t.Run("authority denial is not availability failure", func(t *testing.T) {
		auth := &fakeAuthority{result: valid, err: ErrDenied}
		ledger := &fakeLedger{}
		svc, err := New(Config{
			IssuerIdentity: "spiffe://platform.example/ns/guard/sa/issuer",
			MaxTTL:         5 * time.Minute,
			Now:            func() time.Time { return now },
		}, auth, ledger)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Issue(context.Background(), a); !errors.Is(err, ErrDenied) || errors.Is(err, ErrUnavailable) {
			t.Fatalf("authority denial classification=%v; want ErrDenied without ErrUnavailable", err)
		}
		if ledger.calls != 0 {
			t.Fatalf("denied authority reached ledger: %d", ledger.calls)
		}
	})

	t.Run("ledger conflict is not availability failure", func(t *testing.T) {
		auth := &fakeAuthority{result: valid}
		ledger := &fakeLedger{err: ErrConflict}
		svc, err := New(Config{
			IssuerIdentity: "spiffe://platform.example/ns/guard/sa/issuer",
			MaxTTL:         5 * time.Minute,
			Now:            func() time.Time { return now },
		}, auth, ledger)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Issue(context.Background(), a); !errors.Is(err, ErrConflict) || errors.Is(err, ErrUnavailable) {
			t.Fatalf("ledger conflict classification=%v; want ErrConflict without ErrUnavailable", err)
		}
		if ledger.calls != 1 {
			t.Fatalf("ledger calls=%d; want 1", ledger.calls)
		}
	})

	t.Run("authority outage remains availability failure", func(t *testing.T) {
		auth := &fakeAuthority{err: errors.New("authority timeout")}
		ledger := &fakeLedger{}
		svc, err := New(Config{
			IssuerIdentity: "spiffe://platform.example/ns/guard/sa/issuer",
			MaxTTL:         5 * time.Minute,
			Now:            func() time.Time { return now },
		}, auth, ledger)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Issue(context.Background(), a); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("authority outage classification=%v; want ErrUnavailable", err)
		}
		if ledger.calls != 0 {
			t.Fatalf("unavailable authority reached ledger: %d", ledger.calls)
		}
	})
}
