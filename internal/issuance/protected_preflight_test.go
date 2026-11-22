package issuance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
	"github.com/avaargsh/EngageGuard/internal/admission"
	"github.com/avaargsh/EngageGuard/internal/approval"
	"github.com/avaargsh/EngageGuard/internal/acceptance/postgres"
)

type fakeRuntime struct {
	state            admission.RunSafetySnapshot
	reads            int
	changeAfterFirst bool
}

func (r *fakeRuntime) GetRunSafetySnapshot(_ context.Context, tenant, runID string) (admission.RunSafetySnapshot, error) {
	r.reads++
	if tenant != r.state.TenantID || runID != r.state.RunID {
		return admission.RunSafetySnapshot{}, admission.ErrForbidden
	}
	s := r.state
	if r.changeAfterFirst && r.reads > 1 {
		s.BreakerVersion++
	}
	return s, nil
}

type fakeProtectedDecision struct {
	step               StepProvenance
	denied             bool
	revokeOnPostflight bool
	calls              int
}

func (d *fakeProtectedDecision) VerifyProtectedStep(context.Context, admission.Principal, admission.RunSafetySnapshot, action.ActionSubmission) (StepProvenance, error) {
	d.calls++
	if d.revokeOnPostflight && d.calls > 1 {
		return StepProvenance{}, admission.ErrForbidden
	}
	if d.denied {
		return StepProvenance{}, admission.ErrForbidden
	}
	return d.step, nil
}

type fakeActionResolver struct {
	resolved           action.WorkspaceWrite
	denied             bool
	calls              int
	driftOnPostflight  bool
	revokeOnPostflight bool
}

func (r *fakeActionResolver) ResolveWorkspaceWrite(context.Context, admission.Principal, admission.RunSafetySnapshot, action.ActionSubmission) (action.WorkspaceWrite, error) {
	r.calls++
	if r.denied || (r.revokeOnPostflight && r.calls > 1) {
		return action.WorkspaceWrite{}, admission.ErrForbidden
	}
	current := r.resolved
	if r.driftOnPostflight && r.calls > 1 {
		current.ToolBindingDigest = strings.Repeat("e", 64)
	}
	return current, nil
}

type fakeProtectedACP struct {
	observation       admission.ProtectedWorkspaceObservation
	denied            bool
	driftOnPostflight bool
	calls             int
}

func (a *fakeProtectedACP) ObserveProtectedWorkspace(context.Context, admission.Principal, admission.RunSafetySnapshot, action.WorkspaceWrite, string) (admission.ProtectedWorkspaceObservation, error) {
	a.calls++
	if a.denied {
		return admission.ProtectedWorkspaceObservation{}, admission.ErrForbidden
	}
	observed := a.observation
	if a.driftOnPostflight && a.calls > 1 {
		observed.PolicyRevision = "policy-v2"
	}
	return observed, nil
}

type fakeCurrentApproval struct {
	status                    string
	rev                       string
	calls                     int
	revokeOnPostflight        bool
	revisionDriftOnPostflight bool
}

func (c *fakeCurrentApproval) CheckCurrentApproval(_ context.Context, proof approval.Evidence) (ApprovalState, error) {
	c.calls++
	status := c.status
	if c.revokeOnPostflight && c.calls > 1 {
		status = "REVOKED"
	}
	rev := c.rev
	if c.revisionDriftOnPostflight && c.calls > 1 {
		rev = "rev-4"
	}
	return ApprovalState{ApprovalID: proof.ApprovalID, Scope: proof.Scope, Status: status, Revision: rev}, nil
}

type fakeRisk struct {
	decision         string
	generation       uint64
	denyOnPostflight bool
	bumpOnPostflight bool
	calls            int
}

func (r *fakeRisk) EvaluateRisk(_ context.Context, scope approval.Scope) (RiskState, error) {
	r.calls++
	state := RiskState{Decision: r.decision, ActionHash: scope.ActionHash, PolicyVersion: scope.PolicyVersion, Generation: r.generation}
	if r.denyOnPostflight && r.calls > 1 {
		state.Decision = "DENY"
	}
	if r.bumpOnPostflight && r.calls > 1 {
		state.Generation++
	}
	return state, nil
}

// fakeAccepted simulates Guard's source-owned immutable accepted submission.
type fakeAccepted struct {
	snapshot postgres.AcceptedSubmission
	calls int
	unavailable bool
	changeOnPostflight bool
}
func (a *fakeAccepted) ReadAcceptedSubmission(_ context.Context, tenantID, operationID string) (postgres.AcceptedSubmission, error) {
	a.calls++
	if a.unavailable { return postgres.AcceptedSubmission{}, errors.New("accepted DB unavailable") }
	out := a.snapshot
	if a.changeOnPostflight && a.calls > 1 {
		out.Raw = append([]byte(nil), out.Raw...)
		out.Raw = append(out.Raw, ' ')
	}
	return out, nil
}

type preflightFixture struct {
	runtime    *fakeRuntime
	decision   *fakeProtectedDecision
	actions    *fakeActionResolver
	acp        *fakeProtectedACP
	approvals  *fakeCurrentApproval
	risk       *fakeRisk
	principal  admission.Principal
	submission action.ActionSubmission
	signed     []byte
	pub        ed25519.PublicKey
	accepted   *fakeAccepted
	now        time.Time
}

func makePreflightFixture(t *testing.T) *preflightFixture {
	t.Helper()
	f := &preflightFixture{now: time.Now().UTC().Truncate(time.Second)}
	f.principal = admission.Principal{TenantID: "tenant-a", SubjectID: "service-runtime", ActorID: "service-runtime", WorkloadID: "guard-trust", ServiceID: "agent-runtime"}
	f.submission = action.ActionSubmission{SchemaVersion: "action-submission.v1", RunID: "11111111-1111-4111-8111-111111111111",
		DecisionID: "decision-1", PlanID: "plan-1", PlanHash: strings.Repeat("a", 64), StepID: "step-1",
		Capability:  action.ActionCapabilitySelector{ID: "workspace.write", Version: "1.0.0"},
		ResourceRef: "workspace-1", Arguments: json.RawMessage(`{"path":"docs/output.md"}`)}
	f.runtime = &fakeRuntime{state: admission.RunSafetySnapshot{TenantID: "tenant-a", RunID: f.submission.RunID,
		AgentID: "agent-1", AgentReleaseID: "release-1", SessionID: "session-1",
		Status: "RUNNING", BreakerState: "CLOSED", BreakerEpoch: 2, BreakerVersion: 7}}
	f.decision = &fakeProtectedDecision{step: StepProvenance{
		RunID: f.submission.RunID, AgentID: "agent-1", AgentReleaseID: "release-1", SessionID: "session-1",
		DecisionID: f.submission.DecisionID, PlanID: f.submission.PlanID, PlanHash: f.submission.PlanHash, StepID: f.submission.StepID,
		CapabilityID: "workspace.write", CapabilityVersion: "1.0.0", ResourceRef: "workspace-1",
		Arguments: json.RawMessage(`{"path":"docs/output.md"}`), BreakerEpoch: 2, BreakerVersion: 7, AttemptID: "attempt-1", TurnID: "turn-1",
	}}
	f.actions = &fakeActionResolver{resolved: action.WorkspaceWrite{
		SchemaVersion: "v0.1", TenantID: "tenant-a", SubjectID: "human-1", AgentID: "agent-1",
		OperationID: "22222222-2222-4222-8222-222222222222", CapabilityID: "workspace.write",
		ToolBindingDigest: strings.Repeat("b", 64), PolicyVersion: "policy-v1", Audience: "workspace-executor",
		WorkspaceID: "workspace-1", RelativePath: "docs/output.md", ContentDigest: strings.Repeat("c", 64),
	}}
	raw, err := json.Marshal(f.submission)
	if err != nil { t.Fatal(err) }
	digest, err := action.SubmissionDigest(raw)
	if err != nil { t.Fatal(err) }
	f.accepted = &fakeAccepted{snapshot: postgres.AcceptedSubmission{
		Operation: postgres.Operation{
			TenantID: f.principal.TenantID,
			OperationID: "22222222-2222-4222-8222-222222222222",
			SubmissionDigest: digest,
			Status: "ACCEPTED",
		},
		Raw: raw,
	}}
	f.acp = &fakeProtectedACP{observation: admission.ProtectedWorkspaceObservation{
		ContractSHA256: strings.Repeat("d", 64), ConfigDigest: "sha256:" + strings.Repeat("e", 64), PolicyRevision: "policy-v1",
	}}
	f.approvals = &fakeCurrentApproval{status: "APPROVED", rev: "rev-3"}
	f.risk = &fakeRisk{decision: "ALLOW", generation: 2}
	binding := approval.ExecutionBinding{
		RunID: f.submission.RunID, AttemptID: "attempt-1", TurnID: "turn-1", AgentReleaseID: "release-1",
		DecisionID: "decision-1", PlanHash: f.submission.PlanHash, StepID: "step-1",
	}
	scope, err := approval.ScopeForResolvedWorkspace(f.actions.resolved, binding)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.pub = pub
	ev := approval.Evidence{SchemaVersion: "engageguard.approval-evidence.v1", ApprovalID: "approval-1", Decision: "APPROVED",
		Scope: scope, IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Minute)}
	payload, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(pub)
	signature := ed25519.Sign(priv, append([]byte("engageguard/approval-proof/v1\x00"), payload...))
	f.signed, err = json.Marshal(approval.SignedEvidence{KeyID: hex.EncodeToString(digest[:]), Payload: payload, Signature: signature})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *preflightFixture) gate(t *testing.T) *Gate {
	t.Helper()
	g, err := NewGate(Dependencies{
		Runtime: f.runtime, Decision: f.decision, Actions: f.actions, ACP: f.acp, Accepted: f.accepted,
		Approvals: f.approvals, Risk: f.risk, ApprovalKey: f.pub, Now: func() time.Time { return f.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func TestProtectedPreflightRequiresIndependentFreshAuthorityAndNeverIssues(t *testing.T) {
	f := makePreflightFixture(t)
	if err := f.gate(t).Verify(context.Background(), f.principal, f.submission, f.signed); err != nil {
		t.Fatal(err)
	}
	if f.runtime.reads != 2 || f.decision.calls < 2 || f.actions.calls != 2 || f.approvals.calls < 2 {
		t.Fatalf("missing live postflight checks: Runtime=%d Decision=%d Action=%d Approval=%d", f.runtime.reads, f.decision.calls, f.actions.calls, f.approvals.calls)
	}
}
func TestProtectedPreflightRejectsStaleEvidenceRiskAndSourceDrift(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*preflightFixture)
	}{
		{"runtime breaker drift after first validation", func(f *preflightFixture) { f.runtime.changeAfterFirst = true }},
		{"Decision mismatch PlanID", func(f *preflightFixture) { f.decision.step.PlanID = "other" }},
		{"Decision mismatch raw arguments", func(f *preflightFixture) { f.decision.step.Arguments = json.RawMessage(`{"path":"other"}`) }},
		{"Decision source denies protected write", func(f *preflightFixture) { f.decision.denied = true }},
		{"resolver denied", func(f *preflightFixture) { f.actions.denied = true }},
		{"resolved ToolBinding changes after first verification", func(f *preflightFixture) { f.actions.driftOnPostflight = true }},
		{"resolved action is revoked at postflight", func(f *preflightFixture) { f.actions.revokeOnPostflight = true }},
		{"resolver changed path without new signed approval", func(f *preflightFixture) { f.actions.resolved.RelativePath = "other.md" }},
		{"resolver changed subject without new signed approval", func(f *preflightFixture) { f.actions.resolved.SubjectID = "attacker" }},
		{"ACP policy revision drift", func(f *preflightFixture) { f.acp.observation.PolicyRevision = "policy-v2" }},
		{"ACP source revoked", func(f *preflightFixture) { f.acp.denied = true }},
		{"approval currently revoked", func(f *preflightFixture) { f.approvals.status = "REVOKED" }},
		{"approval revoked between preflight and postflight", func(f *preflightFixture) { f.approvals.revokeOnPostflight = true }},
		{"approval revision changed after initial verification", func(f *preflightFixture) { f.approvals.revisionDriftOnPostflight = true }},
		{"ACP policy changed after initial capability observation", func(f *preflightFixture) { f.acp.driftOnPostflight = true }},
		{"Decision revoked after initial Step validation", func(f *preflightFixture) { f.decision.revokeOnPostflight = true }},
		{"risk DENY after initial check", func(f *preflightFixture) { f.risk.denyOnPostflight = true }},
		{"risk generation changed after initial check", func(f *preflightFixture) { f.risk.bumpOnPostflight = true }},
		{"risk blocked", func(f *preflightFixture) { f.risk.decision = "DENY" }},
		{"risk evidence stale", func(f *preflightFixture) { f.risk.generation = 0 }},
		{"approval signature changed", func(f *preflightFixture) { f.signed = append([]byte(nil), f.signed...); f.signed[len(f.signed)-3] ^= 1 }},
		{"caller provided different target", func(f *preflightFixture) { f.submission.ResourceRef = "workspace-2" }},
		{"untrusted service", func(f *preflightFixture) { f.principal.ServiceID = "unknown" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := makePreflightFixture(t)
			tc.mutate(f)
			if err := f.gate(t).Verify(context.Background(), f.principal, f.submission, f.signed); err == nil {
				t.Fatal("protected workspace preflight passed with unauthorized or stale source")
			}
		})
	}
}
func TestProtectedPreflightConstructionFailsWithMissingDependencies(t *testing.T) {
	f := makePreflightFixture(t)
	g := Dependencies{Runtime: f.runtime, Decision: f.decision, Actions: f.actions, ACP: f.acp, Approvals: f.approvals,
		Risk: f.risk, Accepted: f.accepted, ApprovalKey: f.pub, Now: func() time.Time { return f.now }}
	if _, err := NewGate(Dependencies{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil source accepted: %v", err)
	}
	g.Approvals = nil
	if _, err := NewGate(g); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil live revocation source accepted: %v", err)
	}
}

func TestProtectedPreflightRechecksApprovalExpiryAtReturn(t *testing.T) {
	cases := []struct {
		name   string
		offset time.Duration
		deny   bool
	}{
		{"valid just before expiry", 59 * time.Second, false},
		{"expires exactly at postflight", time.Minute, true},
		{"expires during source rechecks", 61 * time.Second, true},
		{"clock moves backwards", -2 * time.Second, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := makePreflightFixture(t)
			clockReads := 0
			g, err := NewGate(Dependencies{
				Runtime: f.runtime, Decision: f.decision, Actions: f.actions,
				ACP: f.acp, Accepted: f.accepted, Approvals: f.approvals, Risk: f.risk,
				ApprovalKey: f.pub,
				Now: func() time.Time {
					clockReads++
					if clockReads == 1 {
						return f.now
					}
					return f.now.Add(tc.offset)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			err = g.Verify(context.Background(), f.principal, f.submission, f.signed)
			if clockReads < 2 {
				t.Fatalf("protected preflight did not re-read trusted time after source checks: calls=%d err=%v", clockReads, err)
			}
			if tc.deny {
				if !errors.Is(err, ErrDenied) {
					t.Fatalf("expired or rolled-back signed approval was accepted: err=%v", err)
				}
			} else if err != nil {
				t.Fatalf("still-valid signed approval rejected: %v", err)
			}
		})
	}
}

func TestProtectedPreflightRequiresDurableAcceptedSubmissionAndChecksItTwice(t *testing.T) {
	f := makePreflightFixture(t)
	g := f.gate(t)
	if err := g.Verify(context.Background(), f.principal, f.submission, f.signed); err != nil {
		t.Fatalf("valid matching accepted operation blocked: %v", err)
	}
	if f.accepted.calls != 2 {
		t.Fatalf("accepted submission was not checked before and after remote authorities: reads=%d", f.accepted.calls)
	}
}

func TestProtectedPreflightRejectsAcceptedOperationMismatchAndDrift(t *testing.T) {
	for _, tc := range []struct {
		name string
		mutate func(*fakeAccepted)
	}{
		{"accepted record unavailable", func(a *fakeAccepted) { a.unavailable = true }},
		{"accepted operation wrong tenant", func(a *fakeAccepted) { a.snapshot.Operation.TenantID = "tenant-other" }},
		{"accepted operation different ID", func(a *fakeAccepted) { a.snapshot.Operation.OperationID = "33333333-3333-4333-8333-333333333333" }},
		{"accepted operation not accepted", func(a *fakeAccepted) { a.snapshot.Operation.Status = "UNKNOWN" }},
		{"accepted snapshot digest changed", func(a *fakeAccepted) { a.snapshot.Operation.SubmissionDigest = strings.Repeat("0", 64) }},
		{"accepted snapshot bytes changed", func(a *fakeAccepted) { a.snapshot.Raw = append([]byte(nil), a.snapshot.Raw...); a.snapshot.Raw = append(a.snapshot.Raw, ' ') }},
		{"accepted body has different Run", func(a *fakeAccepted) {
			a.snapshot.Raw = []byte(strings.Replace(string(a.snapshot.Raw), "11111111-1111-4111-8111-111111111111", "44444444-4444-4444-8444-444444444444", 1))
			digest, err := action.SubmissionDigest(a.snapshot.Raw); if err != nil { panic(err) }; a.snapshot.Operation.SubmissionDigest = digest
		}},
		{"accepted source changes after first read", func(a *fakeAccepted) { a.changeOnPostflight = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := makePreflightFixture(t)
			tc.mutate(f.accepted)
			if err := f.gate(t).Verify(context.Background(), f.principal, f.submission, f.signed); err == nil {
				t.Fatalf("unauthorized accepted provenance passed: %s", tc.name)
			}
		})
	}
}

func TestProtectedPreflightFailClosedWithoutAcceptedSource(t *testing.T) {
	f := makePreflightFixture(t)
	if _, err := NewGate(Dependencies{
		Runtime: f.runtime, Decision: f.decision, Actions: f.actions,
		ACP: f.acp, Approvals: f.approvals, Risk: f.risk,
		ApprovalKey: f.pub, Now: func() time.Time { return f.now },
	}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing durable acceptance source accepted by Gate: %v", err)
	}
}
