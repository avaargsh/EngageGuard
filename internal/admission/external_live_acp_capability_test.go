package admission

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// The ACP Golden Path launches this independently compiled actual Guard
// client against a real separate mTLS listener, read-only PostgreSQL
// authority role, immutable release and same actual OAuth-admitted Run.
func TestExternalLiveACPCapabilityClient(t *testing.T) {
	if os.Getenv("GUARD_EXTERNAL_LIVE_ACP") != "1" {
		t.Skip("only source-pinned same-Run ACP/Guard integration")
	}
	required := func(name string) string {
		t.Helper()
		value := os.Getenv(name)
		if value == "" {
			t.Fatalf("missing independent ACP Guard fixture %s", name)
		}
		return value
	}
	cert, err := tls.LoadX509KeyPair(required("GUARD_ACP_CLIENT_CERT"), required("GUARD_ACP_CLIENT_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	pem, err := os.ReadFile(required("GUARD_ACP_ROOTS"))
	if err != nil || !roots.AppendCertsFromPEM(pem) {
		t.Fatal("actual Guard client lacks ACP trust anchors")
	}
	tenant, runID := required("GUARD_ACP_TENANT"), required("GUARD_ACP_RUN")
	client, err := NewACPCapabilityClient(required("GUARD_ACP_ORIGIN"),
		required("GUARD_ACP_PEER"), tenant, roots, cert)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	principal := Principal{
		TenantID: tenant, SubjectID: "subject-1", ActorID: "subject-1",
		WorkloadID: "runtime-guard-test", ServiceID: "agent-runtime",
	}
	snapshot := RunSafetySnapshot{
		TenantID: tenant, RunID: runID, AgentID: required("GUARD_ACP_AGENT"),
		AgentReleaseID: required("GUARD_ACP_RELEASE"),
		SessionID: required("GUARD_ACP_SESSION"), Status: "RUNNING",
		BreakerState: "CLOSED", BreakerEpoch: 1, BreakerVersion: 1,
	}
	submission := action.ActionSubmission{
		SchemaVersion: "action-submission.v1", RunID: runID,
		DecisionID: "dec-test-capability", PlanID: "plan-test-capability",
		PlanHash: strings.Repeat("a", 64), StepID: "step-test-capability",
		Capability: action.ActionCapabilitySelector{ID: "sre.metrics.read", Version: "1.0.0"},
		ResourceRef: "payments", Arguments: json.RawMessage("{}"),
	}
	if err := submission.Validate(); err != nil {
		t.Fatal(err)
	}
	got := client.VerifyCapabilityAccess(context.Background(), principal, snapshot, submission)
	switch required("GUARD_ACP_EXPECT") {
	case "verified":
		if got != nil {
			t.Fatalf("actual live ACP denied original OAuth-bound Run: %v", got)
		}
		bad := submission
		bad.Capability.ID = "workspace.write"
		if err := client.VerifyCapabilityAccess(context.Background(), principal, snapshot, bad);
			!errors.Is(err, ErrForbidden) {
			t.Fatalf("effectful capability queried or admitted by Guard: %v", err)
		}
		bad = submission
		bad.ResourceRef = "foreign"
		if err := client.VerifyCapabilityAccess(context.Background(), principal, snapshot, bad);
			!errors.Is(err, ErrForbidden) {
			t.Fatalf("non-bound service acquired ACP capability: %v", err)
		}
		t.Logf("real EngageGuard ACPCapabilityClient verified same-Run %s", runID)
	case "revoked":
		if !errors.Is(got, ErrForbidden) {
			t.Fatalf("revoked original OAuth client still acquired ACP capability: %v", got)
		}
		t.Logf("real EngageGuard ACPCapabilityClient denied revoked same-Run %s", runID)
	default:
		t.Fatal("invalid independent ACP Guard expectation")
	}
}
