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

// Run only from a separately pinned ACP Golden Path with a real OAuth-
// admitted, Runtime-recovered read-only Run and dedicated Guard mTLS peer.
// A passing negative here must NOT be called a positive write-path proof.
func TestExternalLiveACPProtectedWorkspaceClient(t *testing.T) {
	if os.Getenv("GUARD_EXTERNAL_LIVE_PROTECTED_ACP") != "1" {
		t.Skip("requires source-pinned real ACP process and real Run")
	}
	required := func(name string) string {
		t.Helper()
		value := os.Getenv(name)
		if value == "" {
			t.Fatalf("missing mandatory trusted source %s", name)
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
		t.Fatal("independently authenticated Guard missing ACP trust roots")
	}
	tenant, runID := required("GUARD_ACP_TENANT"), required("GUARD_ACP_RUN")
	principal := Principal{
		TenantID: tenant, SubjectID: "runtime-workload",
		ActorID: "agent-runtime", WorkloadID: "runtime-workload",
		ServiceID: "agent-runtime",
	}
	snapshot := RunSafetySnapshot{
		TenantID: tenant, RunID: runID, AgentID: required("GUARD_ACP_AGENT"),
		AgentReleaseID: required("GUARD_ACP_RELEASE"), SessionID: required("GUARD_ACP_SESSION"),
		Status: "RUNNING", BreakerState: "CLOSED", BreakerEpoch: 1, BreakerVersion: 1,
	}
	resolved := action.ActionRequest{
		SchemaVersion: "action-request.v1",
		TenantID:      tenant,
		SubjectID:     required("GUARD_ACP_SUBJECT"),
		ActorID:       "runtime-actor",
		WorkloadID:    "runtime-workload",
		AgentID:       snapshot.AgentID,
		RunID:         runID,
		DecisionID:    "decision-live",
		PlanID:        "plan-live",
		PlanHash:      strings.Repeat("f", 64),
		StepID:        "step-live",
		OperationID:   "11111111-1111-4111-8111-111111111111",
		Capability: action.ActionCapabilityRef{
			ID:             "workspace.write",
			Version:        "1.0.0",
			ContractSHA256: strings.Repeat("c", 64),
		},
		ResourceRef:       "workspace-1",
		Arguments:         json.RawMessage(`{"path":"docs/approved.txt","content_sha256":"` + strings.Repeat("b", 64) + `"}`),
		ToolBindingDigest: strings.Repeat("a", 64),
		PolicyVersion:     required("GUARD_ACP_POLICY"),
		Audience:          "trusted-workspace-executor",
	}
	if err := resolved.Validate(); err != nil {
		t.Fatal(err)
	}
	protected, err := NewACPProtectedWorkspaceClient(required("GUARD_ACP_ORIGIN"),
		required("GUARD_ACP_PEER"), tenant, roots, cert)
	if err != nil {
		t.Fatal(err)
	}
	defer protected.CloseIdleConnections()

	// Explicitly ask for workspace.write against an original read-only SRE
	// Release. This must be a real ACP 403, not a local short circuit.
	_, err = protected.ObserveProtectedWorkspace(context.Background(), principal, snapshot, resolved)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("real ACP promoted SRE read-only catalog to protected workspace.write: %v", err)
	}

	// Cross-check source revocation with the positive read-only reference:
	// both capabilities use the SAME original OAuth-bound Run and listener,
	// and the read-only source changes from VERIFIED to DENIED when revoked.
	readonly, err := NewACPCapabilityClient(required("GUARD_ACP_ORIGIN"),
		required("GUARD_ACP_PEER"), tenant, roots, cert)
	if err != nil {
		t.Fatal(err)
	}
	defer readonly.CloseIdleConnections()
	submission := action.ActionSubmission{
		SchemaVersion: "action-submission.v1", RunID: runID,
		DecisionID: "dec-test-capability", PlanID: "plan-test-capability",
		PlanHash: strings.Repeat("a", 64), StepID: "step-test-capability",
		Capability:  action.ActionCapabilitySelector{ID: "sre.metrics.read", Version: "1.0.0"},
		ResourceRef: "payments", Arguments: json.RawMessage("{}"),
	}
	if err := submission.Validate(); err != nil {
		t.Fatal(err)
	}
	readErr := readonly.VerifyCapabilityAccess(context.Background(), principal, snapshot, submission)
	switch required("GUARD_ACP_EXPECT") {
	case "verified":
		if readErr != nil {
			t.Fatalf("original read-only Run unexpectedly revoked: %v", readErr)
		}
		t.Logf("actual ACP and independent Guard denied protected write on readonly same-Run %s while read remained verified", runID)
	case "revoked":
		if !errors.Is(readErr, ErrForbidden) {
			t.Fatalf("revoked original OAuth client still allowed readonly Run: %v", readErr)
		}
		t.Logf("actual ACP and independent Guard denied protected write and revoked original OAuth source on same-Run %s", runID)
	default:
		t.Fatal("invalid source-pinned expectation")
	}
}
