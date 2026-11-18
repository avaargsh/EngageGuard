package admission

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// This subprocess is compiled independently from the real EngageGuard
// module and invoked by the actual Decision Core same-Run process. No fake
// Guard Decision endpoint or mocked source is provided by this test.
func TestExternalLiveDecisionPlanClient(t *testing.T) {
	if os.Getenv("GUARD_EXTERNAL_LIVE_PLAN") != "1" {
		t.Skip("source-pinned same-Run cross-service CI only")
	}
	required := func(k string) string {
		t.Helper()
		v := os.Getenv(k)
		if v == "" { t.Fatalf("missing isolated Guard source %s", k) }
		return v
	}
	parse := func(k string) uint64 {
		t.Helper()
		v, err := strconv.ParseUint(required(k), 10, 64)
		if err != nil || v == 0 { t.Fatalf("bad breaker %s: %v",k,err) }
		return v
	}
	tenant, runID := required("GUARD_LIVE_TENANT"), required("GUARD_LIVE_RUN")
	cert, err := tls.LoadX509KeyPair(required("GUARD_LIVE_CLIENT_CERT"),required("GUARD_LIVE_CLIENT_KEY"))
	if err != nil { t.Fatal(err) }
	pem, err := os.ReadFile(required("GUARD_LIVE_ROOTS"))
	if err != nil { t.Fatal(err) }
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) { t.Fatal("missing pinned Guard trust roots") }
	client, err := NewDecisionPlanClient(required("GUARD_LIVE_ORIGIN"),required("GUARD_LIVE_PEER"),tenant,roots,cert)
	if err != nil { t.Fatal(err) }
	defer client.CloseIdleConnections()
	snap := RunSafetySnapshot{
		TenantID: tenant, RunID: runID, AgentID: required("GUARD_LIVE_AGENT"),
		AgentReleaseID: required("GUARD_LIVE_RELEASE"), SessionID: required("GUARD_LIVE_SESSION"),
		Status: "RUNNING", BreakerState: "CLOSED",
		BreakerEpoch: parse("GUARD_LIVE_BREAKER_EPOCH"),
		BreakerVersion: parse("GUARD_LIVE_BREAKER_VERSION"),
	}
	// Test-only principal correlation. The live Decision authority still
	// separately authenticates the Guard client certificate and re-reads
	// actual Runtime + ACP + signed Evidence from their own services.
	principal := Principal{TenantID: tenant, SubjectID: "verified-subject",
		ActorID: "verified-subject", WorkloadID: "guard-client-test", ServiceID: "agent-runtime"}
	submission := action.ActionSubmission{
		SchemaVersion: "action-submission.v1", RunID: runID,
		DecisionID: required("GUARD_LIVE_DECISION"), PlanID: required("GUARD_LIVE_PLAN"),
		PlanHash: required("GUARD_LIVE_PLAN_HASH"), StepID: required("GUARD_LIVE_STEP"),
		Capability: action.ActionCapabilitySelector{ID: required("GUARD_LIVE_CAPABILITY"),Version: required("GUARD_LIVE_CAPABILITY_VERSION")},
		ResourceRef: required("GUARD_LIVE_RESOURCE"), Arguments: json.RawMessage("{}"),
	}
	if err := submission.Validate(); err != nil { t.Fatal(err) }
	want := required("GUARD_LIVE_EXPECT")
	got := client.VerifyDecisionPlanStep(context.Background(),principal,snap,submission)
	switch want {
	case "verified":
		if got != nil { t.Fatalf("actual Guard mTLS DecisionPlanClient denied original Step: %v",got) }
		bad := submission
		bad.PlanHash = strings.Repeat("f",64)
		if err := client.VerifyDecisionPlanStep(context.Background(),principal,snap,bad); !errors.Is(err,ErrForbidden) {
			t.Fatalf("forged PlanHash unexpectedly accepted: %v",err)
		}
		bad = submission
		bad.Capability.ID = "workspace.write"
		if err := client.VerifyDecisionPlanStep(context.Background(),principal,snap,bad); !errors.Is(err,ErrForbidden) {
			t.Fatalf("effectful capability unexpectedly reached the authority: %v",err)
		}
		t.Logf("real EngageGuard DecisionPlanClient verified same-Run %s",runID)
	case "revoked":
		if !errors.Is(got,ErrForbidden) { t.Fatalf("revoked source did not fail closed: %v",got) }
		t.Logf("real EngageGuard DecisionPlanClient denied revoked same-Run %s",runID)
	default:
		t.Fatalf("invalid isolated test expectation %q",want)
	}
}
