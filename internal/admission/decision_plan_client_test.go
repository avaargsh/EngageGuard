package admission

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const guardDecisionPeer = "spiffe://platform.example/ns/decision/sa/agent-decision"

func TestGuardDecisionClientReadsExactFreshMTLSPlanNotCallerApproval(t *testing.T) {
	serverCert, roots := safetyServerCert(t, guardDecisionPeer)
	clientCA, signer, clientRoots := newTestTransportCA(t)
	cert := newTestTLSLeaf(t, clientCA, signer, true, "spiffe://platform.example/ns/guard/sa/engageguard")
	snapshot := trustedRuntimeRun()
	snapshot.RunID = safetyRun
	var status atomic.Int32
	status.Store(http.StatusOK)
	var count atomic.Int32
	type planResponse struct {
		SchemaVersion  string `json:"schema_version"`
		RunID          string `json:"run_id"`
		DecisionID     string `json:"decision_id"`
		PlanHash       string `json:"plan_hash"`
		StepID         string `json:"step_id"`
		RecordSHA256   string `json:"record_sha256"`
		BreakerEpoch   int64  `json:"breaker_epoch"`
		BreakerVersion int64  `json:"breaker_version"`
		Status         string `json:"status"`
	}
	submission := testGuardSubmission(t)
	submission.RunID = safetyRun
	submission.DecisionID = "dec_" + strings.Repeat("a", 64)
	submission.Capability.ID = "sre.metrics.read"
	submission.Capability.Version = "1.0.0"
	submission.Arguments = json.RawMessage("{}")
	want := planResponse{
		SchemaVersion: decisionPlanSchema, RunID: safetyRun,
		DecisionID: submission.DecisionID, PlanHash: submission.PlanHash,
		StepID: submission.StepID, RecordSHA256: strings.Repeat("c", 64),
		BreakerEpoch:   int64(snapshot.BreakerEpoch),
		BreakerVersion: int64(snapshot.BreakerVersion), Status: "VERIFIED",
	}
	body, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var response atomic.Value
	response.Store(string(body))
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != decisionPlanPath || r.URL.RawQuery != "" ||
			r.Header.Get("Content-Type") != "application/json" ||
			r.Header.Get("Authorization") != "" {
			t.Errorf("untrusted Guard Decision request")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte(response.Load().(string)))
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots}
	srv.StartTLS()
	defer srv.Close()
	client, err := NewDecisionPlanClient(srv.URL, guardDecisionPeer, snapshot.TenantID, roots, cert)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	principal := boundRuntime()
	if err := client.VerifyDecisionPlanStep(context.Background(), principal, snapshot, submission); err != nil {
		t.Fatalf("authentic fresh Decision proof rejected: %v", err)
	}
	original := count.Load()
	bad := submission
	bad.Capability.ID = "workspace.write"
	if err := client.VerifyDecisionPlanStep(context.Background(), principal, snapshot, bad); !errors.Is(err, ErrForbidden) || count.Load() != original {
		t.Fatalf("write tool sent to read-only Decision authority: %v", err)
	}
	for _, tc := range []struct {
		status int
		body   string
		want   error
	}{
		{http.StatusForbidden, string(body), ErrForbidden},
		{http.StatusServiceUnavailable, string(body), ErrAuthorityUnavailable},
		{http.StatusOK, strings.Replace(string(body), `"breaker_version":11`, `"breaker_version":12`, 1), ErrAuthorityUnavailable},
		{http.StatusOK, strings.Replace(string(body), `"record_sha256":"`+strings.Repeat("c", 64)+`"`, `"record_sha256":"bad"`, 1), ErrAuthorityUnavailable},
		{http.StatusOK, string(body) + " {}", ErrAuthorityUnavailable},
	} {
		status.Store(int32(tc.status))
		response.Store(tc.body)
		if err := client.VerifyDecisionPlanStep(context.Background(), principal, snapshot, submission); !errors.Is(err, tc.want) {
			t.Fatalf("stale or invalid source accepted: %v want %v", err, tc.want)
		}
	}
	status.Store(http.StatusOK)
	response.Store(string(body))
	wrong, err := NewDecisionPlanClient(srv.URL, "spiffe://platform.example/ns/decision/sa/other", snapshot.TenantID, roots, cert)
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.CloseIdleConnections()
	if err := wrong.VerifyDecisionPlanStep(context.Background(), principal, snapshot, submission); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("wrong Decision SPIFFE peer accepted: %v", err)
	}
}

// Guard may not turn a synthetic test proof into a real admission without a
// separately configured, working ACP capability authority.
func TestDecisionPlanClientRequiresPinnedCredentials(t *testing.T) {
	if _, err := NewDecisionPlanClient("http://localhost:8080", "spiffe://platform.example/ns/decision/sa/agent-decision", "tenant-a", x509.NewCertPool(), tls.Certificate{}); err == nil {
		t.Fatal("untrusted plaintext Decision origin accepted")
	}
}
