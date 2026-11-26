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
		RunAttemptID   string `json:"run_attempt_id"`
		TurnID         string `json:"turn_id"`
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
		RunAttemptID: runtimeGuardAttempt, TurnID: runtimeGuardTurn,
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
	binding, err := client.VerifyDecisionPlanStepReceipt(context.Background(), principal, snapshot, submission)
	if err != nil {
		t.Fatalf("authentic fresh Decision proof rejected: %v", err)
	}
	if binding.RunID != safetyRun || binding.RunAttemptID != runtimeGuardAttempt || binding.TurnID != runtimeGuardTurn {
		t.Fatalf("Decision receipt selectors were not returned exactly: %+v", binding)
	}
	original := count.Load()
	bad := submission
	bad.Capability.ID = "workspace.write"
	if err := client.VerifyDecisionPlanStep(context.Background(), principal, snapshot, bad); !errors.Is(err, ErrForbidden) || count.Load() != original {
		t.Fatalf("write tool sent to read-only Decision authority: %v", err)
	}

	// A namespace prefix is not an authorization classifier: "sre." can
	// name a future mutating capability. Only explicitly reviewed read-only
	// capability IDs may reach this necessary-only Decision verifier.
	bad.Capability.ID = "sre.executor.write"
	if err := client.VerifyDecisionPlanStep(context.Background(), principal, snapshot, bad); !errors.Is(err, ErrForbidden) || count.Load() != original {
		t.Fatalf("unreviewed mutating SRE capability reached Decision verifier: %v", err)
	}
	bad = submission
	bad.Capability.Version = "2.0.0"
	if err := client.VerifyDecisionPlanStep(context.Background(), principal, snapshot, bad); !errors.Is(err, ErrForbidden) || count.Load() != original {
		t.Fatalf("unreviewed read-only capability version reached Decision verifier: %v", err)
	}
	bad = submission
	bad.PlanHash = "not-a-sha256"
	if err := client.VerifyDecisionPlanStep(context.Background(), principal, snapshot, bad); !errors.Is(err, ErrForbidden) || count.Load() != original {
		t.Fatalf("malformed ActionSubmission reached Decision verifier: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.VerifyDecisionPlanStepReceipt(canceled, principal, snapshot, submission); !errors.Is(err, ErrAuthorityUnavailable) || count.Load() != original {
		t.Fatalf("canceled context reached Decision authority: %v", err)
	}
	if err := client.VerifyDecisionPlanStep(nil, principal, snapshot, submission); !errors.Is(err, ErrAuthorityUnavailable) || count.Load() != original {
		t.Fatalf("nil context was not rejected: %v", err)
	}
	staleBreaker := strings.Replace(string(body), `"breaker_version":1`, `"breaker_version":2`, 1)
	if staleBreaker == string(body) {
		t.Fatal("breaker-version negative fixture did not mutate the JSON receipt")
	}
	badRecord := strings.Replace(string(body), `"record_sha256":"`+strings.Repeat("c", 64)+`"`, `"record_sha256":"bad"`, 1)
	if badRecord == string(body) {
		t.Fatal("record-hash negative fixture did not mutate the JSON receipt")
	}
	for _, tc := range []struct {
		status int
		body   string
		want   error
	}{
		{http.StatusForbidden, string(body), ErrForbidden},
		{http.StatusServiceUnavailable, string(body), ErrAuthorityUnavailable},
		{http.StatusOK, staleBreaker, ErrAuthorityUnavailable},
		{http.StatusOK, badRecord, ErrAuthorityUnavailable},
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

// A verified mTLS peer must not bypass the bounded response-body check by
// sending unbounded response-header metadata first.
func TestDecisionPlanClientRejectsOversizedResponseHeaders(t *testing.T) {
	serverCert, roots := safetyServerCert(t, guardDecisionPeer)
	clientCA, signer, clientRoots := newTestTransportCA(t)
	cert := newTestTLSLeaf(t, clientCA, signer, true, "spiffe://platform.example/ns/guard/sa/engageguard")
	submission := testGuardSubmission(t)
	submission.RunID = safetyRun
	submission.DecisionID = "dec_" + strings.Repeat("a", 64)
	submission.Capability.ID = "sre.metrics.read"
	submission.Capability.Version = "1.0.0"
	submission.Arguments = json.RawMessage("{}")
	snapshot := trustedRuntimeRun()
	snapshot.RunID = safetyRun
	receipt := guardStepReceipt{
		SchemaVersion: decisionPlanSchema, RunID: snapshot.RunID,
		RunAttemptID: runtimeGuardAttempt, TurnID: runtimeGuardTurn,
		DecisionID: submission.DecisionID, PlanHash: submission.PlanHash,
		StepID: submission.StepID, RecordSHA256: strings.Repeat("c", 64),
		BreakerEpoch:   int64(snapshot.BreakerEpoch),
		BreakerVersion: int64(snapshot.BreakerVersion), Status: "VERIFIED",
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Untrusted-Excessive-Metadata", strings.Repeat("X", 16*1024))
		_, _ = w.Write(data)
	}))
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots,
	}
	srv.StartTLS()
	defer srv.Close()
	client, err := NewDecisionPlanClient(srv.URL, guardDecisionPeer, snapshot.TenantID, roots, cert)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if err := client.VerifyDecisionPlanStep(context.Background(), boundRuntime(), snapshot, submission); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("oversized authenticated Decision response headers accepted: %v", err)
	}
}

// A verified mTLS Decision authority must not make ambiguous HTTP response
// headers into an accepted Plan verification receipt. The first value alone
// is not an authoritative representation or freshness policy.
func TestDecisionPlanClientRejectsAmbiguousResponseHeaders(t *testing.T) {
	serverCert, roots := safetyServerCert(t, guardDecisionPeer)
	clientCA, signer, clientRoots := newTestTransportCA(t)
	clientCert := newTestTLSLeaf(t, clientCA, signer, true, "spiffe://platform.example/ns/guard/sa/engageguard")
	snapshot := trustedRuntimeRun()
	snapshot.RunID = safetyRun
	submission := testGuardSubmission(t)
	submission.RunID = safetyRun
	submission.DecisionID = "dec_" + strings.Repeat("a", 64)
	submission.Capability.ID = "sre.metrics.read"
	submission.Capability.Version = "1.0.0"
	submission.Arguments = json.RawMessage("{}")
	receipt := guardStepReceipt{
		SchemaVersion:  decisionPlanSchema,
		RunID:          snapshot.RunID,
		RunAttemptID:   runtimeGuardAttempt,
		TurnID:         runtimeGuardTurn,
		DecisionID:     submission.DecisionID,
		PlanHash:       submission.PlanHash,
		StepID:         submission.StepID,
		RecordSHA256:   strings.Repeat("c", 64),
		BreakerEpoch:   int64(snapshot.BreakerEpoch),
		BreakerVersion: int64(snapshot.BreakerVersion),
		Status:         "VERIFIED",
	}
	payload, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name          string
		contentTypes  []string
		cacheControls []string
		valid         bool
	}{
		{"single-canonical", []string{"application/json"}, []string{"no-store"}, true},
		{"duplicate-identical-type", []string{"application/json", "application/json"}, []string{"no-store"}, false},
		{"duplicate-conflicting-type", []string{"application/json", "text/plain"}, []string{"no-store"}, false},
		{"duplicate-identical-cache", []string{"application/json"}, []string{"no-store", "no-store"}, false},
		{"duplicate-conflicting-cache", []string{"application/json"}, []string{"no-store", "public"}, false},
	}
	var selected atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		current := cases[int(selected.Load())]
		for _, value := range current.contentTypes {
			w.Header().Add("Content-Type", value)
		}
		for _, value := range current.cacheControls {
			w.Header().Add("Cache-Control", value)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
	}
	srv.StartTLS()
	defer srv.Close()
	client, err := NewDecisionPlanClient(srv.URL, guardDecisionPeer, snapshot.TenantID, roots, clientCert)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			selected.Store(int32(i))
			err := client.VerifyDecisionPlanStep(context.Background(), boundRuntime(), snapshot, submission)
			if tc.valid {
				if err != nil {
					t.Fatalf("single canonical Decision receipt rejected: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrAuthorityUnavailable) {
				t.Fatalf("ambiguous Decision receipt metadata accepted: content-type=%q cache-control=%q err=%v",
					tc.contentTypes, tc.cacheControls, err)
			}
		})
	}
}
