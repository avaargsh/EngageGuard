package admission

import (
	"compress/gzip"
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

// An authenticated peer can still select an ambiguous wire representation.
// These tests exercise real TLS, the production HTTP transport, and the
// automatic gzip decoding path rather than a manually constructed response.
func authorityCompressionServer(
	t *testing.T, peer string, raw []byte, compressed *atomic.Bool,
) (*httptest.Server, *x509.CertPool, tls.Certificate) {
	t.Helper()
	serverCert, roots := safetyServerCert(t, peer)
	clientCA, signer, clientRoots := newTestTransportCA(t)
	clientCert := newTestTLSLeaf(t, clientCA, signer, true, "spiffe://platform.example/ns/guard/sa/engageguard")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if !compressed.Load() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(raw)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		z := gzip.NewWriter(w)
		_, _ = z.Write(raw)
		_ = z.Close()
	}))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, roots, clientCert
}

func TestRuntimeSafetyClientRejectsCompressedAuthorityResponse(t *testing.T) {
	raw := []byte("{\"schema_version\":\"runtime.run-safety.v1\",\"tenant_id\":\"tenant-1\",\"run_id\":\"11111111-1111-4111-8111-222222222222\",\"agent_id\":\"agent-1\",\"agent_release_id\":\"release-1\",\"session_id\":\"session-1\",\"status\":\"RUNNING\",\"breaker_state\":\"CLOSED\",\"breaker_epoch\":1,\"breaker_version\":1}")
	var compressed atomic.Bool
	srv, roots, cert := authorityCompressionServer(t, safetyPeer, raw, &compressed)
	client, err := NewRuntimeRunSafetyClient(srv.URL, safetyPeer, safetyTenant, roots, cert)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	snapshot, err := client.GetRunSafetySnapshot(context.Background(), safetyTenant, safetyRun)
	if err != nil || snapshot.RunID != safetyRun {
		t.Fatalf("identity response rejected: snapshot=%+v err=%v", snapshot, err)
	}
	compressed.Store(true)
	snapshot, err = client.GetRunSafetySnapshot(context.Background(), safetyTenant, safetyRun)
	if !errors.Is(err, ErrAuthorityUnavailable) || snapshot.RunID != "" {
		t.Fatalf("gzip Runtime authority snapshot accepted: snapshot=%+v err=%v", snapshot, err)
	}
}

func TestDecisionPlanClientRejectsCompressedVerificationReceipt(t *testing.T) {
	snapshot := trustedRuntimeRun()
	snapshot.RunID = safetyRun
	submission := testGuardSubmission(t)
	submission.RunID = safetyRun
	submission.DecisionID = "dec_" + strings.Repeat("a", 64)
	submission.Capability.ID = "sre.metrics.read"
	submission.Capability.Version = "1.0.0"
	submission.Arguments = json.RawMessage("{}")
	raw, err := json.Marshal(guardStepReceipt{
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
	})
	if err != nil {
		t.Fatal(err)
	}
	var compressed atomic.Bool
	srv, roots, cert := authorityCompressionServer(t, guardDecisionPeer, raw, &compressed)
	client, err := NewDecisionPlanClient(srv.URL, guardDecisionPeer, snapshot.TenantID, roots, cert)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if err := client.VerifyDecisionPlanStep(context.Background(), boundRuntime(), snapshot, submission); err != nil {
		t.Fatalf("identity Decision receipt rejected: %v", err)
	}
	compressed.Store(true)
	if err := client.VerifyDecisionPlanStep(context.Background(), boundRuntime(), snapshot, submission); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("gzip Decision receipt accepted: %v", err)
	}
}
