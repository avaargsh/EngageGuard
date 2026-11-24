package admission

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const runtimeGuardAuthorityPeer = "spiffe://platform.example/ns/runtime/sa/guard-authority"
const runtimeGuardTurn = "44444444-4444-4444-8444-444444444444"
const runtimeGuardAttempt = "33333333-3333-4333-8333-333333333333"
const runtimeGuardExecution = "22222222-2222-4222-8222-222222222222"

func validRuntimeGuardAuthorityJSON() string {
	return `{
		"schema_version":"runtime.guard-execution-authority.v1",
		"tenant_id":"tenant-1",
		"run_id":"11111111-1111-4111-8111-222222222222",
		"agent_id":"agent-1",
		"agent_release_id":"release-1",
		"session_id":"session-1",
		"workflow_id":"agent-run/v1/11111111-1111-4111-8111-222222222222",
		"execution_id":"22222222-2222-4222-8222-222222222222",
		"run_attempt_id":"33333333-3333-4333-8333-333333333333",
		"turn_id":"44444444-4444-4444-8444-444444444444",
		"invocation_id":"44444444-4444-4444-8444-444444444444",
		"turn_index":1,
		"attempt_generation":1,
		"attempt_breaker_epoch":1,
		"status":"RUNNING",
		"breaker_state":"CLOSED",
		"breaker_epoch":1,
		"breaker_version":1
	}`
}

func TestRuntimeGuardExecutionAuthorityClientRequiresFreshExactRuntimeBinding(t *testing.T) {
	serverCert, roots := safetyServerCert(t, runtimeGuardAuthorityPeer)
	clientCA, signer, clientRoots := newTestTransportCA(t)
	clientCert := newTestTLSLeaf(t, clientCA, signer, true, "spiffe://platform.example/ns/guard/sa/engageguard")
	var body atomic.Value
	body.Store(validRuntimeGuardAuthorityJSON())
	var status atomic.Int32
	status.Store(http.StatusOK)
	var reads atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads.Add(1)
		if r.Method != http.MethodGet ||
			r.URL.Path != "/internal/v1/guard-execution-authority/"+safetyRun+"/"+runtimeGuardTurn ||
			r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" ||
			r.Header.Get("X-Tenant-ID") != "" || r.Header.Get("Cache-Control") != "no-store" {
			t.Error("unexpected Guard execution-authority request")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots}
	srv.StartTLS()
	defer srv.Close()
	client, err := NewRuntimeGuardExecutionAuthorityClient(srv.URL, runtimeGuardAuthorityPeer, safetyTenant, roots, clientCert)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	got, err := client.GetGuardExecutionAuthority(context.Background(), safetyTenant, safetyRun, runtimeGuardTurn)
	if err != nil || got.RunID != safetyRun || got.TenantID != safetyTenant ||
		got.RunAttemptID != runtimeGuardAttempt || got.TurnID != runtimeGuardTurn ||
		got.InvocationID != runtimeGuardTurn || got.TemporalExecutionID != runtimeGuardExecution {
		t.Fatalf("valid current Runtime execution authority rejected: %+v err=%v", got, err)
	}
	if _, err := client.GetGuardExecutionAuthority(context.Background(), "other-tenant", safetyRun, runtimeGuardTurn); !errors.Is(err, ErrForbidden) || reads.Load() != 1 {
		t.Fatal("wrong tenant was sent to Runtime")
	}

	valid := validRuntimeGuardAuthorityJSON()
	badBodies := []string{
		strings.Replace(valid, `"tenant_id":"tenant-1"`, `"tenant_id":"other-tenant"`, 1),
		strings.Replace(valid, `"run_id":"11111111-1111-4111-8111-222222222222"`, `"run_id":"99999999-9999-4999-8999-999999999999"`, 1),
		strings.Replace(valid, `"turn_id":"44444444-4444-4444-8444-444444444444"`, `"turn_id":"55555555-5555-4555-8555-555555555555"`, 1),
		strings.Replace(valid, `"invocation_id":"44444444-4444-4444-8444-444444444444"`, `"invocation_id":"55555555-5555-4555-8555-555555555555"`, 1),
		strings.Replace(valid, `"attempt_generation":1`, `"attempt_generation":2`, 1),
		strings.Replace(valid, `"breaker_state":"CLOSED"`, `"breaker_state":"OPEN"`, 1),
		strings.Replace(valid, `"breaker_version":1`, `"breaker_version":2`, 1),
		strings.Replace(valid, `"breaker_epoch":1`, `"breaker_epoch":2`, 1),
		strings.Replace(valid, `"turn_index":1`, `"turn_index":0`, 1),
		strings.Replace(valid, `"run_attempt_id":"33333333-3333-4333-8333-333333333333"`, `"run_attempt_id":""`, 1),
		strings.Replace(valid, `"schema_version":"runtime.guard-execution-authority.v1"`, `"schema_version":"runtime.guard-execution-authority.v2"`, 1),
		strings.TrimSuffix(valid, "}") + `,"permit":"forbidden"}`,
		valid + " {}",
	}
	for _, bad := range badBodies {
		body.Store(bad)
		if _, err := client.GetGuardExecutionAuthority(context.Background(), safetyTenant, safetyRun, runtimeGuardTurn); err == nil {
			t.Fatalf("invalid Runtime execution authority accepted: %s", bad)
		}
	}
	body.Store(valid)
	status.Store(http.StatusForbidden)
	if _, err := client.GetGuardExecutionAuthority(context.Background(), safetyTenant, safetyRun, runtimeGuardTurn); !errors.Is(err, ErrForbidden) {
		t.Fatalf("fresh Runtime denial not preserved: %v", err)
	}
	status.Store(http.StatusServiceUnavailable)
	if _, err := client.GetGuardExecutionAuthority(context.Background(), safetyTenant, safetyRun, runtimeGuardTurn); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("Runtime outage not classified unavailable: %v", err)
	}
	status.Store(http.StatusOK)
	wrong, err := NewRuntimeGuardExecutionAuthorityClient(srv.URL, "spiffe://platform.example/ns/runtime/sa/other", safetyTenant, roots, clientCert)
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.CloseIdleConnections()
	if _, err := wrong.GetGuardExecutionAuthority(context.Background(), safetyTenant, safetyRun, runtimeGuardTurn); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("wrong Runtime server SPIFFE identity accepted: %v", err)
	}
	var decoded RuntimeExecutionAuthoritySnapshot
	if err := json.Unmarshal([]byte(valid), &decoded); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeGuardExecutionAuthorityClientRejectsMissingServerAuthEKU(t *testing.T) {
	serverCert, roots := safetyServerCertWithEKU(t, runtimeGuardAuthorityPeer, nil)
	clientCA, signer, clientRoots := newTestTransportCA(t)
	clientCert := newTestTLSLeaf(t, clientCA, signer, true, "spiffe://platform.example/ns/guard/sa/engageguard")
	var reached atomic.Bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(validRuntimeGuardAuthorityJSON()))
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots}
	srv.StartTLS()
	defer srv.Close()
	client, err := NewRuntimeGuardExecutionAuthorityClient(srv.URL, runtimeGuardExecutionAuthorityPeer, safetyTenant, roots, clientCert)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if _, err := client.GetGuardExecutionAuthority(context.Background(), safetyTenant, safetyRun, runtimeGuardTurn); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("server certificate without serverAuth EKU accepted: %v", err)
	}
	if reached.Load() {
		t.Fatal("Runtime handler reached without explicit serverAuth EKU")
	}
}
