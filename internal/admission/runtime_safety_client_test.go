package admission

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const safetyPeer = "spiffe://platform.example/ns/runtime/sa/agent-runtime"
const safetyRun = "11111111-1111-4111-8111-222222222222"
const safetyTenant = "tenant-1"

func safetyServerCert(t *testing.T, identity string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	return safetyServerCertWithEKU(t, identity, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

func safetyServerCertWithEKU(t *testing.T, identity string, usage []x509.ExtKeyUsage) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	return safetyServerCertWithKeyUsage(t, identity, usage, x509.KeyUsageDigitalSignature)
}

func safetyServerCertWithKeyUsage(t *testing.T, identity string, usage []x509.ExtKeyUsage, keyUsage x509.KeyUsage) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	ca, signer, roots := newTestTransportCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(identity)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(300), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: keyUsage, ExtKeyUsage: usage,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, URIs: []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}, roots
}

func TestRuntimeSafetyClientRequiresAuthenticFreshExactBinding(t *testing.T) {
	serverCert, roots := safetyServerCert(t, safetyPeer)
	clientCA, signer, clientRoots := newTestTransportCA(t)
	cert := newTestTLSLeaf(t, clientCA, signer, true, "spiffe://platform.example/ns/guard/sa/engageguard")
	good := `{"schema_version":"runtime.run-safety.v1","tenant_id":"tenant-1","run_id":"` + safetyRun + `","agent_id":"agent-1","agent_release_id":"release-1","session_id":"session-1","status":"RUNNING","breaker_state":"CLOSED","breaker_epoch":1,"breaker_version":1}`
	var body atomic.Value
	body.Store(good)
	var status atomic.Int32
	status.Store(http.StatusOK)
	var reads atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/internal/v1/runs/"+safetyRun+"/safety" ||
			r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Tenant-ID") != "" {
			t.Error("unexpected safety request shape")
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
	c, err := NewRuntimeRunSafetyClient(srv.URL, safetyPeer, safetyTenant, roots, cert)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseIdleConnections()
	snap, err := c.GetRunSafetySnapshot(context.Background(), safetyTenant, safetyRun)
	if err != nil || snap.RunID != safetyRun || snap.TenantID != safetyTenant || snap.BreakerEpoch != 1 {
		t.Fatalf("valid real TLS safety read rejected: %+v %v", snap, err)
	}
	if _, err := c.GetRunSafetySnapshot(context.Background(), "other-tenant", safetyRun); !errors.Is(err, ErrForbidden) || reads.Load() != 1 {
		t.Fatal("wrong tenant was sent to Runtime")
	}
	for _, bad := range []string{
		strings.Replace(good, `"tenant-1"`, `"other-tenant"`, 1),
		strings.Replace(good, `"status":"RUNNING"`, `"status":"CANCELLED"`, 1),
		strings.Replace(good, `"breaker_epoch":1`, `"breaker_epoch":0`, 1),
		strings.Replace(good, `"breaker_epoch":1`, `"breaker_epoch":1,"breaker_epoch":2`, 1),
		strings.TrimSuffix(good, "}") + `,"authorized":true}`,
		good + " {}",
	} {
		body.Store(bad)
		if _, err := c.GetRunSafetySnapshot(context.Background(), safetyTenant, safetyRun); err == nil {
			t.Fatal("malformed or mismatched snapshot admitted")
		}
	}
	body.Store(good)
	status.Store(http.StatusForbidden)
	if _, err := c.GetRunSafetySnapshot(context.Background(), safetyTenant, safetyRun); !errors.Is(err, ErrForbidden) {
		t.Fatalf("fresh denial used stale safety result: %v", err)
	}
	status.Store(http.StatusServiceUnavailable)
	if _, err := c.GetRunSafetySnapshot(context.Background(), safetyTenant, safetyRun); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("outage not classified unavailable: %v", err)
	}
	status.Store(http.StatusOK)
	wrong, err := NewRuntimeRunSafetyClient(srv.URL, "spiffe://platform.example/ns/runtime/sa/other", safetyTenant, roots, cert)
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.CloseIdleConnections()
	if _, err := wrong.GetRunSafetySnapshot(context.Background(), safetyTenant, safetyRun); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("wrong server SPIFFE identity accepted: %v", err)
	}
}

// A chain-valid server certificate without an explicit serverAuth EKU is
// unconstrained under ordinary Go x509 verification; Guard must still deny it.
func TestRuntimeSafetyClientRejectsMissingServerAuthEKU(t *testing.T) {
	serverCert, roots := safetyServerCertWithEKU(t, safetyPeer, nil)
	clientCA, signer, clientRoots := newTestTransportCA(t)
	clientCert := newTestTLSLeaf(t, clientCA, signer, true, "spiffe://platform.example/ns/guard/sa/engageguard")
	var reached atomic.Bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(`{"schema_version":"runtime.run-safety.v1","tenant_id":"tenant-1","run_id":"` + safetyRun + `","agent_id":"agent-1","agent_release_id":"release-1","session_id":"session-1","status":"RUNNING","breaker_state":"CLOSED","breaker_epoch":1,"breaker_version":1}`))
	}))
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots,
	}
	srv.StartTLS()
	defer srv.Close()
	client, err := NewRuntimeRunSafetyClient(srv.URL, safetyPeer, safetyTenant, roots, clientCert)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if _, err := client.GetRunSafetySnapshot(context.Background(), safetyTenant, safetyRun); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("server certificate missing explicit serverAuth EKU admitted: %v", err)
	}
	if reached.Load() {
		t.Fatal("server handler received privileged safety read with missing serverAuth EKU")
	}
}

// Response BODY limits do not bound HTTP header allocation. A peer with a
// valid certificate cannot send arbitrarily large header metadata to Guard.
func TestRuntimeSafetyClientRejectsOversizedResponseHeaders(t *testing.T) {
	serverCert, roots := safetyServerCert(t, safetyPeer)
	clientCA, signer, clientRoots := newTestTransportCA(t)
	cert := newTestTLSLeaf(t, clientCA, signer, true, "spiffe://platform.example/ns/guard/sa/engageguard")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Untrusted-Excessive-Metadata", strings.Repeat("X", 16*1024))
		_, _ = w.Write([]byte(`{"schema_version":"runtime.run-safety.v1","tenant_id":"tenant-1","run_id":"` + safetyRun + `","agent_id":"agent-1","agent_release_id":"release-1","session_id":"session-1","status":"RUNNING","breaker_state":"CLOSED","breaker_epoch":1,"breaker_version":1}`))
	}))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
	}
	srv.StartTLS()
	defer srv.Close()
	client, err := NewRuntimeRunSafetyClient(srv.URL, safetyPeer, safetyTenant, roots, cert)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if _, err := client.GetRunSafetySnapshot(context.Background(), safetyTenant, safetyRun); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("oversized HTTP response headers were accepted by safety authority: %v", err)
	}
}

// TLS 1.3 peers have to sign their handshake. A CA-valid, SPIFFE-matched
// server certificate with ServerAuth EKU but no digitalSignature KeyUsage
// must never authorize a Runtime safety read, even if the peer has the key.
func TestRuntimeSafetyClientRejectsServerWithoutDigitalSignatureKeyUsage(t *testing.T) {
	serverCert, roots := safetyServerCertWithKeyUsage(t, safetyPeer,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, x509.KeyUsageKeyEncipherment)
	clientCA, signer, clientRoots := newTestTransportCA(t)
	clientCert := newTestTLSLeaf(t, clientCA, signer, true, "spiffe://platform.example/ns/guard/sa/engageguard")
	var reached atomic.Bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(`{"schema_version":"runtime.run-safety.v1","tenant_id":"tenant-1","run_id":"` + safetyRun + `","agent_id":"agent-1","agent_release_id":"release-1","session_id":"session-1","status":"RUNNING","breaker_state":"CLOSED","breaker_epoch":1,"breaker_version":1}`))
	}))
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots,
	}
	srv.StartTLS()
	defer srv.Close()
	client, err := NewRuntimeRunSafetyClient(srv.URL, safetyPeer, safetyTenant, roots, clientCert)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if _, err := client.GetRunSafetySnapshot(context.Background(), safetyTenant, safetyRun); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("Runtime server cert without digitalSignature KeyUsage admitted: %v", err)
	}
	if reached.Load() {
		t.Fatal("server handler served a safety read using a non-signing certificate")
	}
}
