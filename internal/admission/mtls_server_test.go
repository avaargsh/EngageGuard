package admission

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newTestTransportCA(t *testing.T) (*x509.Certificate, crypto.Signer, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "transport-test-only-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return parsed, key, roots
}

func newTestTLSLeaf(t *testing.T, ca *x509.Certificate, signer crypto.Signer, client bool, spiffeID string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if client {
		identity, err := url.Parse(spiffeID)
		if err != nil {
			t.Fatal(err)
		}
		cert.URIs = []*url.URL{identity}
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		cert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestVerifiedMTLSHTTPServerRejectsMissingTrustMaterial(t *testing.T) {
	serverCA, serverKey, _ := newTestTransportCA(t)
	serverCert := newTestTLSLeaf(t, serverCA, serverKey, false, "")
	clientCA, _, clientRoots := newTestTransportCA(t)
	resolver, err := NewSPIFFEMTLSResolver("platform.example",
		map[string]Principal{runtimeSPIFFE: boundRuntime()}, clientCA)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(resolver, &fakeVerifier{}, &fakeStore{})
	for _, tc := range []struct {
		name    string
		addr    string
		handler http.Handler
		cert    tls.Certificate
		roots   *x509.CertPool
	}{
		{"no handler", "127.0.0.1:0", nil, serverCert, clientRoots},
		{"empty bind address", "", handler, serverCert, clientRoots},
		{"no server certificate", "127.0.0.1:0", handler, tls.Certificate{}, clientRoots},
		{"missing client roots", "127.0.0.1:0", handler, serverCert, nil},
		{"empty client roots", "127.0.0.1:0", handler, serverCert, x509.NewCertPool()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if server, err := NewMTLSHTTPServer(tc.addr, tc.handler, tc.cert, tc.roots); err == nil {
				_ = server.Close()
				t.Fatal("accepted incomplete mTLS security configuration")
			}
		})
	}
}

func TestMTLSHTTPServerRealHandshakeAndAdmission(t *testing.T) {
	serverCA, serverKey, serverRoots := newTestTransportCA(t)
	serverCert := newTestTLSLeaf(t, serverCA, serverKey, false, "")
	clientCA, clientCAKey, clientRoots := newTestTransportCA(t)
	goodCert := newTestTLSLeaf(t, clientCA, clientCAKey, true, runtimeSPIFFE)
	unknownCert := newTestTLSLeaf(t, clientCA, clientCAKey, true, "spiffe://platform.example/ns/agents/sa/unknown")
	otherCA, otherCAKey, _ := newTestTransportCA(t)
	untrustedCert := newTestTLSLeaf(t, otherCA, otherCAKey, true, runtimeSPIFFE)
	// The TLS transport accepts either trusted CA, but the SPIFFE trust-domain
	// binding must reject a forged same-URI certificate from the other CA.
	spoofCA, spoofKey, _ := newTestTransportCA(t)
	spoofCert := newTestTLSLeaf(t, spoofCA, spoofKey, true, runtimeSPIFFE)
	mixedClientRoots := clientRoots.Clone()
	mixedClientRoots.AddCert(spoofCA)

	resolver, err := NewSPIFFEMTLSResolver("platform.example",
		map[string]Principal{runtimeSPIFFE: boundRuntime()}, clientCA)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{}
	verifier := &fakeVerifier{}
	server, err := NewMTLSHTTPServer("127.0.0.1:0", NewHandler(resolver, verifier, store), serverCert, mixedClientRoots)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.ServeTLS(ln, "", "") }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	if server.TLSConfig.MinVersion != tls.VersionTLS13 || server.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("server configuration allows unauthenticated or TLS 1.2 clients")
	}
	endpoint := "https://" + ln.Addr().String() + "/v1/action-submissions"
	request := func(cert []tls.Certificate, maxTLS uint16) (*http.Response, error) {
		t.Helper()
		client := &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs: serverRoots, Certificates: cert,
				MinVersion: tls.VersionTLS12, MaxVersion: maxTLS,
			}},
		}
		req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(goodBody()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "network-handshake-key")
		req.Header.Set("X-Tenant-ID", "tenant-attacker")
		return client.Do(req)
	}

	response, err := request([]tls.Certificate{goodCert}, 0)
	if err != nil {
		t.Fatalf("trusted mTLS client rejected: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusCreated || store.calls != 1 || store.tenant != boundRuntime().TenantID ||
		verifier.calls != 1 {
		t.Fatalf("authenticated Runtime submission missing: status=%d store=%+v verifier=%d",
			response.StatusCode, store, verifier.calls)
	}

	// A valid certificate from the trusted client CA is not sufficient unless
	// the URI SAN is bound to the runtime Principal.
	response, err = request([]tls.Certificate{unknownCert}, 0)
	if err != nil {
		t.Fatalf("unknown SPIFFE client should reach resolver after TLS verification: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || store.calls != 1 {
		t.Fatalf("unbound SPIFFE identity reached store: code=%d calls=%d", response.StatusCode, store.calls)
	}
	// TLS accepts this second issuer, but its SPIFFE identity is not
	// authorized to speak for the pinned trust domain.
	response, err = request([]tls.Certificate{spoofCert}, 0)
	if err != nil {
		t.Fatalf("spoofed SPIFFE client should reach resolver after TLS verification: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || store.calls != 1 || verifier.calls != 1 {
		t.Fatalf("mixed-CA forged SPIFFE reached admission: status=%d store=%d verifier=%d",
			response.StatusCode, store.calls, verifier.calls)
	}

	// These must fail before HTTP admission runs.
	for _, tc := range []struct {
		name  string
		certs []tls.Certificate
		max   uint16
	}{
		{"missing client certificate", nil, 0},
		{"untrusted client issuer", []tls.Certificate{untrustedCert}, 0},
		{"TLS 1.2", []tls.Certificate{goodCert}, tls.VersionTLS12},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response, err := request(tc.certs, tc.max)
			if err == nil {
				_ = response.Body.Close()
				t.Fatalf("insecure client accepted over actual TLS handshake with status=%d", response.StatusCode)
			}
			if store.calls != 1 {
				t.Fatalf("insecure handshake executed acceptance store: calls=%d", store.calls)
			}
		})
	}
}

// A misconfigured deployment might call Serve instead of ServeTLS. The
// transport constructor must still refuse plaintext independently of a
// resolver that accidentally returns a privileged Principal.
func TestMTLSHTTPServerPlainServeCannotReachAdmission(t *testing.T) {
	serverCA, serverKey, _ := newTestTransportCA(t)
	serverCert := newTestTLSLeaf(t, serverCA, serverKey, false, "")
	clientCA, _, clientRoots := newTestTransportCA(t)
	resolver, err := NewSPIFFEMTLSResolver("platform.example",
		map[string]Principal{runtimeSPIFFE: boundRuntime()}, clientCA)
	if err != nil {
		t.Fatal(err)
	}
	verifier := &fakeVerifier{}
	store := &fakeStore{}
	server, err := NewMTLSHTTPServer("127.0.0.1:0", NewHandler(resolver, verifier, store), serverCert, clientRoots)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(ln) }() // intentionally unsafe deployment mode
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	req, err := http.NewRequest(http.MethodPost,
		"http://"+ln.Addr().String()+"/v1/action-submissions", strings.NewReader(goodBody()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "plaintext-should-never-be-accepted")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Tenant-ID", "tenant-verified")
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || store.calls != 0 || verifier.calls != 0 {
		t.Fatalf("plaintext Serve bypassed mTLS transport: status=%d store=%d verifier=%d",
			response.StatusCode, store.calls, verifier.calls)
	}
}

// Security RED: production TLS ingress must not accept an unpinned SPIFFE
// identity resolver or a generic handler that bypasses Guard admission.
func TestMTLSHTTPServerRejectsUnpinnedOrUnboundAdmission(t *testing.T) {
	serverCA, serverKey, _ := newTestTransportCA(t)
	serverCert := newTestTLSLeaf(t, serverCA, serverKey, false, "")
	_, _, clientRoots := newTestTransportCA(t)

	unpinned := NewHandler(
		configuredResolver(t, map[string]Principal{runtimeSPIFFE: boundRuntime()}),
		&fakeVerifier{}, &fakeStore{},
	)
	if server, err := NewMTLSHTTPServer("127.0.0.1:0", unpinned, serverCert, clientRoots); err == nil {
		_ = server.Close()
		t.Fatal("accepted network admission without a trust-root-pinned SPIFFE resolver")
	}

	arbitraryHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	if server, err := NewMTLSHTTPServer("127.0.0.1:0", arbitraryHandler, serverCert, clientRoots); err == nil {
		_ = server.Close()
		t.Fatal("accepted arbitrary handler without mandatory Principal and Run verification")
	}
}

// Defense-in-depth: plaintext is denied even when lower layers are deliberately
// permissive, not just because the SPIFFE resolver would reject absent TLS.
func TestVerifiedClientTLSGateRejectsPermissiveResolver(t *testing.T) {
	verifier := &fakeVerifier{}
	store := &fakeStore{}
	gate := requireVerifiedClientTLS(NewHandler(
		&fakeResolver{principal: boundRuntime()}, verifier, store))
	req := httptest.NewRequest(http.MethodPost, "/v1/action-submissions",
		strings.NewReader(goodBody()))
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Tenant-ID", "tenant-verified")
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || verifier.calls != 0 || store.calls != 0 {
		t.Fatalf("permissive resolver bypassed outer TLS gate: status=%d verifier=%d store=%d",
			rec.Code, verifier.calls, store.calls)
	}
}
