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
		Subject: pkix.Name{CommonName: "transport-test-only-ca"},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
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
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
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
	_, _, clientRoots := newTestTransportCA(t)
	resolver := configuredResolver(t, map[string]Principal{runtimeSPIFFE: boundRuntime()})
	handler := NewHandler(resolver, &fakeVerifier{}, &fakeStore{})
	for _, tc := range []struct {
		name string
		addr string
		handler http.Handler
		cert tls.Certificate
		roots *x509.CertPool
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

	resolver := configuredResolver(t, map[string]Principal{runtimeSPIFFE: boundRuntime()})
	store := &fakeStore{}
	verifier := &fakeVerifier{}
	server, err := NewMTLSHTTPServer("127.0.0.1:0", NewHandler(resolver, verifier, store), serverCert, clientRoots)
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
			Timeout: 3*time.Second,
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
	// These must fail before HTTP admission runs.
	for _, tc := range []struct {
		name string
		certs []tls.Certificate
		max uint16
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
