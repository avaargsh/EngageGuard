package admission

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"io"
	"strings"
	"testing"
	"time"
)

const runtimeSPIFFE = "spiffe://platform.example/ns/agents/sa/agent-runtime"

func boundRuntime() Principal {
	return Principal{TenantID: "tenant-verified", SubjectID: "runtime-workload", ServiceID: "agent-runtime"}
}

// This builds a real CA-signed client certificate and verifies its chain with
// x509.Verify, not a synthetic VerifiedChains entry fabricated from the leaf.
func verifiedClientTLS(t *testing.T, identities ...string) *tls.ConnectionState {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "test-only-client-ca"},
		NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var uris []*url.URL
	for _, raw := range identities {
		identity, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		uris = append(uris, identity)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{CommonName: "do-not-trust-cn"},
		NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: uris,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		t.Fatal(err)
	}
	return &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: chains}
}

func configuredResolver(t *testing.T, bindings map[string]Principal) PrincipalResolver {
	t.Helper()
	resolver, err := NewSPIFFEMTLSResolver("platform.example", bindings)
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

func TestVerifiedMTLSSPIFFEMapsToImmutableTenant(t *testing.T) {
	source := map[string]Principal{runtimeSPIFFE: boundRuntime()}
	resolver := configuredResolver(t, source)
	source[runtimeSPIFFE] = Principal{TenantID: "tenant-attacker", SubjectID: "attacker", ServiceID: "agent-runtime"}
	req := httptest.NewRequest(http.MethodPost, "/v1/action-submissions", nil)
	req.TLS = verifiedClientTLS(t, runtimeSPIFFE)
	req.Header.Set("X-Tenant-ID", "tenant-attacker")
	req.Header.Set("X-Service-ID", "fake-service")
	principal, err := resolver.ResolvePrincipal(context.Background(), req)
	if err != nil || principal != boundRuntime() {
		t.Fatalf("verified SPIFFE mapping was spoofed or lost: %+v, %v", principal, err)
	}
}

func TestUnverifiedAndAmbiguousMTLSFailsClosed(t *testing.T) {
	resolver := configuredResolver(t, map[string]Principal{runtimeSPIFFE: boundRuntime()})
	good := verifiedClientTLS(t, runtimeSPIFFE)
	badLeaf := verifiedClientTLS(t, "spiffe://platform.example/ns/agents/sa/attacker")
	cases := []struct {
		name string
		state *tls.ConnectionState
	}{
		{"missing TLS", nil},
		{"no verified chain", &tls.ConnectionState{PeerCertificates: good.PeerCertificates}},
		{"peer leaf not in verified chain", &tls.ConnectionState{PeerCertificates: badLeaf.PeerCertificates, VerifiedChains: good.VerifiedChains}},
		{"unknown SPIFFE", badLeaf},
		{"wrong trust domain", verifiedClientTLS(t, "spiffe://evil.example/ns/agents/sa/agent-runtime")},
		{"multiple URI SANs", verifiedClientTLS(t, runtimeSPIFFE, "spiffe://platform.example/ns/agents/sa/attacker")},
		{"DNS URL instead of SPIFFE", verifiedClientTLS(t, "https://platform.example/ns/agents/sa/agent-runtime")},
		{"SPIFFE query injected", verifiedClientTLS(t, runtimeSPIFFE+"?tenant=attacker")},
		{"SPIFFE extra segment", verifiedClientTLS(t, runtimeSPIFFE+"/tenant-attacker")},
		{"SPIFFE escaped path", verifiedClientTLS(t, "spiffe://platform.example/ns/agents/sa/agent%2Druntime")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/action-submissions", nil)
			req.TLS = tc.state
			if _, err := resolver.ResolvePrincipal(context.Background(), req); err == nil {
				t.Fatal("untrusted or ambiguous TLS identity authenticated")
			}
		})
	}
}

func TestMTLSResolverConfigRejectsAuthorityAmbiguity(t *testing.T) {
	for _, tc := range []struct{
		domain string
		bindings map[string]Principal
	}{
		{"", map[string]Principal{runtimeSPIFFE: boundRuntime()}},
		{"Platform.Example", map[string]Principal{runtimeSPIFFE: boundRuntime()}},
		{"evil.example", map[string]Principal{runtimeSPIFFE: boundRuntime()}},
		{"platform.example", map[string]Principal{}},
		{"platform.example", map[string]Principal{"not-a-spiffe-id": boundRuntime()}},
		{"platform.example", map[string]Principal{runtimeSPIFFE: {TenantID: "tenant-a", SubjectID: "subject-a", ServiceID: "another-service"}}},
		{"platform.example", map[string]Principal{runtimeSPIFFE: {TenantID: "tenant a", SubjectID: "subject-a", ServiceID: "agent-runtime"}}},
	} {
		if _, err := NewSPIFFEMTLSResolver(tc.domain, tc.bindings); err == nil {
			t.Fatalf("invalid SPIFFE configuration accepted: domain=%q bindings=%v", tc.domain, tc.bindings)
		}
	}
}

func TestSPIFFEMTLSResolverWithAdmissionNeverUsesHeaderTenant(t *testing.T) {
	resolver := configuredResolver(t, map[string]Principal{runtimeSPIFFE: boundRuntime()})
	verifier := &fakeVerifier{}
	store := &fakeStore{}
	handler := NewHandler(resolver, verifier, store)
	req := httptest.NewRequest(http.MethodPost, "/v1/action-submissions", nil)
	req.TLS = verifiedClientTLS(t, runtimeSPIFFE)
	req.Header.Set("X-Tenant-ID", "tenant-attacker")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "run-1:step-1")
	req.Body = ioNopCloserFromString(goodBody())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated || store.tenant != "tenant-verified" {
		t.Fatalf("mTLS authority failed: status=%d store tenant=%s", rec.Code, store.tenant)
	}
}

func ioNopCloserFromString(s string) io.ReadCloser {
	return io.NopCloser(strings.NewReader(s))
}
