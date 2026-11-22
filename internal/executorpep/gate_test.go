package executorpep

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
)

const goodExecutorID = "spiffe://platform.example/ns/sandbox/sa/executor"
const testPermitID = "10000000-0000-4000-8000-000000000001"
const testAttemptID = "10000000-0000-4000-8000-000000000002"

type fakeLedger struct {
	calls  int
	failAt int
}

func (f *fakeLedger) InspectPreEffectLedger(_ context.Context, _, _ string, _ action.WorkspaceWrite) error {
	f.calls++
	if f.calls == f.failAt {
		return errors.New("revoked or UNKNOWN")
	}
	return nil
}

type fakeLive struct {
	calls  int
	failAt int
}

func (f *fakeLive) VerifyCurrent(_ context.Context, _, _ string, _ action.WorkspaceWrite) error {
	f.calls++
	if f.calls == f.failAt {
		return errors.New("live authority revoked or unavailable")
	}
	return nil
}

type testCA struct {
	cert  *x509.Certificate
	key   crypto.Signer
	roots *x509.CertPool
}

func issueTestCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: "test-only-issuer"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		IsCA:         true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return testCA{cert: cert, key: key, roots: pool}
}
func issueTestLeaf(t *testing.T, ca testCA, client bool, identity string, omitClientEKU ...bool) tls.Certificate {
	t.Helper()
	return issueTestLeafUntil(t, ca, client, identity, time.Now().Add(time.Hour), omitClientEKU...)
}

func issueTestLeafUntil(t *testing.T, ca testCA, client bool, identity string, notAfter time.Time, omitClientEKU ...bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		NotBefore:    now.Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if client {
		uri, err := url.Parse(identity)
		if err != nil {
			t.Fatal(err)
		}
		template.URIs = []*url.URL{uri}
		if len(omitClientEKU) == 0 || !omitClientEKU[0] {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
	} else {
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
func verifiedPeer(t *testing.T, ca testCA, identity string, omitClientEKU ...bool) *tls.ConnectionState {
	t.Helper()
	leaf := issueTestLeaf(t, ca, true, identity, omitClientEKU...)
	xleaf, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	chains, err := xleaf.Verify(x509.VerifyOptions{Roots: ca.roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		t.Fatal(err)
	}
	return &tls.ConnectionState{
		HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{xleaf}, VerifiedChains: chains,
	}
}
func resolvedWorkspaceWrite() action.WorkspaceWrite {
	return action.WorkspaceWrite{
		SchemaVersion: "v0.1", TenantID: "tenant-a", SubjectID: "subject-a",
		AgentID: "agent-a", OperationID: "10000000-0000-4000-8000-000000000003",
		CapabilityID:      "workspace.write",
		ToolBindingDigest: strings.Repeat("a", 64), PolicyVersion: "policy-7",
		Audience: "trusted-workspace-executor", WorkspaceID: "workspace-a",
		RelativePath: "docs/output.md", ContentDigest: strings.Repeat("b", 64),
	}
}
func makeGate(t *testing.T, root *x509.Certificate, ledger Ledger, live LiveAuthority) *Gate {
	t.Helper()
	g, err := NewGate(Binding{
		ExecutorSPIFFEID: goodExecutorID, TenantID: "tenant-a",
		Audience: "trusted-workspace-executor", ClientRoot: root,
	}, ledger, live)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestExecutorPreEffectVerifiedIdentityAndAllFreshChecks(t *testing.T) {
	ca := issueTestCA(t)
	ledger, live := &fakeLedger{}, &fakeLive{}
	g := makeGate(t, ca.cert, ledger, live)
	if err := g.Check(context.Background(), verifiedPeer(t, ca, goodExecutorID),
		testPermitID, testAttemptID, resolvedWorkspaceWrite()); err != nil {
		t.Fatalf("trusted, fresh, exact pre-effect inspection rejected: %v", err)
	}
	// Final postflight reads must be real: not a single preflight snapshot.
	if ledger.calls != 2 || live.calls != 2 {
		t.Fatalf("pre-effect gate lacked a final freshness check: ledger=%d live=%d", ledger.calls, live.calls)
	}
}
func TestExecutorPreEffectFailClosedForIdentityOrAuthorityDrift(t *testing.T) {
	ca := issueTestCA(t)
	other := issueTestCA(t)
	for _, tc := range []struct {
		name                 string
		ca                   *x509.Certificate
		peer                 *tls.ConnectionState
		action               func(*action.WorkspaceWrite)
		liveFail, ledgerFail int
	}{
		{"no TLS", ca.cert, nil, nil, 0, 0},
		{"wrong executor SPIFFE", ca.cert, verifiedPeer(t, ca, "spiffe://platform.example/ns/sandbox/sa/attacker"), nil, 0, 0},
		// Go x509.Verify permits an absent EKU as unconstrained. A protected
		// executor must require an explicit client-auth SVID usage.
		{"missing client-auth EKU", ca.cert, verifiedPeer(t, ca, goodExecutorID, true), nil, 0, 0},
		{"runtime is not executor", ca.cert, verifiedPeer(t, ca, "spiffe://platform.example/ns/agents/sa/agent-runtime"), nil, 0, 0},
		{"different pinned CA", other.cert, verifiedPeer(t, ca, goodExecutorID), nil, 0, 0},
		{"tenant drift", ca.cert, verifiedPeer(t, ca, goodExecutorID), func(a *action.WorkspaceWrite) { a.TenantID = "tenant-b" }, 0, 0},
		{"audience drift", ca.cert, verifiedPeer(t, ca, goodExecutorID), func(a *action.WorkspaceWrite) { a.Audience = "other-executor" }, 0, 0},
		{"unavailable live preflight", ca.cert, verifiedPeer(t, ca, goodExecutorID), nil, 1, 0},
		{"policy revoked after ledger read", ca.cert, verifiedPeer(t, ca, goodExecutorID), nil, 2, 0},
		{"ledger UNKNOWN/revoked at final check", ca.cert, verifiedPeer(t, ca, goodExecutorID), nil, 0, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := &fakeLedger{failAt: tc.ledgerFail}
			v := &fakeLive{failAt: tc.liveFail}
			g := makeGate(t, tc.ca, l, v)
			a := resolvedWorkspaceWrite()
			if tc.action != nil {
				tc.action(&a)
			}
			if err := g.Check(context.Background(), tc.peer, testPermitID, testAttemptID, a); err == nil {
				t.Fatal("identity or live-authority drift passed necessary gate")
			}
			if tc.name == "no TLS" || tc.name == "wrong executor SPIFFE" || tc.name == "missing client-auth EKU" || tc.name == "runtime is not executor" || tc.name == "different pinned CA" || tc.name == "tenant drift" || tc.name == "audience drift" {
				if l.calls != 0 || v.calls != 0 {
					t.Fatalf("unauthenticated caller reached sources: ledger=%d live=%d", l.calls, v.calls)
				}
			}
		})
	}
}
func TestExecutorPreEffectConstructorRequiresAllAuthorities(t *testing.T) {
	ca := issueTestCA(t)
	binding := Binding{ExecutorSPIFFEID: goodExecutorID, TenantID: "tenant-a", Audience: "trusted-workspace-executor", ClientRoot: ca.cert}
	var typedNilLedger *fakeLedger
	for _, tc := range []struct {
		name    string
		binding Binding
		ledger  Ledger
		live    LiveAuthority
	}{
		{"missing pinned CA", Binding{ExecutorSPIFFEID: goodExecutorID, TenantID: "tenant-a", Audience: "trusted-workspace-executor"}, &fakeLedger{}, &fakeLive{}},
		{"no ledger", binding, nil, &fakeLive{}},
		{"typed nil ledger", binding, typedNilLedger, &fakeLive{}},
		{"no live authority", binding, &fakeLedger{}, nil},
		{"missing identity", Binding{TenantID: "tenant-a", Audience: "trusted-workspace-executor", ClientRoot: ca.cert}, &fakeLedger{}, &fakeLive{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewGate(tc.binding, tc.ledger, tc.live); err == nil {
				t.Fatal("incomplete executor identity/authority was accepted")
			}
		})
	}
}

func TestExecutorPreEffectRejectsMalformedPeerAndNonCanonicalIdentifiers(t *testing.T) {
	ca := issueTestCA(t)
	goodPeer := verifiedPeer(t, ca, goodExecutorID)
	malformedPeer := verifiedPeer(t, ca, goodExecutorID)
	// Defensive boundary: an in-process caller can supply a malformed
	// ConnectionState. The check must fail closed, not crash the process.
	malformedPeer.PeerCertificates[0].URIs[0] = nil
	for _, tc := range []struct {
		name      string
		peer      *tls.ConnectionState
		permitID  string
		attemptID string
	}{
		{"nil SPIFFE URI must deny without panic", malformedPeer, testPermitID, testAttemptID},
		{"zero-version permit UUID must deny", goodPeer, "00000000-0000-0000-0000-000000000000", testAttemptID},
		{"non-RFC variant attempt UUID must deny", goodPeer, testPermitID, "10000000-0000-4000-0000-000000000002"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ledger, live := &fakeLedger{}, &fakeLive{}
			g := makeGate(t, ca.cert, ledger, live)
			if err := g.Check(context.Background(), tc.peer, tc.permitID, tc.attemptID,
				resolvedWorkspaceWrite()); err == nil {
				t.Fatal("malformed peer or non-canonical identifier passed the gate")
			}
			if ledger.calls != 0 || live.calls != 0 {
				t.Fatalf("malformed request reached trusted authorities: ledger=%d live=%d", ledger.calls, live.calls)
			}
		})
	}
}

func TestExecutorPreEffectRejectsMutatedParsedCertificateIdentity(t *testing.T) {
	ca := issueTestCA(t)
	// A parsed ConnectionState is mutable by Go callers. Even if its
	// VerifiedChains slice refers to the same object, the identity and
	// usage must come from signed DER, not from post-verification edits.
	subjectSpoof := verifiedPeer(t, ca, "spiffe://platform.example/ns/sandbox/sa/untrusted")
	expected, err := url.Parse(goodExecutorID)
	if err != nil {
		t.Fatal(err)
	}
	subjectSpoof.PeerCertificates[0].URIs[0] = expected

	usageSpoof := verifiedPeer(t, ca, goodExecutorID, true)
	usageSpoof.PeerCertificates[0].ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	for _, tc := range []struct {
		name string
		peer *tls.ConnectionState
	}{
		{"altered parsed SPIFFE SAN cannot impersonate signed executor", subjectSpoof},
		{"altered parsed client-auth usage cannot impersonate signed EKU", usageSpoof},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ledger, live := &fakeLedger{}, &fakeLive{}
			g := makeGate(t, ca.cert, ledger, live)
			if err := g.Check(context.Background(), tc.peer, testPermitID, testAttemptID,
				resolvedWorkspaceWrite()); err == nil {
				t.Fatal("mutated parsed certificate was accepted despite unchanged signed DER")
			}
			if ledger.calls != 0 || live.calls != 0 {
				t.Fatalf("mutated certificate reached trusted authorities: ledger=%d live=%d", ledger.calls, live.calls)
			}
		})
	}
}

// expiryWaitLive is a test authority that returns successful fresh reads
// while the executor's signed client certificate crosses its expiration.
type expiryWaitLive struct {
	expiresAt time.Time
	calls     int
}
func (f *expiryWaitLive) VerifyCurrent(ctx context.Context, _, _ string, _ action.WorkspaceWrite) error {
	f.calls++
	if f.calls == 2 {
		wait := time.Until(f.expiresAt.Add(time.Second))
		if wait > 0 {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}

func TestExecutorPreEffectDenyWhenClientCertExpiresDuringLiveChecks(t *testing.T) {
	ca := issueTestCA(t)
	// ASN.1 certificate validity has whole-second precision. Give the
	// initial signed chain a few seconds of validity, then cross the real
	// expiry deterministically during the second trusted source read.
	expiresAt := time.Now().Add(4 * time.Second).Truncate(time.Second)
	leaf := issueTestLeafUntil(t, ca, true, goodExecutorID, expiresAt)
	signedLeaf, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	chains, err := signedLeaf.Verify(x509.VerifyOptions{
		Roots: ca.roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("precondition: certificate must be initially valid: %v", err)
	}
	peer := &tls.ConnectionState{
		HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{signedLeaf}, VerifiedChains: chains,
	}
	ledger := &fakeLedger{}
	live := &expiryWaitLive{expiresAt: expiresAt}
	g := makeGate(t, ca.cert, ledger, live)
	err = g.Check(context.Background(), peer, testPermitID, testAttemptID, resolvedWorkspaceWrite())
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("client certificate expired during trusted checks; must fail closed: %v", err)
	}
	if ledger.calls != 2 || live.calls != 2 {
		t.Fatalf("precondition: both authority reads must complete before expiry postflight: live=%d ledger=%d", live.calls, ledger.calls)
	}
}

func TestExecutorPreEffectRealTLS13MTLSHandshake(t *testing.T) {
	serverCA := issueTestCA(t)
	clientCA := issueTestCA(t)
	serverCert := issueTestLeaf(t, serverCA, false, "")
	goodClient := issueTestLeaf(t, clientCA, true, goodExecutorID)
	missingClientEKU := issueTestLeaf(t, clientCA, true, goodExecutorID, true)
	wrongIdentity := issueTestLeaf(t, clientCA, true, "spiffe://platform.example/ns/sandbox/sa/other")
	wrongCA := issueTestCA(t)
	untrustedClient := issueTestLeaf(t, wrongCA, true, goodExecutorID)

	ledger, live := &fakeLedger{}, &fakeLive{}
	g := makeGate(t, clientCA.cert, ledger, live)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := g.Check(r.Context(), r.TLS, testPermitID, testAttemptID, resolvedWorkspaceWrite()); err != nil {
			http.Error(w, "blocked", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCA.roots,
	}
	srv.StartTLS()
	defer srv.Close()
	call := func(cert []tls.Certificate) (int, error) {
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: serverCA.roots, Certificates: cert,
		}}}
		resp, err := client.Get(srv.URL + "/pre-effect/inspect")
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		return resp.StatusCode, nil
	}
	status, err := call([]tls.Certificate{goodClient})
	if err != nil || status != http.StatusNoContent {
		t.Fatalf("valid real mTLS executor precheck: status=%d err=%v", status, err)
	}
	if ledger.calls != 2 || live.calls != 2 {
		t.Fatalf("network path skipped live checks: ledger=%d live=%d", ledger.calls, live.calls)
	}
	status, err = call([]tls.Certificate{missingClientEKU})
	if err != nil || status != http.StatusForbidden {
		t.Fatalf("client certificate without explicit ClientAuth EKU passed: status=%d err=%v", status, err)
	}
	status, err = call([]tls.Certificate{wrongIdentity})
	if err != nil || status != http.StatusForbidden {
		t.Fatalf("wrong SPIFFE was accepted: status=%d err=%v", status, err)
	}
	if status, err = call(nil); err == nil {
		t.Fatalf("no client cert reached authenticated handler: status=%d", status)
	}
	if status, err = call([]tls.Certificate{untrustedClient}); err == nil {
		t.Fatalf("untrusted client CA reached handler: status=%d", status)
	}
	if ledger.calls != 2 || live.calls != 2 {
		t.Fatal("bad handshake/identity reached authority checks")
	}
}
