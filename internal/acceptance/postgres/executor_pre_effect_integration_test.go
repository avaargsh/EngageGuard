package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
	"github.com/avaargsh/EngageGuard/internal/executorpep"
)

// localCurrentAuthority is intentionally a test-only stand-in for still-missing
// independently authenticated Runtime/Decision/ACP/Approval adapters.
// Success here is necessary-only local integration, never an effect grant.
type localCurrentAuthority struct {
	calls int
}

func (a *localCurrentAuthority) VerifyCurrent(_ context.Context, _, _ string, _ action.WorkspaceWrite) error {
	a.calls++
	return nil
}

func signedExecutorTestPeer(t *testing.T) (*x509.Certificate, *tls.ConnectionState) {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(71),
		Subject: pkix.Name{CommonName: "integration-only-executor-root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse("spiffe://platform.example/ns/sandbox/sa/executor")
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(72),
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{uri},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, leafKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatal(err)
	}
	return root, &tls.ConnectionState{
		HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: chains,
	}
}

func TestExecutorNecessaryGateAgainstRealPostgresClaimRevokeAndUnknown(t *testing.T) {
	for _, scenario := range []string{"claimed", "unclaimed", "revoked", "unknown", "different-content"} {
		t.Run(scenario, func(t *testing.T) {
			store, resolved, permitID := seededWorkspacePermit(t)
			ctx := context.Background()
			root, peer := signedExecutorTestPeer(t)
			live := &localCurrentAuthority{}
			gate, err := executorpep.NewGate(executorpep.Binding{
				ExecutorSPIFFEID: "spiffe://platform.example/ns/sandbox/sa/executor",
				TenantID: "tenant-a", Audience: "trusted-workspace-executor", ClientRoot: root,
			}, store, live)
			if err != nil {
				t.Fatal(err)
			}
			// A fabricated Attempt UUID is rejected while the Permit is ISSUED.
			attemptID := "10000000-0000-4000-8000-000000000002"
			if scenario != "unclaimed" {
				intent, err := store.ClaimAuthorizedIntent(ctx, permitID, resolved)
				if err != nil {
					t.Fatal(err)
				}
				attemptID = intent.AttemptID
			}
			switch scenario {
			case "revoked":
				revoked, err := store.RevokeScopedPermit(ctx, resolved.TenantID, permitID,
					"executor-gate-test-revoke", "SECURITY_RESPONSE")
				if err != nil || !revoked {
					t.Fatalf("revoke claimed Permit: %t %v", revoked, err)
				}
			case "unknown":
				if _, err := store.MarkDispatchUnknown(ctx, resolved.TenantID, resolved.OperationID,
					attemptID, "ACK_LOST"); err != nil {
					t.Fatal(err)
				}
			case "different-content":
				resolved.ContentDigest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
			}
			err = gate.Check(ctx, peer, permitID, attemptID, resolved)
			if scenario == "claimed" {
				if err != nil || live.calls != 2 {
					t.Fatalf("intact real PG claim not observed twice: err=%v live=%d", err, live.calls)
				}
			} else if !errors.Is(err, executorpep.ErrBlocked) {
				t.Fatalf("unclaimed, revoked, UNKNOWN or changed action accepted: scenario=%s err=%v", scenario, err)
			}
			// The gate only reads Guard state. No executor effect is possible.
		})
	}
}
