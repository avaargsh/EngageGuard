package executorpep

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// ErrBlocked means mandatory identity or local evidence is absent, altered,
// expired or revoked. It never proves that a provider effect did not occur.
var ErrBlocked = errors.New("executor pre-effect checks blocked")

// ErrUnavailable means a necessary live authority failed to answer.
// No automatic retry, cached approval or fail-open dispatch is possible.
var ErrUnavailable = errors.New("executor pre-effect authority unavailable")

var identityRE = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
var uuidRE = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

// Binding is provisioned by the executor operator, never read from untrusted
// model output, request bodies, forwarding headers or the TLS peer itself.
type Binding struct {
	ExecutorSPIFFEID string
	TenantID         string
	Audience         string
	ClientRoot       *x509.Certificate
}

// Ledger reads Guard-owned Permit, exact Attempt and immutable Audit facts.
// A complete ledger is a NECESSARY check, not a dispatch grant.
type Ledger interface {
	InspectPreEffectLedger(context.Context, string, string, action.WorkspaceWrite) error
}

// LiveAuthority must re-read current independently owned Runtime/Decision/ACP
// policy, approval and revocation. Implementations must NOT trust caller claims
// or cache "allow" snapshots. There is no production adapter in this PR.
type LiveAuthority interface {
	VerifyCurrent(context.Context, string, string, action.WorkspaceWrite) error
}

// Gate performs no external side effects and returns no execution capability.
// It is intentionally not an exposed endpoint or deployed Executor PEP.
type Gate struct {
	binding Binding
	ledger  Ledger
	live    LiveAuthority
}

func missingAuthority(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	default:
		return false
	}
}

func validExecutorSPIFFE(value string) bool {
	uri, err := url.Parse(value)
	if err != nil || uri.Scheme != "spiffe" || uri.Host == "" ||
		uri.Host != uri.Hostname() || uri.User != nil || uri.Opaque != "" ||
		uri.RawQuery != "" || uri.Fragment != "" || uri.RawPath != "" ||
		uri.String() != value {
		return false
	}
	parts := strings.Split(uri.Path, "/")
	return len(parts) == 5 && parts[0] == "" && parts[1] == "ns" &&
		parts[3] == "sa" && identityRE.MatchString(parts[2]) &&
		identityRE.MatchString(parts[4])
}

func NewGate(binding Binding, ledger Ledger, live LiveAuthority) (*Gate, error) {
	if missingAuthority(ledger) || missingAuthority(live) ||
		!validExecutorSPIFFE(binding.ExecutorSPIFFEID) ||
		!identityRE.MatchString(binding.TenantID) ||
		!identityRE.MatchString(binding.Audience) ||
		binding.ClientRoot == nil || len(binding.ClientRoot.Raw) == 0 {
		return nil, ErrUnavailable
	}
	// Parse the operator-provided DER into private immutable state so
	// accidentally mutating a caller-owned x509 object cannot alter trust.
	root, err := x509.ParseCertificate(binding.ClientRoot.Raw)
	if err != nil || !root.IsCA ||
		root.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, ErrUnavailable
	}
	binding.ClientRoot = root
	return &Gate{binding: binding, ledger: ledger, live: live}, nil
}

// verifiedExecutor requires a *transport-verified* TLS 1.3 peer certificate,
// a single exact SPIFFE URI SAN, and a chain to the operator-pinned root.
// The independently repeated certificate verification also prevents callers
// from substituting a fabricated VerifiedChains slice in component tests.
// A real network adapter MUST use tls.RequireAndVerifyClientCert.
func (g *Gate) verifiedExecutor(peer *tls.ConnectionState) bool {
	if peer == nil || !peer.HandshakeComplete || peer.Version < tls.VersionTLS13 ||
		len(peer.PeerCertificates) == 0 || len(peer.VerifiedChains) == 0 {
		return false
	}
	leaf := peer.PeerCertificates[0]
	if leaf == nil || leaf.IsCA || len(leaf.Raw) == 0 ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		len(leaf.URIs) != 1 || len(leaf.DNSNames) != 0 ||
		len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 ||
		leaf.URIs[0].String() != g.binding.ExecutorSPIFFEID {
		return false
	}
	transportVerified := false
	for _, chain := range peer.VerifiedChains {
		if len(chain) > 0 && chain[0] != nil && chain[0].Equal(leaf) &&
			chain[len(chain)-1] != nil && chain[len(chain)-1].Equal(g.binding.ClientRoot) {
			transportVerified = true
			break
		}
	}
	if !transportVerified {
		return false
	}
	roots := x509.NewCertPool()
	roots.AddCert(g.binding.ClientRoot)
	intermediates := x509.NewCertPool()
	for _, cert := range peer.PeerCertificates[1:] {
		if cert != nil {
			intermediates.AddCert(cert)
		}
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates,
		CurrentTime: time.Now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err == nil
}

// Check verifies necessary pre-effect inputs, never authorizes dispatch.
// The caller supplies TLS state ONLY from a verified mTLS network boundary;
// an HTTP header, JSON payload or model claim is not acceptable identity.
// Repeated reads detect some live revocations between phases, but the final
// read and a later effect are NOT atomic. An independently deployed Executor
// PEP with provider idempotency, trusted Permit issuer and actual effect-time
// enforcement remains REQUIRED before production mutation is enabled.
func (g *Gate) Check(ctx context.Context, peer *tls.ConnectionState,
	permitID, attemptID string, resolved action.WorkspaceWrite) error {
	if g == nil || missingAuthority(g.ledger) || missingAuthority(g.live) ||
		ctx == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return ErrUnavailable
	}
	if !g.verifiedExecutor(peer) ||
		resolved.TenantID != g.binding.TenantID ||
		resolved.Audience != g.binding.Audience ||
		!uuidRE.MatchString(permitID) || !uuidRE.MatchString(attemptID) {
		return ErrBlocked
	}
	if _, err := action.Hash(resolved); err != nil {
		return ErrBlocked
	}
	// A live-source check is mandatory before the Guard database read.
	// Neither a previous admission snapshot nor a committed Claim is enough.
	for range 2 {
		if err := ctx.Err(); err != nil {
			return ErrUnavailable
		}
		if err := g.live.VerifyCurrent(ctx, permitID, attemptID, resolved); err != nil {
			return ErrUnavailable
		}
		if err := g.ledger.InspectPreEffectLedger(ctx, permitID, attemptID, resolved); err != nil {
			return ErrBlocked
		}
	}
	if err := ctx.Err(); err != nil {
		return ErrUnavailable
	}
	return nil
}
