package executorpep

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// ErrBlocked means mandatory identity or local evidence is absent, altered,
// expired or revoked. It never proves that the provider did not run.
var ErrBlocked = errors.New("executor pre-effect checks blocked")

// ErrUnavailable means a necessary live authority or ledger source failed
// to answer. No automatic retry, cached approval or fail-open dispatch is possible.
var ErrUnavailable = errors.New("executor pre-effect authority unavailable")

var identityRE = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

// Guard-generated operation and attempt IDs must be canonical RFC 4122 variant UUIDs.
var uuidRE = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

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

// LiveAuthority must re-read current independently owned Runtime/Decision/ACP,
// approval, risk and executor-certificate revocation state. Its configuration
// must be bound to the same operator-provisioned executor identity as Binding.
// It must not trust caller claims or cache positive snapshots.
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
	// mutating a caller-owned x509 object cannot alter the trust anchor.
	root, err := x509.ParseCertificate(binding.ClientRoot.Raw)
	if err != nil || !root.IsCA || !root.BasicConstraintsValid ||
		root.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, ErrUnavailable
	}
	binding.ClientRoot = root
	return &Gate{binding: binding, ledger: ledger, live: live}, nil
}

// An executor SVID must have exactly one explicit ClientAuth EKU. An absent,
// Any, or mixed-purpose EKU is not an executor identity.
func explicitClientAuthEKU(cert *x509.Certificate) bool {
	return cert != nil && len(cert.ExtKeyUsage) == 1 &&
		cert.ExtKeyUsage[0] == x509.ExtKeyUsageClientAuth &&
		len(cert.UnknownExtKeyUsage) == 0
}

// verifiedExecutor requires a transport-verified TLS 1.3 peer certificate,
// a single exact SPIFFE URI SAN, and a chain to the operator-pinned root.
// A real network adapter MUST use tls.RequireAndVerifyClientCert.
func (g *Gate) verifiedExecutor(peer *tls.ConnectionState) bool {
	if peer == nil || !peer.HandshakeComplete || peer.Version != tls.VersionTLS13 ||
		len(peer.PeerCertificates) == 0 || len(peer.VerifiedChains) == 0 {
		return false
	}
	// Parsed ConnectionState fields are mutable by in-process callers.
	// Reparse the signed DER before consulting identity, EKU or KeyUsage.
	leaf := peer.PeerCertificates[0]
	if leaf == nil || len(leaf.Raw) == 0 {
		return false
	}
	signedLeaf, err := x509.ParseCertificate(leaf.Raw)
	if err != nil || !explicitClientAuthEKU(signedLeaf) {
		return false
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0] == nil ||
		len(signedLeaf.URIs) != 1 || signedLeaf.URIs[0] == nil ||
		leaf.URIs[0].String() != signedLeaf.URIs[0].String() ||
		!reflect.DeepEqual(leaf.ExtKeyUsage, signedLeaf.ExtKeyUsage) ||
		!reflect.DeepEqual(leaf.UnknownExtKeyUsage, signedLeaf.UnknownExtKeyUsage) ||
		leaf.KeyUsage != signedLeaf.KeyUsage {
		return false
	}
	if signedLeaf.IsCA || signedLeaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		len(signedLeaf.URIs) != 1 || signedLeaf.URIs[0] == nil ||
		len(signedLeaf.DNSNames) != 0 || len(signedLeaf.EmailAddresses) != 0 ||
		len(signedLeaf.IPAddresses) != 0 ||
		signedLeaf.URIs[0].String() != g.binding.ExecutorSPIFFEID {
		return false
	}

	transportVerified := false
	for _, chain := range peer.VerifiedChains {
		if len(chain) > 0 && chain[0] != nil && chain[0].Equal(signedLeaf) &&
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
		if cert == nil || len(cert.Raw) == 0 {
			return false
		}
		signedIntermediate, err := x509.ParseCertificate(cert.Raw)
		if err != nil {
			return false
		}
		intermediates.AddCert(signedIntermediate)
	}
	_, err = signedLeaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err == nil
}

type unavailableLedgerError interface {
	error
	Unavailable() bool
}

func isLedgerUnavailable(err error) bool {
	var unavailable unavailableLedgerError
	return errors.As(err, &unavailable) && unavailable.Unavailable()
}

// Check verifies necessary pre-effect inputs, never authorizes dispatch.
// The caller must pass TLS state only from a verified mTLS network boundary.
// Repeated reads detect some live revocations between phases, but the final
// read and a later effect are NOT atomic. An independently deployed Executor
// PEP with provider idempotency and actual effect-time enforcement remains
// REQUIRED before production mutation is enabled.
func (g *Gate) Check(
	ctx context.Context, peer *tls.ConnectionState,
	permitID, attemptID string, resolved action.WorkspaceWrite,
) error {
	if g == nil || missingAuthority(g.ledger) || missingAuthority(g.live) || ctx == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: context: %w", ErrUnavailable, err)
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

	// Require two fresh, ordered pairs. Neither admission nor a previous
	// successful ledger read is enough to satisfy the final observation.
	for range 2 {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%w: context: %w", ErrUnavailable, err)
		}
		if err := g.live.VerifyCurrent(ctx, permitID, attemptID, resolved); err != nil {
			return fmt.Errorf("%w: live authority: %w", ErrUnavailable, err)
		}
		if err := g.ledger.InspectPreEffectLedger(ctx, permitID, attemptID, resolved); err != nil {
			if isLedgerUnavailable(err) {
				return fmt.Errorf("%w: ledger inspection: %w", ErrUnavailable, err)
			}
			return fmt.Errorf("%w: ledger inspection: %w", ErrBlocked, err)
		}
	}

	// Revalidate the signed chain after all source reads so an identity that
	// expires while those reads run cannot pass. Certificate revocation is
	// part of the mandatory live authority, not x509.Verify's scope.
	if !g.verifiedExecutor(peer) {
		return ErrBlocked
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: context: %w", ErrUnavailable, err)
	}
	return nil
}
