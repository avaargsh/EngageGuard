package admission

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// SPIFFEMTLSResolver pins an authenticated workload to an operator-supplied
// tenant and subject; it never reads identity claims from HTTP headers.
// A network deployment must pin the trust-domain CA roots as well as identity.
type SPIFFEMTLSResolver struct {
	trustDomain     string
	bindings        map[string]Principal
	trustedRootPins map[[32]byte]struct{}
}

var trustDomainRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)

// Without trustedRoots, the resolver is only suitable for isolated component
// tests. NewMTLSHTTPServer refuses unpinned resolvers at its network boundary.
func NewSPIFFEMTLSResolver(trustDomain string, bindings map[string]Principal, trustedRoots ...*x509.Certificate) (*SPIFFEMTLSResolver, error) {
	if !trustDomainRE.MatchString(trustDomain) || strings.Contains(trustDomain, "..") ||
		strings.HasPrefix(trustDomain, "-") || strings.Contains(trustDomain, ".-") ||
		strings.Contains(trustDomain, "-.") || len(bindings) == 0 {
		return nil, errors.New("invalid SPIFFE trust domain or empty bindings")
	}
	copyBindings := make(map[string]Principal, len(bindings))
	for identity, principal := range bindings {
		if _, err := validateRuntimeSPIFFE(identity, trustDomain); err != nil ||
			!validIdentity(principal.TenantID) || !validIdentity(principal.SubjectID) ||
			!validIdentity(principal.ActorID) || !validIdentity(principal.WorkloadID) ||
			principal.ServiceID != "agent-runtime" {
			return nil, errors.New("invalid SPIFFE principal binding")
		}
		copyBindings[identity] = principal
	}
	rootPins := make(map[[32]byte]struct{}, len(trustedRoots))
	for _, root := range trustedRoots {
		if root == nil || len(root.Raw) == 0 || !root.IsCA ||
			root.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("invalid SPIFFE trust-domain root certificate")
		}
		rootPins[sha256.Sum256(root.Raw)] = struct{}{}
	}
	return &SPIFFEMTLSResolver{trustDomain: trustDomain, bindings: copyBindings, trustedRootPins: rootPins}, nil
}

func validateRuntimeSPIFFE(identity, trustDomain string) (*url.URL, error) {
	uri, err := url.Parse(identity)
	if err != nil || uri.Scheme != "spiffe" || uri.Host != trustDomain ||
		uri.User != nil || uri.Opaque != "" || uri.RawQuery != "" || uri.ForceQuery || uri.Fragment != "" ||
		uri.RawPath != "" || uri.String() != identity {
		return nil, ErrUnauthenticated
	}
	parts := strings.Split(uri.Path, "/")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "ns" || parts[3] != "sa" ||
		!validIdentity(parts[2]) || !validIdentity(parts[4]) {
		return nil, ErrUnauthenticated
	}
	return uri, nil
}

func (s *SPIFFEMTLSResolver) ResolvePrincipal(_ context.Context, request *http.Request) (Principal, error) {
	if s == nil || request == nil || request.TLS == nil {
		return Principal{}, ErrUnauthenticated
	}
	state := request.TLS
	if !state.HandshakeComplete || state.Version < tls.VersionTLS13 ||
		len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return Principal{}, ErrUnauthenticated
	}
	leaf := state.PeerCertificates[0]
	if leaf == nil || leaf.IsCA || len(leaf.Raw) == 0 || len(leaf.URIs) != 1 ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		leaf.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return Principal{}, ErrUnauthenticated
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return Principal{}, ErrUnauthenticated
	}
	// The server must require and verify client certificates against dedicated
	// ClientCAs; PeerCertificates without a verified chain provide no authority.
	verified := false
	for _, chain := range state.VerifiedChains {
		if len(chain) == 0 || chain[0] == nil || !chain[0].Equal(leaf) {
			continue
		}
		if len(s.trustedRootPins) > 0 {
			root := chain[len(chain)-1]
			if root == nil || len(root.Raw) == 0 {
				continue
			}
			if _, ok := s.trustedRootPins[sha256.Sum256(root.Raw)]; !ok {
				continue
			}
		}
		verified = true
		break
	}
	if !verified {
		return Principal{}, ErrUnauthenticated
	}
	clientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth {
		return Principal{}, ErrUnauthenticated
	}
	identity := leaf.URIs[0].String()
	if _, err := validateRuntimeSPIFFE(identity, s.trustDomain); err != nil {
		return Principal{}, ErrUnauthenticated
	}
	principal, known := s.bindings[identity]
	if !known {
		return Principal{}, ErrUnauthenticated
	}
	return principal, nil
}
