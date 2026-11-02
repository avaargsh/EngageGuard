package admission

import (
	"context"
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
type SPIFFEMTLSResolver struct {
	trustDomain string
	bindings    map[string]Principal
}

var trustDomainRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)

func NewSPIFFEMTLSResolver(trustDomain string, bindings map[string]Principal) (*SPIFFEMTLSResolver, error) {
	if !trustDomainRE.MatchString(trustDomain) || strings.Contains(trustDomain, "..") ||
		strings.HasPrefix(trustDomain, "-") || strings.Contains(trustDomain, ".-") ||
		strings.Contains(trustDomain, "-.") || len(bindings) == 0 {
		return nil, errors.New("invalid SPIFFE trust domain or empty bindings")
	}
	copyBindings := make(map[string]Principal, len(bindings))
	for identity, principal := range bindings {
		if _, err := validateRuntimeSPIFFE(identity, trustDomain); err != nil ||
			!validIdentity(principal.TenantID) || !validIdentity(principal.SubjectID) ||
			principal.ServiceID != "agent-runtime" {
			return nil, errors.New("invalid SPIFFE principal binding")
		}
		copyBindings[identity] = principal
	}
	return &SPIFFEMTLSResolver{trustDomain: trustDomain, bindings: copyBindings}, nil
}

func validateRuntimeSPIFFE(identity, trustDomain string) (*url.URL, error) {
	uri, err := url.Parse(identity)
	if err != nil || uri.Scheme != "spiffe" || uri.Host != trustDomain ||
		uri.User != nil || uri.Opaque != "" || uri.RawQuery != "" || uri.Fragment != "" ||
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
		len(state.PeerCertificates) != 1 || len(state.VerifiedChains) == 0 {
		return Principal{}, ErrUnauthenticated
	}
	leaf := state.PeerCertificates[0]
	if leaf == nil || leaf.IsCA || len(leaf.Raw) == 0 || len(leaf.URIs) != 1 {
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
		if len(chain) > 0 && chain[0] != nil && chain[0].Equal(leaf) {
			verified = true
			break
		}
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
