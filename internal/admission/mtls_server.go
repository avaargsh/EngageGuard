package admission

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// NewMTLSHTTPServer configures a strict TLS 1.3 network boundary for the
// authenticated Guard HTTP admission handler. The returned server MUST be
// started with ServeTLS or ListenAndServeTLS, never plain Serve.
//
// It requires a server certificate/key pair and an explicit client CA pool;
// system roots and optional client certificates are not permitted. The
// SPIFFE resolver remains the separate, mandatory workload-to-tenant binding,
// and the authoritative RunVerifier remains required by the handler.
// This does not issue Permits or authorize protected side effects.
func NewMTLSHTTPServer(address string, admissionHandler http.Handler, certificate tls.Certificate, trustedClientCAs *x509.CertPool) (*http.Server, error) {
	if strings.TrimSpace(address) == "" {
		return nil, errors.New("Guard mTLS listen address required")
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return nil, fmt.Errorf("invalid Guard mTLS listen address: %w", err)
	}
	if admissionHandler == nil {
		return nil, errors.New("Guard authenticated handler required")
	}
	// Never let a valid TLS connection bypass the authenticated admission
	// pipeline or use an SPIFFE identity verified by an unpinned CA.
	guardHandler, ok := admissionHandler.(*handler)
	if !ok || guardHandler == nil || guardHandler.verifier == nil || guardHandler.store == nil {
		return nil, errors.New("Guard mTLS endpoint requires a complete admission handler")
	}
	spiffeResolver, ok := guardHandler.resolver.(*SPIFFEMTLSResolver)
	if !ok || spiffeResolver == nil || len(spiffeResolver.trustedRootPins) == 0 {
		return nil, errors.New("Guard mTLS endpoint requires trust-root-pinned SPIFFE Principal binding")
	}
	if trustedClientCAs == nil || len(trustedClientCAs.Subjects()) == 0 {
		return nil, errors.New("dedicated nonempty Guard client CA pool required")
	}
	if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return nil, errors.New("Guard server certificate and private key required")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse Guard server certificate: %w", err)
	}
	now := time.Now()
	if leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, errors.New("Guard server certificate cannot authenticate a TLS 1.3 endpoint")
	}
	serverAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			serverAuth = true
			break
		}
	}
	if !serverAuth {
		return nil, errors.New("Guard server certificate missing ServerAuth usage")
	}
	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("Guard server key must support TLS signing")
	}
	leafPub, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("encode Guard server certificate key: %w", err)
	}
	keyPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(leafPub, keyPub) {
		return nil, errors.New("Guard server key does not match leaf certificate")
	}

	return &http.Server{
		Addr:    address,
		Handler: requireVerifiedClientTLS(admissionHandler),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    trustedClientCAs.Clone(),
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{"h2", "http/1.1"},
		},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}, nil
}

// requireVerifiedClientTLS is defense in depth against accidental plaintext
// http.Server.Serve, a missing client-certificate policy or a permissive
// PrincipalResolver. An X-Forwarded-Proto header never proves transport TLS.
// The configured TLS server still performs the actual client-CA validation.
func requireVerifiedClientTLS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r == nil || r.TLS == nil || !r.TLS.HandshakeComplete ||
			r.TLS.Version < tls.VersionTLS13 ||
			len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "verified mutual TLS required", http.StatusUnauthorized)
			return
		}
		leaf := r.TLS.PeerCertificates[0]
		chainValid := false
		if leaf != nil {
			for _, chain := range r.TLS.VerifiedChains {
				if len(chain) != 0 && chain[0] != nil && chain[0].Equal(leaf) {
					chainValid = true
					break
				}
			}
		}
		if !chainValid {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "verified mutual TLS required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
