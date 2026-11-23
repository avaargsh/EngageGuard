package admission

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const runtimeSafetySchema = "runtime.run-safety.v1"
const maxSafetyResponse = 8192

var canonicalSafetyRunID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// RuntimeRunSafetyClient implements the existing authority seam. It only
// reads fresh local safety state; this is not proof of plan/capability
// authority, authorization, permit issuance, or external effect.
type RuntimeRunSafetyClient struct {
	origin string
	tenant string
	http   *http.Client
}

// The provisioned credential belongs to the trusted Guard service, never
// an Agent or Sandbox. A single tenant is explicit until delegated service
// identities are ratified. Server chain, DNS/IP SAN and exact SPIFFE URI
// must all validate; no caller-supplied HTTP transport or redirect.
func NewRuntimeRunSafetyClient(origin, expectedSPIFFE, tenant string, roots *x509.CertPool, cert tls.Certificate) (*RuntimeRunSafetyClient, error) {
	u, err := url.Parse(origin)
	identity, idErr := url.Parse(expectedSPIFFE)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.Opaque != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		idErr != nil || identity == nil || !validIdentity(tenant) ||
		roots == nil || len(roots.Subjects()) == 0 || len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		return nil, ErrAuthorityUnavailable
	}
	if _, err := validateRuntimeSPIFFE(expectedSPIFFE, identity.Host); err != nil {
		return nil, ErrAuthorityUnavailable
	}
	if _, err := x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return nil, ErrAuthorityUnavailable
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      roots.Clone(),
			Certificates: []tls.Certificate{cert},
			VerifyConnection: func(state tls.ConnectionState) error {
				if state.Version < tls.VersionTLS13 || len(state.PeerCertificates) == 0 ||
					len(state.VerifiedChains) == 0 {
					return ErrAuthorityUnavailable
				}
				leaf := state.PeerCertificates[0]
				if leaf == nil || leaf.IsCA || len(leaf.URIs) != 1 || leaf.URIs[0] == nil ||
					leaf.URIs[0].String() != expectedSPIFFE || time.Now().Before(leaf.NotBefore) ||
					!time.Now().Before(leaf.NotAfter) {
					return ErrAuthorityUnavailable
				}
				// Go x509 treats a missing EKU as unrestricted. This authority
				// demands an explicit serverAuth purpose in the signed leaf.
				for _, eku := range leaf.ExtKeyUsage {
					if eku == x509.ExtKeyUsageServerAuth {
						return nil
					}
				}
				return ErrAuthorityUnavailable
			},
		},
		DisableKeepAlives:     true, // require fresh cert verification on each read
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
	}
	return &RuntimeRunSafetyClient{
		origin: strings.TrimSuffix(u.String(), "/"),
		tenant: tenant,
		http: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *RuntimeRunSafetyClient) CloseIdleConnections() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}

func (c *RuntimeRunSafetyClient) GetRunSafetySnapshot(ctx context.Context, tenant, id string) (RunSafetySnapshot, error) {
	var empty RunSafetySnapshot
	if c == nil || c.http == nil {
		return empty, ErrAuthorityUnavailable
	}
	if tenant != c.tenant || !canonicalSafetyRunID.MatchString(id) {
		return empty, ErrForbidden
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+"/internal/v1/runs/"+id+"/safety", nil)
	if err != nil {
		return empty, ErrAuthorityUnavailable
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	res, err := c.http.Do(req)
	if err != nil {
		return empty, ErrAuthorityUnavailable
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusForbidden:
		return empty, ErrForbidden
	case http.StatusOK:
	default:
		return empty, ErrAuthorityUnavailable
	}
	media, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || res.Header.Get("Cache-Control") != "no-store" {
		return empty, ErrAuthorityUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxSafetyResponse+1))
	if err != nil || len(raw) > maxSafetyResponse || !utf8.Valid(raw) {
		return empty, ErrAuthorityUnavailable
	}
	snapshot, err := decodeSafetySnapshot(raw)
	if err != nil {
		return empty, ErrAuthorityUnavailable
	}
	if snapshot.TenantID != tenant || snapshot.RunID != id ||
		!validRuntimeIdentity(snapshot.AgentID) || !validRuntimeIdentity(snapshot.AgentReleaseID) ||
		!validRuntimeIdentity(snapshot.SessionID) || snapshot.Status != "RUNNING" ||
		snapshot.BreakerState != "CLOSED" || snapshot.BreakerEpoch == 0 || snapshot.BreakerVersion == 0 {
		return empty, ErrForbidden
	}
	return snapshot, nil
}

func decodeSafetySnapshot(raw []byte) (RunSafetySnapshot, error) {
	var result RunSafetySnapshot
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return result, ErrAuthorityUnavailable
	}
	var version string
	seen := make(map[string]bool, 10)
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return RunSafetySnapshot{}, ErrAuthorityUnavailable
		}
		seen[key] = true
		var dest any
		switch key {
		case "schema_version":
			dest = &version
		case "tenant_id":
			dest = &result.TenantID
		case "run_id":
			dest = &result.RunID
		case "agent_id":
			dest = &result.AgentID
		case "agent_release_id":
			dest = &result.AgentReleaseID
		case "session_id":
			dest = &result.SessionID
		case "status":
			dest = &result.Status
		case "breaker_state":
			dest = &result.BreakerState
		case "breaker_epoch":
			dest = &result.BreakerEpoch
		case "breaker_version":
			dest = &result.BreakerVersion
		default:
			return RunSafetySnapshot{}, ErrAuthorityUnavailable
		}
		if err := d.Decode(dest); err != nil {
			return RunSafetySnapshot{}, ErrAuthorityUnavailable
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(seen) != 10 || version != runtimeSafetySchema {
		return RunSafetySnapshot{}, ErrAuthorityUnavailable
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return RunSafetySnapshot{}, ErrAuthorityUnavailable
	}
	return result, nil
}

var _ RunSafetyAuthority = (*RuntimeRunSafetyClient)(nil)
