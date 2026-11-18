package admission

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
)

const acpCapabilitySchema = "acp.guard-capability.v1"
const acpCapabilityPath = "/internal/v1/guard-capabilities:verify"

// The untrusted submission selects a capability by name/version, but only
// live ACP's original OAuth-bound Run and immutable release are authority.
type acpCapabilityRequest struct {
	SchemaVersion     string `json:"schema_version"`
	RunID             string `json:"run_id"`
	AgentID           string `json:"agent_id"`
	AgentReleaseID    string `json:"agent_release_id"`
	SessionID         string `json:"session_id"`
	CapabilityID      string `json:"capability_id"`
	CapabilityVersion string `json:"capability_version"`
	ResourceRef       string `json:"resource_ref"`
}

type acpCapabilityReceipt struct {
	SchemaVersion     string `json:"schema_version"`
	RunID             string `json:"run_id"`
	AgentID           string `json:"agent_id"`
	AgentReleaseID    string `json:"agent_release_id"`
	SessionID         string `json:"session_id"`
	CapabilityID      string `json:"capability_id"`
	CapabilityVersion string `json:"capability_version"`
	ContractSHA256    string `json:"contract_sha256"`
	PolicyRevision    string `json:"policy_revision"`
	ResourceRef       string `json:"resource_ref"`
	Status            string `json:"status"`
}

// ACPCapabilityClient is an independent, current, necessary-only authority.
// It never caches, issues, accepts or signs an execution Permit.
type ACPCapabilityClient struct {
	origin string
	tenant string
	http   *http.Client
}

func NewACPCapabilityClient(origin, expectedSPIFFE, tenant string, roots *x509.CertPool, credential tls.Certificate) (*ACPCapabilityClient, error) {
	u, err := url.Parse(origin)
	id, idErr := url.Parse(expectedSPIFFE)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.Opaque != "" || u.Path != "" || u.RawPath != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != origin ||
		idErr != nil || id.Scheme != "spiffe" || id.Host == "" || id.Port() != "" ||
		id.Path == "" || id.Path == "/" || id.User != nil || id.Opaque != "" ||
		id.RawPath != "" || id.RawQuery != "" || id.ForceQuery || id.Fragment != "" ||
		id.String() != expectedSPIFFE || !validIdentity(tenant) || roots == nil ||
		len(roots.Subjects()) == 0 || len(credential.Certificate) == 0 || credential.PrivateKey == nil {
		return nil, ErrAuthorityUnavailable
	}
	transport := &http.Transport{
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      roots.Clone(),
			Certificates: []tls.Certificate{credential},
			VerifyConnection: func(s tls.ConnectionState) error {
				if s.Version != tls.VersionTLS13 || len(s.VerifiedChains) == 0 ||
					len(s.PeerCertificates) == 0 {
					return ErrAuthorityUnavailable
				}
				leaf := s.PeerCertificates[0]
				now := time.Now()
				if leaf == nil || leaf.IsCA || len(leaf.URIs) != 1 || leaf.URIs[0] == nil ||
					leaf.URIs[0].String() != expectedSPIFFE ||
					now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
					leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
					return ErrAuthorityUnavailable
				}
				for _, usage := range leaf.ExtKeyUsage {
					if usage == x509.ExtKeyUsageServerAuth {
						return nil
					}
				}
				return ErrAuthorityUnavailable
			},
		},
	}
	return &ACPCapabilityClient{origin: origin, tenant: tenant, http: &http.Client{
		Transport: transport, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (c *ACPCapabilityClient) CloseIdleConnections() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}

func (c *ACPCapabilityClient) VerifyCapabilityAccess(
	ctx context.Context, principal Principal, run RunSafetySnapshot, submission action.ActionSubmission,
) error {
	if c == nil || c.http == nil {
		return ErrAuthorityUnavailable
	}
	if principal.ServiceID != "agent-runtime" || principal.TenantID != c.tenant ||
		run.TenantID != c.tenant || run.RunID != submission.RunID ||
		run.Status != "RUNNING" || run.BreakerState != "CLOSED" ||
		run.BreakerEpoch == 0 || run.BreakerVersion == 0 ||
		!canonicalSafetyRunID.MatchString(run.RunID) ||
		!validRuntimeIdentity(run.AgentID) || !validRuntimeIdentity(run.AgentReleaseID) ||
		!validRuntimeIdentity(run.SessionID) || submission.Validate() != nil {
		return ErrForbidden
	}
	if !bytes.Equal(submission.Arguments, []byte("{}")) ||
		!strings.HasPrefix(submission.Capability.ID, "sre.") {
		return ErrForbidden
	}
	payload := acpCapabilityRequest{
		SchemaVersion: acpCapabilitySchema,
		RunID:         run.RunID, AgentID: run.AgentID, AgentReleaseID: run.AgentReleaseID,
		SessionID: run.SessionID, CapabilityID: submission.Capability.ID,
		CapabilityVersion: submission.Capability.Version,
		ResourceRef:       submission.ResourceRef,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return ErrAuthorityUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+acpCapabilityPath, bytes.NewReader(raw))
	if err != nil {
		return ErrAuthorityUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	response, err := c.http.Do(request)
	if err != nil {
		return ErrAuthorityUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusForbidden {
		return ErrForbidden
	}
	if response.StatusCode != http.StatusOK {
		return ErrAuthorityUnavailable
	}
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || response.Header.Get("Cache-Control") != "no-store" {
		return ErrAuthorityUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(body) == 0 || len(body) > 4096 {
		return ErrAuthorityUnavailable
	}
	var verified acpCapabilityReceipt
	if json.Unmarshal(body, &verified) != nil || verified.SchemaVersion != acpCapabilitySchema ||
		verified.Status != "VERIFIED" || verified.RunID != run.RunID ||
		verified.AgentID != run.AgentID || verified.AgentReleaseID != run.AgentReleaseID ||
		verified.SessionID != run.SessionID ||
		verified.CapabilityID != submission.Capability.ID ||
		verified.CapabilityVersion != submission.Capability.Version ||
		verified.ResourceRef != submission.ResourceRef ||
		!canonicalSHA256(verified.ContractSHA256) ||
		!validRuntimeIdentity(verified.PolicyRevision) {
		return ErrAuthorityUnavailable
	}
	canonical, err := json.Marshal(verified)
	if err != nil || !bytes.Equal(canonical, bytes.TrimSpace(body)) {
		return ErrAuthorityUnavailable
	}
	return nil
}

var _ CapabilityAuthority = (*ACPCapabilityClient)(nil)
