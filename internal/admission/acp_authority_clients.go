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
	"unicode/utf8"

	"github.com/avaargsh/EngageGuard/internal/action"
)

const (
	acpCapabilitySchema                    = "acp.guard-capability.v1"
	acpCapabilityPath                      = "/internal/v1/guard-capabilities:verify"
	acpProtectedWorkspaceSchema            = "acp.guard-protected-workspace.v1"
	acpProtectedWorkspacePath              = "/internal/v1/guard-protected-workspaces:verify"
	acpReadOnlyCapabilityID                = "sre.metrics.read"
	acpReadOnlyCapabilityVersion           = "1.0.0"
	acpProtectedWorkspaceCapabilityVersion = "1.0.0"
	maxACPAuthorityReceipt                 = 4096
	maxACPAuthorityHeaders                 = 8 * 1024
)

// acpAuthorityHTTPClient is a dedicated, single-tenant Guard-to-ACP mTLS
// client. It deliberately does not accept caller transports, headers,
// forwarded identity, redirects, response compression or cached receipts.
type acpAuthorityHTTPClient struct {
	origin string
	tenant string
	http   *http.Client
}

func newACPPinnedHTTPClient(
	origin, expectedSPIFFE, tenant string, roots *x509.CertPool, credential tls.Certificate,
) (*acpAuthorityHTTPClient, error) {
	u, err := url.Parse(origin)
	identity, identityErr := url.Parse(expectedSPIFFE)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" ||
		u.User != nil || u.Opaque != "" || u.Path != "" || u.RawPath != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != origin ||
		identityErr != nil || identity.Scheme != "spiffe" || identity.Host == "" ||
		identity.Host != identity.Hostname() || identity.Path == "" || identity.Path == "/" ||
		identity.User != nil || identity.Opaque != "" || identity.RawPath != "" ||
		identity.RawQuery != "" || identity.ForceQuery || identity.Fragment != "" ||
		identity.String() != expectedSPIFFE || !validIdentity(tenant) ||
		roots == nil || len(roots.Subjects()) == 0 ||
		len(credential.Certificate) == 0 || credential.PrivateKey == nil {
		return nil, ErrAuthorityUnavailable
	}
	leaf, err := x509.ParseCertificate(credential.Certificate[0])
	if err != nil || leaf == nil || leaf.IsCA ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, ErrAuthorityUnavailable
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		len(leaf.URIs) != 1 || leaf.URIs[0] == nil {
		return nil, ErrAuthorityUnavailable
	}
	// Guard only presents a provisioned workload credential to ACP. Do not
	// send a server-only, unconstrained, expired or non-SPIFFE certificate as
	// an mTLS client identity, even if the remote listener is misconfigured.
	if _, err := validateRuntimeSPIFFE(leaf.URIs[0].String(), leaf.URIs[0].Host); err != nil {
		return nil, ErrAuthorityUnavailable
	}
	clientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
			break
		}
	}
	if !clientAuth {
		return nil, ErrAuthorityUnavailable
	}

	transport := &http.Transport{
		DisableKeepAlives:      true, // revalidate the peer certificate on every authority read
		TLSHandshakeTimeout:    3 * time.Second,
		ResponseHeaderTimeout:  5 * time.Second,
		MaxResponseHeaderBytes: maxACPAuthorityHeaders,
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      roots.Clone(),
			Certificates: []tls.Certificate{credential},
			VerifyConnection: func(state tls.ConnectionState) error {
				if state.Version != tls.VersionTLS13 ||
					len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
					return ErrAuthorityUnavailable
				}
				leaf := state.PeerCertificates[0]
				now := time.Now()
				if leaf == nil || leaf.IsCA || len(leaf.URIs) != 1 || leaf.URIs[0] == nil ||
					leaf.URIs[0].String() != expectedSPIFFE ||
					now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
					leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
					return ErrAuthorityUnavailable
				}
				// A missing EKU is unrestricted in Go's x509 verifier. ACP
				// authority requires an explicit serverAuth leaf purpose.
				for _, usage := range leaf.ExtKeyUsage {
					if usage == x509.ExtKeyUsageServerAuth {
						return nil
					}
				}
				return ErrAuthorityUnavailable
			},
		},
	}
	return &acpAuthorityHTTPClient{
		origin: strings.TrimSuffix(u.String(), "/"),
		tenant: tenant,
		http: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *acpAuthorityHTTPClient) closeIdleConnections() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}

func (c *acpAuthorityHTTPClient) postJSON(
	ctx context.Context, path string, payload any,
) (*http.Response, error) {
	if c == nil || c.http == nil || ctx == nil {
		return nil, ErrAuthorityUnavailable
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrAuthorityUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+path, bytes.NewReader(raw))
	if err != nil {
		return nil, ErrAuthorityUnavailable
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil || ctx.Err() != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, ErrAuthorityUnavailable
	}
	return response, nil
}

// readACPReceipt rejects ambiguous representation metadata before decoding.
// Header.Get is intentionally avoided because it hides duplicate values.
func readACPReceipt(response *http.Response) ([]byte, error) {
	if response == nil || response.Body == nil || response.Uncompressed ||
		len(response.Header.Values("Content-Encoding")) != 0 {
		return nil, ErrAuthorityUnavailable
	}
	contentTypes := response.Header.Values("Content-Type")
	cacheControls := response.Header.Values("Cache-Control")
	if len(contentTypes) != 1 || len(cacheControls) != 1 || cacheControls[0] != "no-store" {
		return nil, ErrAuthorityUnavailable
	}
	media, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || media != "application/json" {
		return nil, ErrAuthorityUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxACPAuthorityReceipt+1))
	if err != nil || len(raw) == 0 || len(raw) > maxACPAuthorityReceipt || !utf8.Valid(raw) {
		return nil, ErrAuthorityUnavailable
	}
	return bytes.TrimSpace(raw), nil
}

// decodeCanonicalACPReceipt rejects duplicate keys, unknown fields, trailing
// JSON values and noncanonical encodings. The ACP response is authenticated
// by mTLS but remains untrusted input at this boundary.
func decodeCanonicalACPReceipt(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrAuthorityUnavailable
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ErrAuthorityUnavailable
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrAuthorityUnavailable
	}
	return nil
}

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

// validACPAuthorityIdentifier applies the same printable-ASCII boundary to
// Runtime and ACP authority identifiers while retaining the Runtime wire
// contract's 255-byte limit.
func validACPAuthorityIdentifier(value string) bool {
	if !validRuntimeIdentity(value) {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

// ACPCapabilityClient is a fresh, read-only capability observation. It never
// caches a positive result and cannot approve or execute an action.
type ACPCapabilityClient struct {
	base *acpAuthorityHTTPClient
}

func NewACPCapabilityClient(
	origin, expectedSPIFFE, tenant string, roots *x509.CertPool, credential tls.Certificate,
) (*ACPCapabilityClient, error) {
	base, err := newACPPinnedHTTPClient(origin, expectedSPIFFE, tenant, roots, credential)
	if err != nil {
		return nil, err
	}
	return &ACPCapabilityClient{base: base}, nil
}

func (c *ACPCapabilityClient) CloseIdleConnections() {
	if c != nil && c.base != nil {
		c.base.closeIdleConnections()
	}
}

func (c *ACPCapabilityClient) VerifyCapabilityAccess(
	ctx context.Context, principal Principal, run RunSafetySnapshot, submission action.ActionSubmission,
) error {
	if c == nil || c.base == nil || c.base.http == nil || ctx == nil {
		return ErrAuthorityUnavailable
	}
	if principal.ServiceID != "agent-runtime" ||
		!validIdentity(principal.TenantID) || principal.TenantID != c.base.tenant ||
		!validIdentity(principal.SubjectID) || !validIdentity(principal.ActorID) ||
		!validIdentity(principal.WorkloadID) ||
		run.TenantID != c.base.tenant || run.RunID != submission.RunID ||
		run.Status != "RUNNING" || run.BreakerState != "CLOSED" ||
		run.BreakerEpoch == 0 || run.BreakerVersion == 0 ||
		!canonicalSafetyRunID.MatchString(run.RunID) ||
		!validACPAuthorityIdentifier(run.AgentID) ||
		!validACPAuthorityIdentifier(run.AgentReleaseID) ||
		!validACPAuthorityIdentifier(run.SessionID) || submission.Validate() != nil {
		return ErrForbidden
	}
	// This client is intentionally limited to the one reviewed read-only
	// SRE capability. A namespace prefix or a caller-provided effect label
	// cannot classify a future tool as safe.
	if submission.Capability.ID != acpReadOnlyCapabilityID ||
		submission.Capability.Version != acpReadOnlyCapabilityVersion ||
		!bytes.Equal(submission.Arguments, []byte("{}")) {
		return ErrForbidden
	}

	payload := acpCapabilityRequest{
		SchemaVersion: acpCapabilitySchema,
		RunID:         run.RunID, AgentID: run.AgentID,
		AgentReleaseID: run.AgentReleaseID, SessionID: run.SessionID,
		CapabilityID:      submission.Capability.ID,
		CapabilityVersion: submission.Capability.Version,
		ResourceRef:       submission.ResourceRef,
	}
	response, err := c.base.postJSON(ctx, acpCapabilityPath, payload)
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
	raw, err := readACPReceipt(response)
	if err != nil {
		return err
	}
	var receipt acpCapabilityReceipt
	if decodeCanonicalACPReceipt(raw, &receipt) != nil ||
		receipt.SchemaVersion != acpCapabilitySchema || receipt.Status != "VERIFIED" ||
		receipt.RunID != run.RunID || receipt.AgentID != run.AgentID ||
		receipt.AgentReleaseID != run.AgentReleaseID || receipt.SessionID != run.SessionID ||
		receipt.CapabilityID != submission.Capability.ID ||
		receipt.CapabilityVersion != submission.Capability.Version ||
		receipt.ResourceRef != submission.ResourceRef ||
		!canonicalSHA256(receipt.ContractSHA256) ||
		!validACPAuthorityIdentifier(receipt.PolicyRevision) || ctx.Err() != nil {
		return ErrAuthorityUnavailable
	}
	return nil
}

var _ CapabilityAuthority = (*ACPCapabilityClient)(nil)

type acpProtectedWorkspaceRequest struct {
	SchemaVersion     string `json:"schema_version"`
	RunID             string `json:"run_id"`
	AgentID           string `json:"agent_id"`
	AgentReleaseID    string `json:"agent_release_id"`
	SessionID         string `json:"session_id"`
	SubjectID         string `json:"subject_id"`
	CapabilityID      string `json:"capability_id"`
	CapabilityVersion string `json:"capability_version"`
	PolicyRevision    string `json:"policy_revision"`
	WorkspaceID       string `json:"workspace_id"`
	ToolBindingDigest string `json:"tool_binding_digest"`
	Audience          string `json:"audience"`
}

type acpProtectedWorkspaceReceipt struct {
	SchemaVersion     string `json:"schema_version"`
	RunID             string `json:"run_id"`
	AgentID           string `json:"agent_id"`
	AgentReleaseID    string `json:"agent_release_id"`
	SessionID         string `json:"session_id"`
	SubjectID         string `json:"subject_id"`
	CapabilityID      string `json:"capability_id"`
	CapabilityVersion string `json:"capability_version"`
	ContractSHA256    string `json:"contract_sha256"`
	ConfigDigest      string `json:"config_digest"`
	PolicyRevision    string `json:"policy_revision"`
	WorkspaceID       string `json:"workspace_id"`
	ToolBindingDigest string `json:"tool_binding_digest"`
	Audience          string `json:"audience"`
	Status            string `json:"status"`
}

// ProtectedWorkspaceObservation is a point-in-time ACP catalog observation.
// It is not approval, risk clearance, a Permit, a PEP decision or a receipt.
type ProtectedWorkspaceObservation struct {
	ContractSHA256 string
	ConfigDigest   string
	PolicyRevision string
}

// ProtectedWorkspaceAuthority is a necessary-only source contract. Consumers
// must still verify Decision provenance, current approval/revocation, risk,
// Permit claim and effect-time Executor PEP independently.
type ProtectedWorkspaceAuthority interface {
	ObserveProtectedWorkspace(
		context.Context, Principal, RunSafetySnapshot, action.ActionRequest,
	) (ProtectedWorkspaceObservation, error)
}

// ACPProtectedWorkspaceClient calls the separate protected-workspace
// observation route. It cannot issue or claim a Permit or dispatch an effect.
type ACPProtectedWorkspaceClient struct {
	base *acpAuthorityHTTPClient
}

func NewACPProtectedWorkspaceClient(
	origin, expectedSPIFFE, tenant string, roots *x509.CertPool, credential tls.Certificate,
) (*ACPProtectedWorkspaceClient, error) {
	base, err := newACPPinnedHTTPClient(origin, expectedSPIFFE, tenant, roots, credential)
	if err != nil {
		return nil, err
	}
	return &ACPProtectedWorkspaceClient{base: base}, nil
}

func (c *ACPProtectedWorkspaceClient) CloseIdleConnections() {
	if c != nil && c.base != nil {
		c.base.closeIdleConnections()
	}
}

// ObserveProtectedWorkspace derives every selector from a live Runtime
// snapshot and a trusted, canonical ActionRequest v1 resolved by Guard. The
// resolved SubjectID is the original human subject; it is never inferred
// from the Runtime service workload principal.
func (c *ACPProtectedWorkspaceClient) ObserveProtectedWorkspace(
	ctx context.Context, principal Principal, run RunSafetySnapshot, resolved action.ActionRequest,
) (ProtectedWorkspaceObservation, error) {
	var empty ProtectedWorkspaceObservation
	if c == nil || c.base == nil || c.base.http == nil || ctx == nil {
		return empty, ErrAuthorityUnavailable
	}
	if principal.ServiceID != "agent-runtime" || principal.TenantID != c.base.tenant ||
		!validIdentity(principal.SubjectID) || !validIdentity(principal.ActorID) ||
		!validIdentity(principal.WorkloadID) ||
		run.TenantID != c.base.tenant || run.Status != "RUNNING" ||
		run.BreakerState != "CLOSED" || run.BreakerEpoch == 0 ||
		run.BreakerVersion == 0 || !canonicalSafetyRunID.MatchString(run.RunID) ||
		!validIdentity(run.AgentID) || !validIdentity(run.AgentReleaseID) ||
		!validIdentity(run.SessionID) || resolved.Validate() != nil ||
		resolved.TenantID != c.base.tenant || resolved.RunID != run.RunID ||
		resolved.AgentID != run.AgentID ||
		resolved.ActorID != principal.ActorID || resolved.WorkloadID != principal.WorkloadID ||
		!canonicalSafetyRunID.MatchString(resolved.OperationID) ||
		resolved.Capability.ID != "workspace.write" ||
		resolved.Capability.Version != acpProtectedWorkspaceCapabilityVersion ||
		!canonicalSHA256(resolved.Capability.ContractSHA256) ||
		!validIdentity(resolved.SubjectID) || !validIdentity(resolved.PolicyVersion) ||
		!validIdentity(resolved.ResourceRef) || !validIdentity(resolved.Audience) ||
		!canonicalSHA256(resolved.ToolBindingDigest) {
		return empty, ErrForbidden
	}

	payload := acpProtectedWorkspaceRequest{
		SchemaVersion: acpProtectedWorkspaceSchema,
		RunID:         run.RunID, AgentID: run.AgentID,
		AgentReleaseID: run.AgentReleaseID, SessionID: run.SessionID,
		SubjectID: resolved.SubjectID, CapabilityID: resolved.Capability.ID,
		CapabilityVersion: resolved.Capability.Version, PolicyRevision: resolved.PolicyVersion,
		WorkspaceID:       resolved.ResourceRef,
		ToolBindingDigest: resolved.ToolBindingDigest, Audience: resolved.Audience,
	}
	response, err := c.base.postJSON(ctx, acpProtectedWorkspacePath, payload)
	if err != nil {
		return empty, ErrAuthorityUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusForbidden {
		return empty, ErrForbidden
	}
	if response.StatusCode != http.StatusOK {
		return empty, ErrAuthorityUnavailable
	}
	raw, err := readACPReceipt(response)
	if err != nil {
		return empty, err
	}
	var receipt acpProtectedWorkspaceReceipt
	if decodeCanonicalACPReceipt(raw, &receipt) != nil ||
		receipt.SchemaVersion != acpProtectedWorkspaceSchema || receipt.Status != "VERIFIED" ||
		receipt.RunID != run.RunID || receipt.AgentID != run.AgentID ||
		receipt.AgentReleaseID != run.AgentReleaseID || receipt.SessionID != run.SessionID ||
		receipt.SubjectID != resolved.SubjectID ||
		receipt.CapabilityID != resolved.Capability.ID ||
		receipt.CapabilityVersion != resolved.Capability.Version ||
		receipt.ContractSHA256 != resolved.Capability.ContractSHA256 ||
		receipt.PolicyRevision != resolved.PolicyVersion ||
		receipt.WorkspaceID != resolved.ResourceRef ||
		receipt.ToolBindingDigest != resolved.ToolBindingDigest ||
		receipt.Audience != resolved.Audience ||
		!canonicalSHA256(receipt.ContractSHA256) ||
		!strings.HasPrefix(receipt.ConfigDigest, "sha256:") ||
		!canonicalSHA256(strings.TrimPrefix(receipt.ConfigDigest, "sha256:")) ||
		ctx.Err() != nil {
		return empty, ErrAuthorityUnavailable
	}
	return ProtectedWorkspaceObservation{
		ContractSHA256: receipt.ContractSHA256,
		ConfigDigest:   receipt.ConfigDigest,
		PolicyRevision: receipt.PolicyRevision,
	}, nil
}

var _ CapabilityAuthority = (*ACPCapabilityClient)(nil)
var _ ProtectedWorkspaceAuthority = (*ACPProtectedWorkspaceClient)(nil)
