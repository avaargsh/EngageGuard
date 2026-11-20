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
	"strings"

	"github.com/avaargsh/EngageGuard/internal/action"
)

const acpProtectedWorkspaceSchema = "acp.guard-protected-workspace.v1"
const acpProtectedWorkspacePath = "/internal/v1/guard-protected-workspaces:verify"

// Exactly one trusted, scope-limited workspace.write catalog selector. The
// original ACP source owns policy, Release digest, Run/Session and subject.
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

// ProtectedWorkspaceObservation is a read-only, time-of-check ACP catalog
// observation. It is NOT a Permit, risk/approval decision, executor or
// authorization to perform a side effect.
type ProtectedWorkspaceObservation struct {
	ContractSHA256 string
	ConfigDigest   string
	PolicyRevision string
}

// ACPProtectedWorkspaceClient reuses the already pinned, distinct Guard->ACP
// TLS1.3 client, but calls a separate explicitly effectful catalog schema.
// It never replaces read-only SRE CapabilityAuthority/DecisionPlanAuthority.
type ACPProtectedWorkspaceClient struct {
	base *ACPCapabilityClient
}

func NewACPProtectedWorkspaceClient(
	origin, expectedSPIFFE, tenant string, roots *x509.CertPool, credential tls.Certificate,
) (*ACPProtectedWorkspaceClient, error) {
	client, err := NewACPCapabilityClient(origin, expectedSPIFFE, tenant, roots, credential)
	if err != nil {
		return nil, err
	}
	return &ACPProtectedWorkspaceClient{base: client}, nil
}

func (c *ACPProtectedWorkspaceClient) CloseIdleConnections() {
	if c != nil && c.base != nil {
		c.base.CloseIdleConnections()
	}
}

// ObserveProtectedWorkspace rederives the request from independently
// authenticated Runtime state and a trusted, canonical resolved write Action.
// The Runtime mTLS service principal can differ from the *human subject*
// originally admitted by ACP. The resolved human subject must be obtained
// from ACP/Guard policy, never inferred from the service workload's actor ID.
//
// ACP currently only returns a read-only necessary catalog observation. The
// caller MUST separately verify ActionHash+signed approval, fresh revocation,
// risk, Decision/Plan and Run safety and obtain a one-time Guard Permit. This
// function itself can never issue/claim a Permit or dispatch an executor.
func (c *ACPProtectedWorkspaceClient) ObserveProtectedWorkspace(
	ctx context.Context, principal Principal, run RunSafetySnapshot,
	resolved action.WorkspaceWrite, capabilityVersion string,
) (ProtectedWorkspaceObservation, error) {
	var empty ProtectedWorkspaceObservation
	if c == nil || c.base == nil || c.base.http == nil {
		return empty, ErrAuthorityUnavailable
	}
	if principal.ServiceID != "agent-runtime" || principal.TenantID != c.base.tenant ||
		run.TenantID != c.base.tenant || run.Status != "RUNNING" ||
		run.BreakerState != "CLOSED" || run.BreakerEpoch == 0 ||
		run.BreakerVersion == 0 || !canonicalSafetyRunID.MatchString(run.RunID) ||
		resolved.Validate() != nil || resolved.TenantID != c.base.tenant ||
		resolved.AgentID != run.AgentID || resolved.SubjectID == "" ||
		!validRuntimeIdentity(run.AgentReleaseID) || !validRuntimeIdentity(run.SessionID) ||
		capabilityVersion != "1.0.0" {
		return empty, ErrForbidden
	}
	payload := acpProtectedWorkspaceRequest{
		SchemaVersion: acpProtectedWorkspaceSchema,
		RunID:         run.RunID, AgentID: run.AgentID,
		AgentReleaseID: run.AgentReleaseID, SessionID: run.SessionID,
		SubjectID: resolved.SubjectID, CapabilityID: resolved.CapabilityID,
		CapabilityVersion: capabilityVersion, PolicyRevision: resolved.PolicyVersion,
		WorkspaceID:       resolved.WorkspaceID,
		ToolBindingDigest: resolved.ToolBindingDigest, Audience: resolved.Audience,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return empty, ErrAuthorityUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base.origin+acpProtectedWorkspacePath, bytes.NewReader(raw))
	if err != nil {
		return empty, ErrAuthorityUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	response, err := c.base.http.Do(request)
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
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/json" ||
		response.Header.Get("Cache-Control") != "no-store" {
		return empty, ErrAuthorityUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(body) == 0 || len(body) > 4096 {
		return empty, ErrAuthorityUnavailable
	}
	var proof acpProtectedWorkspaceReceipt
	if json.Unmarshal(body, &proof) != nil ||
		proof.SchemaVersion != acpProtectedWorkspaceSchema || proof.Status != "VERIFIED" ||
		proof.RunID != run.RunID || proof.AgentID != run.AgentID ||
		proof.AgentReleaseID != run.AgentReleaseID || proof.SessionID != run.SessionID ||
		proof.SubjectID != resolved.SubjectID ||
		proof.CapabilityID != resolved.CapabilityID ||
		proof.CapabilityVersion != capabilityVersion ||
		proof.PolicyRevision != resolved.PolicyVersion ||
		proof.WorkspaceID != resolved.WorkspaceID ||
		proof.ToolBindingDigest != resolved.ToolBindingDigest ||
		proof.Audience != resolved.Audience ||
		!canonicalSHA256(proof.ContractSHA256) ||
		!strings.HasPrefix(proof.ConfigDigest, "sha256:") ||
		!canonicalSHA256(strings.TrimPrefix(proof.ConfigDigest, "sha256:")) {
		return empty, ErrAuthorityUnavailable
	}
	canonical, err := json.Marshal(proof)
	if err != nil || !bytes.Equal(canonical, bytes.TrimSpace(body)) {
		return empty, ErrAuthorityUnavailable
	}
	return ProtectedWorkspaceObservation{
		ContractSHA256: proof.ContractSHA256, ConfigDigest: proof.ConfigDigest,
		PolicyRevision: proof.PolicyRevision,
	}, nil
}
