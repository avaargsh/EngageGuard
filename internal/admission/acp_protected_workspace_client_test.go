package admission

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/avaargsh/EngageGuard/internal/action"
)

func protectedWorkspaceFixture() action.WorkspaceWrite {
	return action.WorkspaceWrite{
		SchemaVersion: "v0.1", TenantID: "tenant-verified",
		SubjectID: "human-subject", AgentID: "agent-1",
		OperationID:       "11111111-1111-4111-8111-111111111111",
		CapabilityID:      "workspace.write",
		ToolBindingDigest: strings.Repeat("a", 64),
		PolicyVersion:     "policy-1", Audience: "trusted-workspace-executor",
		WorkspaceID: "workspace-1", RelativePath: "docs/approved.md",
		ContentDigest: strings.Repeat("b", 64),
	}
}

func TestProtectedWorkspaceClientChecksPinnedACPAndExactResolvedAction(t *testing.T) {
	const peer = "spiffe://platform.example/ns/acp/sa/guard-capability"
	serverCert, roots := safetyServerCert(t, peer)
	ca, signer, clientRoots := newTestTransportCA(t)
	clientCert := newTestTLSLeaf(t, ca, signer, true, "spiffe://platform.example/ns/guard/sa/engageguard")
	run := trustedRuntimeRun()
	run.RunID = safetyRun
	principal := boundRuntime()
	resolved := protectedWorkspaceFixture()
	response := acpProtectedWorkspaceReceipt{
		SchemaVersion: acpProtectedWorkspaceSchema,
		RunID:         run.RunID, AgentID: run.AgentID,
		AgentReleaseID: run.AgentReleaseID, SessionID: run.SessionID,
		SubjectID: resolved.SubjectID, CapabilityID: "workspace.write",
		CapabilityVersion: "1.0.0", ContractSHA256: strings.Repeat("c", 64),
		ConfigDigest:   "sha256:" + strings.Repeat("d", 64),
		PolicyRevision: resolved.PolicyVersion, WorkspaceID: resolved.WorkspaceID,
		ToolBindingDigest: resolved.ToolBindingDigest, Audience: resolved.Audience,
		Status: "VERIFIED",
	}
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var wire atomic.Value
	wire.Store(string(raw))
	var status atomic.Int32
	status.Store(http.StatusOK)
	var calls atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != acpProtectedWorkspacePath ||
			r.Header.Get("Content-Type") != "application/json" ||
			r.Header.Get("Authorization") != "" || r.Header.Get("X-Tenant-ID") != "" {
			t.Error("protected catalog client sent unsafe authority headers")
		}
		var selector acpProtectedWorkspaceRequest
		if err := json.NewDecoder(r.Body).Decode(&selector); err != nil ||
			selector.RunID != run.RunID || selector.AgentID != run.AgentID ||
			selector.AgentReleaseID != run.AgentReleaseID || selector.SessionID != run.SessionID ||
			selector.SubjectID != resolved.SubjectID || selector.CapabilityID != "workspace.write" ||
			selector.CapabilityVersion != "1.0.0" || selector.WorkspaceID != resolved.WorkspaceID ||
			selector.ToolBindingDigest != resolved.ToolBindingDigest || selector.Audience != resolved.Audience ||
			selector.PolicyRevision != resolved.PolicyVersion {
			t.Error("protected workspace selector was not derived from trusted resolved action")
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte(wire.Load().(string)))
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: clientRoots, Certificates: []tls.Certificate{serverCert}}
	server.StartTLS()
	defer server.Close()
	client, err := NewACPProtectedWorkspaceClient(server.URL, peer, principal.TenantID, roots, clientCert)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	result, err := client.ObserveProtectedWorkspace(context.Background(), principal, run, resolved, "1.0.0")
	if err != nil || result.ContractSHA256 != response.ContractSHA256 || result.ConfigDigest != response.ConfigDigest {
		t.Fatalf("fresh source-pinned protected catalog rejected: %+v %v", result, err)
	}
	count := calls.Load()
	foreign := principal
	foreign.TenantID = "other-tenant"
	if _, err := client.ObserveProtectedWorkspace(context.Background(), foreign, run, resolved, "1.0.0"); !errors.Is(err, ErrForbidden) || calls.Load() != count {
		t.Fatalf("wrong tenant accessed ACP protected catalog: %v", err)
	}
	for _, tc := range []struct{ name, changed string }{
		{"different subject", strings.Replace(string(raw), `"subject_id":"human-subject"`, `"subject_id":"attacker"`, 1)},
		{"different binding", strings.Replace(string(raw), strings.Repeat("a", 64), strings.Repeat("e", 64), 1)},
		{"different audience", strings.Replace(string(raw), `"audience":"trusted-workspace-executor"`, `"audience":"untrusted"`, 1)},
		{"changed workspace", strings.Replace(string(raw), `"workspace_id":"workspace-1"`, `"workspace_id":"workspace-2"`, 1)},
		{"changed policy", strings.Replace(string(raw), `"policy_revision":"policy-1"`, `"policy_revision":"policy-2"`, 1)},
		{"bad digest", strings.Replace(string(raw), strings.Repeat("c", 64), "bad", 1)},
		{"permit injection", strings.Replace(string(raw), `"status":"VERIFIED"`, `"status":"VERIFIED","permit":"forged"`, 1)},
		{"duplicate fields", strings.Replace(string(raw), `"status":"VERIFIED"`, `"status":"VERIFIED","status":"VERIFIED"`, 1)},
		{"trailing", string(raw) + " {}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire.Store(tc.changed)
			if _, err := client.ObserveProtectedWorkspace(context.Background(), principal, run, resolved, "1.0.0"); !errors.Is(err, ErrAuthorityUnavailable) {
				t.Fatalf("invalid ACP protected observation accepted: %v", err)
			}
		})
	}
	wire.Store(string(raw))
	status.Store(http.StatusForbidden)
	if _, err := client.ObserveProtectedWorkspace(context.Background(), principal, run, resolved, "1.0.0"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revocation did not deny current observation: %v", err)
	}
	status.Store(http.StatusServiceUnavailable)
	if _, err := client.ObserveProtectedWorkspace(context.Background(), principal, run, resolved, "1.0.0"); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("authority outage reused previous positive result: %v", err)
	}
	status.Store(http.StatusOK)
	badPeer, err := NewACPProtectedWorkspaceClient(server.URL, "spiffe://platform.example/ns/acp/sa/other", principal.TenantID, roots, clientCert)
	if err != nil {
		t.Fatal(err)
	}
	defer badPeer.CloseIdleConnections()
	if _, err := badPeer.ObserveProtectedWorkspace(context.Background(), principal, run, resolved, "1.0.0"); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("wrong ACP server SPIFFE accepted: %v", err)
	}
}
