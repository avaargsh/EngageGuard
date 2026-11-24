package admission

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/avaargsh/EngageGuard/internal/action"
)

const (
	testACPPeer          = "spiffe://platform.example/ns/acp/sa/guard-capability"
	testGuardPeer        = "spiffe://platform.example/ns/guard/sa/engageguard"
	testACPTenant        = "tenant-1"
	testACPPath          = "/internal/v1/guard-capabilities:verify"
	testACPProtectedPath = "/internal/v1/guard-protected-workspaces:verify"
)

type capabilityReceiptFixture struct {
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

type protectedWorkspaceReceiptFixture struct {
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

func acpTestPrincipal() Principal {
	return Principal{
		TenantID: testACPTenant, SubjectID: "runtime-subject",
		ActorID: "runtime-actor", WorkloadID: "guard-runtime",
		ServiceID: "agent-runtime",
	}
}

func acpTestRun() RunSafetySnapshot {
	return RunSafetySnapshot{
		TenantID: testACPTenant, RunID: safetyRun,
		AgentID: "agent-1", AgentReleaseID: "release-1", SessionID: "session-1",
		Status: "RUNNING", BreakerState: "CLOSED", BreakerEpoch: 1, BreakerVersion: 1,
	}
}

func acpTestActionRequest() action.ActionRequest {
	return action.ActionRequest{
		SchemaVersion: "action-request.v1",
		TenantID:      testACPTenant,
		SubjectID:     "original-human-subject",
		ActorID:       "runtime-actor",
		WorkloadID:    "guard-runtime",
		AgentID:       "agent-1",
		RunID:         safetyRun,
		DecisionID:    "decision-1",
		PlanID:        "plan-1",
		PlanHash:      strings.Repeat("f", 64),
		StepID:        "step-1",
		OperationID:   "11111111-1111-4111-8111-111111111111",
		Capability: action.ActionCapabilityRef{
			ID:             "workspace.write",
			Version:        "1.0.0",
			ContractSHA256: strings.Repeat("c", 64),
		},
		ResourceRef:       "workspace-1",
		Arguments:         []byte(`{"path":"docs/approved.md","content_sha256":"` + strings.Repeat("b", 64) + `"}`),
		ToolBindingDigest: strings.Repeat("a", 64),
		PolicyVersion:     "policy-1",
		Audience:          "trusted-workspace-executor",
	}
}
func acpTestSubmission(t *testing.T) action.ActionSubmission {
	t.Helper()
	submission := testGuardSubmission(t)
	submission.RunID = safetyRun
	submission.Capability = action.ActionCapabilitySelector{ID: "sre.metrics.read", Version: "1.0.0"}
	submission.ResourceRef = "payments"
	submission.Arguments = json.RawMessage("{}")
	if err := submission.Validate(); err != nil {
		t.Fatal(err)
	}
	return submission
}

func TestACPCapabilityClientBindsFreshReadOnlySourceAndRejectsEscalation(t *testing.T) {
	serverCert, roots := safetyServerCert(t, testACPPeer)
	clientCA, signer, clientRoots := newTestTransportCA(t)
	clientCert := newTestTLSLeaf(t, clientCA, signer, true, testGuardPeer)
	principal, run, submission := acpTestPrincipal(), acpTestRun(), acpTestSubmission(t)

	receipt := capabilityReceiptFixture{
		SchemaVersion: "acp.guard-capability.v1", RunID: run.RunID,
		AgentID: run.AgentID, AgentReleaseID: run.AgentReleaseID, SessionID: run.SessionID,
		CapabilityID: submission.Capability.ID, CapabilityVersion: submission.Capability.Version,
		ContractSHA256: strings.Repeat("c", 64), PolicyRevision: "policy-1",
		ResourceRef: submission.ResourceRef, Status: "VERIFIED",
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var wire atomic.Value
	wire.Store(string(body))
	var status atomic.Int32
	status.Store(http.StatusOK)
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != testACPPath ||
			r.Header.Get("Content-Type") != "application/json" ||
			r.Header.Get("Accept-Encoding") != "identity" ||
			r.Header.Get("Cache-Control") != "no-store" ||
			r.Header.Get("Authorization") != "" || r.Header.Get("X-Tenant-ID") != "" {
			t.Error("Guard sent an unexpected ACP capability request")
		}
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil ||
			request["schema_version"] != "acp.guard-capability.v1" ||
			request["run_id"] != run.RunID || request["agent_id"] != run.AgentID ||
			request["agent_release_id"] != run.AgentReleaseID ||
			request["session_id"] != run.SessionID ||
			request["capability_id"] != submission.Capability.ID ||
			request["capability_version"] != submission.Capability.Version ||
			request["resource_ref"] != submission.ResourceRef {
			t.Error("ACP selector was not derived from the live Runtime snapshot and submission")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte(wire.Load().(string)))
	}))
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: clientRoots, Certificates: []tls.Certificate{serverCert},
	}
	server.StartTLS()
	defer server.Close()

	client, err := NewACPCapabilityClient(server.URL, testACPPeer, principal.TenantID, roots, clientCert)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()

	if err := client.VerifyCapabilityAccess(context.Background(), principal, run, submission); err != nil {
		t.Fatalf("fresh source-pinned ACP capability was denied: %v", err)
	}
	initialCalls := calls.Load()

	mutating := submission
	mutating.Capability.ID = "workspace.write"
	if err := client.VerifyCapabilityAccess(context.Background(), principal, run, mutating); !errors.Is(err, ErrForbidden) || calls.Load() != initialCalls {
		t.Fatalf("read-only capability client allowed or queried a write action: err=%v calls=%d", err, calls.Load())
	}
	foreign := principal
	foreign.TenantID = "tenant-foreign"
	if err := client.VerifyCapabilityAccess(context.Background(), foreign, run, submission); !errors.Is(err, ErrForbidden) || calls.Load() != initialCalls {
		t.Fatalf("foreign tenant reached ACP: err=%v calls=%d", err, calls.Load())
	}

	for _, tc := range []struct{ name, body string }{
		{"wrong release", strings.Replace(string(body), `"agent_release_id":"release-1"`, `"agent_release_id":"release-attacker"`, 1)},
		{"wrong policy", strings.Replace(string(body), `"policy_revision":"policy-1"`, `"policy_revision":""`, 1)},
		{"bad digest", strings.Replace(string(body), strings.Repeat("c", 64), "bad", 1)},
		{"duplicate field", strings.Replace(string(body), `"status":"VERIFIED"`, `"status":"VERIFIED","status":"VERIFIED"`, 1)},
		{"unknown permit field", strings.Replace(string(body), `"status":"VERIFIED"`, `"status":"VERIFIED","permit":"forged"`, 1)},
		{"trailing object", string(body) + " {}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire.Store(tc.body)
			if err := client.VerifyCapabilityAccess(context.Background(), principal, run, submission); !errors.Is(err, ErrAuthorityUnavailable) {
				t.Fatalf("malformed ACP capability receipt accepted: %v", err)
			}
		})
	}
	wire.Store(string(body))
	status.Store(http.StatusForbidden)
	if err := client.VerifyCapabilityAccess(context.Background(), principal, run, submission); !errors.Is(err, ErrForbidden) {
		t.Fatalf("live ACP denial was not preserved: %v", err)
	}
	status.Store(http.StatusServiceUnavailable)
	if err := client.VerifyCapabilityAccess(context.Background(), principal, run, submission); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("ACP outage reused a previous positive receipt: %v", err)
	}
	status.Store(http.StatusOK)

	wrongPeer, err := NewACPCapabilityClient(server.URL, "spiffe://platform.example/ns/acp/sa/other", principal.TenantID, roots, clientCert)
	if err != nil {
		t.Fatal(err)
	}
	defer wrongPeer.CloseIdleConnections()
	if err := wrongPeer.VerifyCapabilityAccess(context.Background(), principal, run, submission); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("wrong ACP SPIFFE peer was accepted: %v", err)
	}
}

func TestACPProtectedWorkspaceClientBindsExactResolvedActionAndNeverIssuesPermit(t *testing.T) {
	serverCert, roots := safetyServerCert(t, testACPPeer)
	clientCA, signer, clientRoots := newTestTransportCA(t)
	clientCert := newTestTLSLeaf(t, clientCA, signer, true, testGuardPeer)
	principal, run, resolved := acpTestPrincipal(), acpTestRun(), acpTestActionRequest()
	if err := resolved.Validate(); err != nil {
		t.Fatal(err)
	}

	receipt := protectedWorkspaceReceiptFixture{
		SchemaVersion: acpProtectedWorkspaceSchema,
		RunID:         run.RunID, AgentID: run.AgentID, AgentReleaseID: run.AgentReleaseID,
		SessionID: run.SessionID, SubjectID: resolved.SubjectID,
		CapabilityID: resolved.Capability.ID, CapabilityVersion: resolved.Capability.Version,
		ContractSHA256: resolved.Capability.ContractSHA256,
		ConfigDigest:   "sha256:" + strings.Repeat("d", 64),
		PolicyRevision: resolved.PolicyVersion, WorkspaceID: resolved.ResourceRef,
		ToolBindingDigest: resolved.ToolBindingDigest, Audience: resolved.Audience,
		Status: "VERIFIED",
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var wire atomic.Value
	wire.Store(string(body))
	var status atomic.Int32
	status.Store(http.StatusOK)
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != testACPProtectedPath ||
			r.Header.Get("Content-Type") != "application/json" ||
			r.Header.Get("Authorization") != "" || r.Header.Get("X-Tenant-ID") != "" {
			t.Error("Guard sent an unexpected protected-workspace request")
		}
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil ||
			request["schema_version"] != acpProtectedWorkspaceSchema ||
			request["run_id"] != run.RunID || request["agent_id"] != run.AgentID ||
			request["agent_release_id"] != run.AgentReleaseID ||
			request["session_id"] != run.SessionID || request["subject_id"] != resolved.SubjectID ||
			request["capability_id"] != resolved.Capability.ID ||
			request["capability_version"] != resolved.Capability.Version ||
			request["policy_revision"] != resolved.PolicyVersion ||
			request["workspace_id"] != resolved.ResourceRef ||
			request["tool_binding_digest"] != resolved.ToolBindingDigest ||
			request["audience"] != resolved.Audience {
			t.Error("protected selector was not derived from the trusted ActionRequest v1")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte(wire.Load().(string)))
	}))
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: clientRoots, Certificates: []tls.Certificate{serverCert},
	}
	server.StartTLS()
	defer server.Close()

	client, err := NewACPProtectedWorkspaceClient(server.URL, testACPPeer, principal.TenantID, roots, clientCert)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()

	observation, err := client.ObserveProtectedWorkspace(context.Background(), principal, run, resolved)
	if err != nil || observation.ContractSHA256 != receipt.ContractSHA256 ||
		observation.ConfigDigest != receipt.ConfigDigest || observation.PolicyRevision != receipt.PolicyRevision {
		t.Fatalf("fresh source-pinned ACP protected observation rejected: %+v %v", observation, err)
	}
	initialCalls := calls.Load()

	foreign := principal
	foreign.TenantID = "tenant-foreign"
	if _, err := client.ObserveProtectedWorkspace(context.Background(), foreign, run, resolved); !errors.Is(err, ErrForbidden) || calls.Load() != initialCalls {
		t.Fatalf("foreign tenant reached ACP protected route: err=%v calls=%d", err, calls.Load())
	}
	wrongVersion := resolved
	wrongVersion.Capability.Version = "2.0.0"
	if _, err := client.ObserveProtectedWorkspace(context.Background(), principal, run, wrongVersion); !errors.Is(err, ErrForbidden) || calls.Load() != initialCalls {
		t.Fatalf("unreviewed protected capability version reached ACP: err=%v calls=%d", err, calls.Load())
	}

	for _, tc := range []struct{ name, body string }{
		{"different subject", strings.Replace(string(body), `"subject_id":"original-human-subject"`, `"subject_id":"attacker"`, 1)},
		{"different binding", strings.Replace(string(body), strings.Repeat("a", 64), strings.Repeat("e", 64), 1)},
		{"different audience", strings.Replace(string(body), `"audience":"trusted-workspace-executor"`, `"audience":"untrusted"`, 1)},
		{"different workspace", strings.Replace(string(body), `"workspace_id":"workspace-1"`, `"workspace_id":"workspace-2"`, 1)},
		{"different policy", strings.Replace(string(body), `"policy_revision":"policy-1"`, `"policy_revision":"policy-2"`, 1)},
		{"bad contract digest", strings.Replace(string(body), strings.Repeat("c", 64), "bad", 1)},
		{"bad config digest", strings.Replace(string(body), strings.Repeat("d", 64), "bad", 1)},
		{"unknown permit field", strings.Replace(string(body), `"status":"VERIFIED"`, `"status":"VERIFIED","permit":"forged"`, 1)},
		{"duplicate field", strings.Replace(string(body), `"status":"VERIFIED"`, `"status":"VERIFIED","status":"VERIFIED"`, 1)},
		{"trailing object", string(body) + " {}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire.Store(tc.body)
			if _, err := client.ObserveProtectedWorkspace(context.Background(), principal, run, resolved); !errors.Is(err, ErrAuthorityUnavailable) {
				t.Fatalf("malformed ACP protected observation accepted: %v", err)
			}
		})
	}
	wire.Store(string(body))
	status.Store(http.StatusForbidden)
	if _, err := client.ObserveProtectedWorkspace(context.Background(), principal, run, resolved); !errors.Is(err, ErrForbidden) {
		t.Fatalf("live ACP protected-write denial was not preserved: %v", err)
	}
	status.Store(http.StatusServiceUnavailable)
	if _, err := client.ObserveProtectedWorkspace(context.Background(), principal, run, resolved); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("ACP outage reused a previous positive observation: %v", err)
	}
	status.Store(http.StatusOK)

	wrongPeer, err := NewACPProtectedWorkspaceClient(server.URL, "spiffe://platform.example/ns/acp/sa/other", principal.TenantID, roots, clientCert)
	if err != nil {
		t.Fatal(err)
	}
	defer wrongPeer.CloseIdleConnections()
	if _, err := wrongPeer.ObserveProtectedWorkspace(context.Background(), principal, run, resolved); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("wrong ACP SPIFFE peer was accepted: %v", err)
	}
}

func TestReadACPReceiptRejectsAmbiguousRepresentationMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(http.Header, *http.Response)
		body   string
	}{
		{
			name: "duplicate content type",
			mutate: func(h http.Header, _ *http.Response) {
				h.Add("Content-Type", "application/json")
			},
			body: "{}",
		},
		{
			name: "duplicate cache control",
			mutate: func(h http.Header, _ *http.Response) {
				h.Add("Cache-Control", "no-store")
			},
			body: "{}",
		},
		{
			name: "compressed representation",
			mutate: func(h http.Header, _ *http.Response) {
				h.Set("Content-Encoding", "gzip")
			},
			body: "{}",
		},
		{
			name: "transparent decompression",
			mutate: func(_ http.Header, response *http.Response) {
				response.Uncompressed = true
			},
			body: "{}",
		},
		{
			name: "wrong media type",
			mutate: func(h http.Header, _ *http.Response) {
				h.Set("Content-Type", "text/plain")
			},
			body: "{}",
		},
		{
			name: "cacheable receipt",
			mutate: func(h http.Header, _ *http.Response) {
				h.Set("Cache-Control", "public, max-age=60")
			},
			body: "{}",
		},
		{
			name:   "oversized receipt",
			mutate: func(http.Header, *http.Response) {},
			body:   strings.Repeat("x", maxACPAuthorityReceipt+1),
		},
		{
			name:   "invalid UTF-8",
			mutate: func(http.Header, *http.Response) {},
			body:   string([]byte{0xff}),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := make(http.Header)
			headers.Set("Content-Type", "application/json")
			headers.Set("Cache-Control", "no-store")
			response := &http.Response{
				Header: headers,
				Body:   io.NopCloser(strings.NewReader(tc.body)),
			}
			tc.mutate(headers, response)
			if _, err := readACPReceipt(response); !errors.Is(err, ErrAuthorityUnavailable) {
				t.Fatalf("ambiguous ACP receipt metadata accepted: %v", err)
			}
		})
	}
}
