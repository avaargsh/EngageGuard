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

const acpCapabilityPeer = "spiffe://platform.example/ns/acp/sa/guard-capability"

func TestACPCapabilityClientRequiresLiveExactReleaseAndTLSIdentity(t *testing.T) {
	serverCert, roots := safetyServerCert(t, acpCapabilityPeer)
	ca, signer, clientRoots := newTestTransportCA(t)
	cert := newTestTLSLeaf(t, ca, signer, true, "spiffe://platform.example/ns/guard/sa/engageguard")
	snap := trustedRuntimeRun()
	snap.RunID = safetyRun
	principal := boundRuntime()
	submission := testGuardSubmission(t)
	submission.RunID = safetyRun
	submission.Capability = action.ActionCapabilitySelector{ID: "sre.metrics.read", Version: "1.0.0"}
	submission.Arguments = json.RawMessage("{}")
	response := acpCapabilityReceipt{
		SchemaVersion: acpCapabilitySchema, RunID: safetyRun,
		AgentID: snap.AgentID, AgentReleaseID: snap.AgentReleaseID,
		SessionID: snap.SessionID, CapabilityID: submission.Capability.ID,
		CapabilityVersion: submission.Capability.Version,
		ContractSHA256:    strings.Repeat("a", 64), PolicyRevision: "policy-1",
		ResourceRef: submission.ResourceRef, Status: "VERIFIED",
	}
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var wire atomic.Value
	wire.Store(string(body))
	var status atomic.Int32
	status.Store(http.StatusOK)
	var calls atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != acpCapabilityPath ||
			r.Header.Get("Content-Type") != "application/json" ||
			r.Header.Get("Authorization") != "" || r.Header.Get("X-Tenant-ID") != "" {
			t.Error("Guard sent untrusted authority fields")
		}
		var selector acpCapabilityRequest
		if err := json.NewDecoder(r.Body).Decode(&selector); err != nil ||
			selector.RunID != snap.RunID || selector.AgentID != snap.AgentID ||
			selector.AgentReleaseID != snap.AgentReleaseID ||
			selector.SessionID != snap.SessionID ||
			selector.CapabilityID != submission.Capability.ID ||
			selector.CapabilityVersion != submission.Capability.Version ||
			selector.ResourceRef != submission.ResourceRef {
			t.Error("ACP selector not derived from trusted Runtime")
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte(wire.Load().(string)))
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: clientRoots, Certificates: []tls.Certificate{serverCert}}
	srv.StartTLS()
	defer srv.Close()
	client, err := NewACPCapabilityClient(srv.URL, acpCapabilityPeer, principal.TenantID, roots, cert)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if err := client.VerifyCapabilityAccess(context.Background(), principal, snap, submission); err != nil {
		t.Fatalf("fresh actual mTLS capability denied: %v", err)
	}
	baseCalls := calls.Load()
	foreign := principal
	foreign.TenantID = "foreign"
	if err := client.VerifyCapabilityAccess(context.Background(), foreign, snap, submission); !errors.Is(err, ErrForbidden) || calls.Load() != baseCalls {
		t.Fatalf("foreign tenant queried ACP: %v", err)
	}
	for _, tc := range []struct {
		name string
		wire string
	}{
		{"wrong release", strings.Replace(string(body), `"agent_release_id":"release-1"`, `"agent_release_id":"release-attacker"`, 1)},
		{"wrong policy", strings.Replace(string(body), `"policy_revision":"policy-1"`, `"policy_revision":""`, 1)},
		{"bad digest", strings.Replace(string(body), strings.Repeat("a", 64), "bad", 1)},
		{"duplicate field", strings.Replace(string(body), `"status":"VERIFIED"`, `"status":"VERIFIED","status":"VERIFIED"`, 1)},
		{"extra grant", strings.Replace(string(body), `"status":"VERIFIED"`, `"status":"VERIFIED","permit":"true"`, 1)},
		{"trailing data", string(body) + " {}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire.Store(tc.wire)
			if err := client.VerifyCapabilityAccess(context.Background(), principal, snap, submission); !errors.Is(err, ErrAuthorityUnavailable) {
				t.Fatalf("untrusted ACP capability receipt accepted: %v", err)
			}
		})
	}
	wire.Store(string(body))
	status.Store(http.StatusForbidden)
	if err := client.VerifyCapabilityAccess(context.Background(), principal, snap, submission); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked capability not denied: %v", err)
	}
	status.Store(http.StatusServiceUnavailable)
	if err := client.VerifyCapabilityAccess(context.Background(), principal, snap, submission); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("outage reused stale positive receipt: %v", err)
	}
	status.Store(http.StatusOK)
	wrong, err := NewACPCapabilityClient(srv.URL, "spiffe://platform.example/ns/acp/sa/other", principal.TenantID, roots, cert)
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.CloseIdleConnections()
	if err := wrong.VerifyCapabilityAccess(context.Background(), principal, snap, submission); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("wrong ACP peer accepted: %v", err)
	}
}
