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
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
)

const decisionPlanSchema = "decision.guard-plan-step.v1"
const decisionPlanPath = "/internal/v1/guard-plan-steps:verify"

type guardStepRequest struct {
	SchemaVersion     string          `json:"schema_version"`
	RunID             string          `json:"run_id"`
	AgentID           string          `json:"agent_id"`
	AgentReleaseID    string          `json:"agent_release_id"`
	SessionID         string          `json:"session_id"`
	DecisionID        string          `json:"decision_id"`
	PlanID            string          `json:"plan_id"`
	PlanHash          string          `json:"plan_hash"`
	StepID            string          `json:"step_id"`
	CapabilityID      string          `json:"capability_id"`
	CapabilityVersion string          `json:"capability_version"`
	ResourceRef       string          `json:"resource_ref"`
	Arguments         json.RawMessage `json:"arguments"`
	BreakerEpoch      int64           `json:"breaker_epoch"`
	BreakerVersion    int64           `json:"breaker_version"`
}

type guardStepReceipt struct {
	SchemaVersion  string `json:"schema_version"`
	RunID          string `json:"run_id"`
	DecisionID     string `json:"decision_id"`
	PlanHash       string `json:"plan_hash"`
	StepID         string `json:"step_id"`
	RecordSHA256   string `json:"record_sha256"`
	BreakerEpoch   int64  `json:"breaker_epoch"`
	BreakerVersion int64  `json:"breaker_version"`
	Status         string `json:"status"`
}

// DecisionPlanClient is a necessary-only live verification dependency.
// All requested fields come from trusted Guard's canonical Run snapshot
// and untrusted selectors; the Decision service resolves the original plan
// and independently reads Runtime/ACP/Evidence. No Permit is returned.
type DecisionPlanClient struct {
	origin string
	tenant string
	http   *http.Client
}

func NewDecisionPlanClient(
	origin, expectedSPIFFE, tenant string, roots *x509.CertPool, credential tls.Certificate,
) (*DecisionPlanClient, error) {
	u, err := url.Parse(origin)
	id, idErr := url.Parse(expectedSPIFFE)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.Opaque != "" || u.Path != "" || u.RawPath != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != origin ||
		idErr != nil || id.Scheme != "spiffe" || id.Host == "" || id.Port() != "" ||
		id.Path == "" || id.Path == "/" || id.User != nil || id.Opaque != "" ||
		id.RawPath != "" || id.RawQuery != "" || id.ForceQuery || id.Fragment != "" ||
		id.String() != expectedSPIFFE || !validIdentity(tenant) ||
		roots == nil || len(roots.Subjects()) == 0 ||
		len(credential.Certificate) == 0 || credential.PrivateKey == nil {
		return nil, ErrAuthorityUnavailable
	}
	tr := &http.Transport{
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    3 * time.Second,
		ResponseHeaderTimeout:  5 * time.Second,
		MaxResponseHeaderBytes: 8 * 1024, // authenticated metadata is also untrusted
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      roots.Clone(),
			Certificates: []tls.Certificate{credential},
			VerifyConnection: func(s tls.ConnectionState) error {
				if s.Version != tls.VersionTLS13 || len(s.PeerCertificates) == 0 ||
					len(s.VerifiedChains) == 0 {
					return ErrAuthorityUnavailable
				}
				leaf := s.PeerCertificates[0]
				now := time.Now()
				if leaf == nil || leaf.IsCA || len(leaf.URIs) != 1 || leaf.URIs[0] == nil ||
					leaf.URIs[0].String() != expectedSPIFFE || now.Before(leaf.NotBefore) ||
					!now.Before(leaf.NotAfter) || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
					return ErrAuthorityUnavailable
				}
				for _, use := range leaf.ExtKeyUsage {
					if use == x509.ExtKeyUsageServerAuth {
						return nil
					}
				}
				return ErrAuthorityUnavailable
			},
		},
	}
	return &DecisionPlanClient{origin: origin, tenant: tenant, http: &http.Client{
		Timeout: 20 * time.Second, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (c *DecisionPlanClient) CloseIdleConnections() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}

func (c *DecisionPlanClient) VerifyDecisionPlanStep(
	ctx context.Context, principal Principal, snapshot RunSafetySnapshot, submission action.ActionSubmission,
) error {
	if c == nil || c.http == nil {
		return ErrAuthorityUnavailable
	}
	if principal.TenantID != c.tenant || snapshot.TenantID != c.tenant ||
		principal.ServiceID != "agent-runtime" || snapshot.RunID != submission.RunID ||
		snapshot.Status != "RUNNING" || snapshot.BreakerState != "CLOSED" ||
		snapshot.BreakerEpoch == 0 || snapshot.BreakerVersion == 0 {
		return ErrForbidden
	}
	// This first compatible version only verifies read-only SRE observations.
	// Plan candidates do not bind arbitrary tool argument payloads yet.
	// Prefix membership is not a read-only authorization: an SRE-namespaced
	// selector could name a mutating action. This v1 client only admits the
	// explicitly reviewed read-only observation capability. Any expansion
	// requires a trusted capability catalog and its own negative test.
	if !bytes.Equal(submission.Arguments, []byte("{}")) ||
		submission.Capability.ID != "sre.metrics.read" {
		return ErrForbidden
	}
	const maxUint = uint64(^uint64(0) >> 1)
	if snapshot.BreakerEpoch > maxUint || snapshot.BreakerVersion > maxUint {
		return ErrForbidden
	}
	reqPayload := guardStepRequest{
		SchemaVersion: decisionPlanSchema, RunID: snapshot.RunID,
		AgentID: snapshot.AgentID, AgentReleaseID: snapshot.AgentReleaseID,
		SessionID: snapshot.SessionID, DecisionID: submission.DecisionID,
		PlanID: submission.PlanID, PlanHash: submission.PlanHash,
		StepID: submission.StepID, CapabilityID: submission.Capability.ID,
		CapabilityVersion: submission.Capability.Version,
		ResourceRef:       submission.ResourceRef, Arguments: submission.Arguments,
		BreakerEpoch: int64(snapshot.BreakerEpoch), BreakerVersion: int64(snapshot.BreakerVersion),
	}
	raw, err := json.Marshal(reqPayload)
	if err != nil {
		return ErrAuthorityUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+decisionPlanPath, bytes.NewReader(raw))
	if err != nil {
		return ErrAuthorityUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	res, err := c.http.Do(req)
	if err != nil {
		return ErrAuthorityUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusForbidden {
		return ErrForbidden
	}
	if res.StatusCode != http.StatusOK {
		return ErrAuthorityUnavailable
	}
	media, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || res.Header.Get("Cache-Control") != "no-store" {
		return ErrAuthorityUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 4097))
	if err != nil || len(body) == 0 || len(body) > 4096 {
		return ErrAuthorityUnavailable
	}
	var receipt guardStepReceipt
	if json.Unmarshal(body, &receipt) != nil ||
		receipt.SchemaVersion != decisionPlanSchema ||
		receipt.Status != "VERIFIED" || receipt.RunID != snapshot.RunID ||
		receipt.DecisionID != submission.DecisionID ||
		receipt.PlanHash != submission.PlanHash ||
		receipt.StepID != submission.StepID ||
		receipt.BreakerEpoch != int64(snapshot.BreakerEpoch) ||
		receipt.BreakerVersion != int64(snapshot.BreakerVersion) ||
		!canonicalSHA256(receipt.RecordSHA256) {
		return ErrAuthorityUnavailable
	}
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(canonical, bytes.TrimSpace(body)) {
		return ErrAuthorityUnavailable
	}
	return nil
}

func canonicalSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			continue
		}
		return false
	}
	return true
}

var _ DecisionPlanAuthority = (*DecisionPlanClient)(nil)
