package admission

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
)

const runtimeExecutionAuthoritySchema = "runtime.guard-execution-authority.v1"

// RuntimeExecutionAuthoritySnapshot is a necessary-only identity observation,
// not approval, a Permit or an execution grant.
type RuntimeExecutionAuthoritySnapshot struct {
	SchemaVersion       string `json:"schema_version"`
	TenantID            string `json:"tenant_id"`
	RunID               string `json:"run_id"`
	AgentID             string `json:"agent_id"`
	AgentReleaseID      string `json:"agent_release_id"`
	SessionID           string `json:"session_id"`
	WorkflowID          string `json:"workflow_id"`
	TemporalExecutionID string `json:"execution_id"`
	RunAttemptID        string `json:"run_attempt_id"`
	TurnID              string `json:"turn_id"`
	InvocationID        string `json:"invocation_id"`
	TurnIndex           int32  `json:"turn_index"`
	AttemptGeneration   int64  `json:"attempt_generation"`
	AttemptBreakerEpoch int64  `json:"attempt_breaker_epoch"`
	Status              string `json:"status"`
	BreakerState        string `json:"breaker_state"`
	BreakerEpoch        int64  `json:"breaker_epoch"`
	BreakerVersion      int64  `json:"breaker_version"`
}

type RuntimeGuardExecutionAuthorityClient struct {
	base *acpAuthorityHTTPClient
}

func NewRuntimeGuardExecutionAuthorityClient(origin, peer, tenant string, roots *x509.CertPool, credential tls.Certificate) (*RuntimeGuardExecutionAuthorityClient, error) {
	base, err := newACPPinnedHTTPClient(origin, peer, tenant, roots, credential)
	if err != nil {
		return nil, err
	}
	return &RuntimeGuardExecutionAuthorityClient{base: base}, nil
}

func (c *RuntimeGuardExecutionAuthorityClient) CloseIdleConnections() {
	if c != nil && c.base != nil {
		c.base.closeIdleConnections()
	}
}

func (c *RuntimeGuardExecutionAuthorityClient) GetGuardExecutionAuthority(ctx context.Context, tenant, runID, turnID string) (RuntimeExecutionAuthoritySnapshot, error) {
	var zero RuntimeExecutionAuthoritySnapshot
	if c == nil || c.base == nil || c.base.http == nil || ctx == nil || ctx.Err() != nil {
		return zero, ErrAuthorityUnavailable
	}
	if tenant != c.base.tenant || !canonicalSafetyRunID.MatchString(runID) || !canonicalSafetyRunID.MatchString(turnID) {
		return zero, ErrForbidden
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base.origin+"/internal/v1/guard-execution-authority/"+runID+"/"+turnID, nil)
	if err != nil {
		return zero, ErrAuthorityUnavailable
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-store")
	res, err := c.base.http.Do(req)
	if err != nil {
		return zero, ErrAuthorityUnavailable
	}
	defer res.Body.Close()
	if ctx.Err() != nil {
		return zero, ErrAuthorityUnavailable
	}
	if res.StatusCode == http.StatusForbidden {
		return zero, ErrForbidden
	}
	if res.StatusCode != http.StatusOK {
		return zero, ErrAuthorityUnavailable
	}
	raw, err := readACPReceipt(res)
	if err != nil {
		return zero, err
	}
	a, err := decodeRuntimeExecutionAuthority(raw)
	if err != nil || ctx.Err() != nil {
		return zero, ErrAuthorityUnavailable
	}
	if a.TenantID != tenant || a.RunID != runID || a.TurnID != turnID ||
		!validACPAuthorityIdentifier(a.AgentID) || !validACPAuthorityIdentifier(a.AgentReleaseID) ||
		!validACPAuthorityIdentifier(a.SessionID) ||
		!canonicalSafetyRunID.MatchString(a.RunAttemptID) || !canonicalSafetyRunID.MatchString(a.TemporalExecutionID) ||
		a.InvocationID != turnID || a.WorkflowID != "agent-run/v1/"+runID ||
		a.Status != "RUNNING" || a.BreakerState != "CLOSED" ||
		a.AttemptGeneration != 1 || a.AttemptBreakerEpoch != 1 || a.BreakerEpoch != 1 ||
		a.BreakerVersion != 1 || a.TurnIndex < 1 || a.TurnIndex > 10000 {
		return zero, ErrForbidden
	}
	return a, nil
}

// Compare exact field names against the wire contract and reject duplicate,
// missing and null fields without requiring a particular JSON whitespace order.
func decodeRuntimeExecutionAuthority(raw []byte) (RuntimeExecutionAuthoritySnapshot, error) {
	var a RuntimeExecutionAuthoritySnapshot
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return a, ErrAuthorityUnavailable
	}
	fields := map[string]any{
		"schema_version": &a.SchemaVersion, "tenant_id": &a.TenantID,
		"run_id": &a.RunID, "agent_id": &a.AgentID, "agent_release_id": &a.AgentReleaseID,
		"session_id": &a.SessionID, "workflow_id": &a.WorkflowID,
		"execution_id": &a.TemporalExecutionID, "run_attempt_id": &a.RunAttemptID,
		"turn_id": &a.TurnID, "invocation_id": &a.InvocationID, "turn_index": &a.TurnIndex,
		"attempt_generation": &a.AttemptGeneration, "attempt_breaker_epoch": &a.AttemptBreakerEpoch,
		"status": &a.Status, "breaker_state": &a.BreakerState,
		"breaker_epoch": &a.BreakerEpoch, "breaker_version": &a.BreakerVersion,
	}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		dest, exists := fields[key]
		if err != nil || !ok || !exists {
			return RuntimeExecutionAuthoritySnapshot{}, ErrAuthorityUnavailable
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) ||
			json.Unmarshal(value, dest) != nil {
			return RuntimeExecutionAuthoritySnapshot{}, ErrAuthorityUnavailable
		}
		delete(fields, key)
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(fields) != 0 || a.SchemaVersion != runtimeExecutionAuthoritySchema {
		return RuntimeExecutionAuthoritySnapshot{}, ErrAuthorityUnavailable
	}
	if _, err := d.Token(); err != io.EOF {
		return RuntimeExecutionAuthoritySnapshot{}, ErrAuthorityUnavailable
	}
	return a, nil
}
