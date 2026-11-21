// Package approval verifies independently signed evidence for a future
// EngageGuard Scoped Permit issuer. Verification alone never grants a Permit,
// authorizes a protected action or proves current non-revocation.
package approval

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"
)

const approvalDomain = "engageguard/approval-proof/v1\x00"
const maxApprovalWire = 16 * 1024
const maxApprovalPayload = 8 * 1024
const maxApprovalWindow = 5 * time.Minute

var ErrApprovalRejected = errors.New("independent Guard approval evidence rejected")

// Scope is bound to the trusted issuer's separately resolved identifiers.
// In particular, ActionHash must be calculated by Guard from a resolved Action
// and NEVER supplied by the model or accepted from ActionSubmission as proof.
type Scope struct {
	TenantID          string `json:"tenant_id"`
	RunID             string `json:"run_id"`
	AttemptID         string `json:"attempt_id"`
	TurnID            string `json:"turn_id"`
	OperationID       string `json:"operation_id"`
	AgentID           string `json:"agent_id"`
	AgentReleaseID    string `json:"agent_release_id"`
	SubjectID         string `json:"subject_id"`
	DecisionID        string `json:"decision_id"`
	PlanHash          string `json:"plan_hash"`
	StepID            string `json:"step_id"`
	ActionHash        string `json:"action_hash"`
	ToolBindingDigest string `json:"tool_binding_digest"`
	PolicyVersion     string `json:"policy_version"`
	Audience          string `json:"audience"`
	ResourceRef       string `json:"resource_ref"`
}

// Evidence is a short-lived operator-approval attestation, not a bearer
// authorization. The current approval/revocation authority must be read again
// at Permit issuance and executor PEP before any protected effect.
type Evidence struct {
	SchemaVersion string    `json:"schema_version"`
	ApprovalID    string    `json:"approval_id"`
	Decision      string    `json:"decision"`
	Scope         Scope     `json:"scope"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// SignedEvidence holds exact canonical JSON payload bytes. The signer key
// is pinned out of band, never accepted from this envelope.
type SignedEvidence struct {
	KeyID     string `json:"key_id"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

var approvalIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var approvalDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func validScope(s Scope) bool {
	for _, value := range []string{s.TenantID, s.RunID, s.AttemptID, s.TurnID,
		s.OperationID, s.AgentID, s.AgentReleaseID, s.SubjectID, s.DecisionID,
		s.StepID, s.PolicyVersion, s.Audience, s.ResourceRef} {
		if !approvalIdentifier.MatchString(value) {
			return false
		}
	}
	return approvalDigest.MatchString(s.PlanHash) &&
		approvalDigest.MatchString(s.ActionHash) && approvalDigest.MatchString(s.ToolBindingDigest)
}

func decodeCanonical(raw []byte, limit int, target any) bool {
	if len(raw) == 0 || len(raw) > limit {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return false
	}
	canonical, err := json.Marshal(target)
	return err == nil && bytes.Equal(canonical, raw)
}

// VerifySignedEvidence checks pinned-key Ed25519, exact source-scoped payload
// identity, a domain-separated signature and a tight signed validity interval.
// It is a necessary-only precondition for a future trusted Scoped Permit issuer.
// It MUST NOT be called as a substitute for current Run, Decision, ACP, policy,
// human approval revocation, risk checks, durable Permit claim or executor PEP.
func VerifySignedEvidence(wire []byte, publicKey ed25519.PublicKey, expected Scope, now time.Time) (Evidence, error) {
	deny := func() (Evidence, error) { return Evidence{}, ErrApprovalRejected }
	if len(publicKey) != ed25519.PublicKeySize || now.IsZero() || !validScope(expected) {
		return deny()
	}
	var signed SignedEvidence
	if !decodeCanonical(wire, maxApprovalWire, &signed) ||
		len(signed.Payload) == 0 || len(signed.Payload) > maxApprovalPayload ||
		len(signed.Signature) != ed25519.SignatureSize {
		return deny()
	}
	fingerprint := sha256.Sum256(publicKey)
	if signed.KeyID != hex.EncodeToString(fingerprint[:]) {
		return deny()
	}
	message := make([]byte, 0, len(approvalDomain)+len(signed.Payload))
	message = append(message, approvalDomain...)
	message = append(message, signed.Payload...)
	if !ed25519.Verify(publicKey, message, signed.Signature) {
		return deny()
	}

	var proof Evidence
	if !decodeCanonical(signed.Payload, maxApprovalPayload, &proof) ||
		proof.SchemaVersion != "engageguard.approval-evidence.v1" ||
		!approvalIdentifier.MatchString(proof.ApprovalID) ||
		proof.Decision != "APPROVED" || !validScope(proof.Scope) || proof.Scope != expected ||
		proof.IssuedAt.IsZero() || proof.ExpiresAt.IsZero() ||
		!proof.ExpiresAt.After(proof.IssuedAt) ||
		proof.ExpiresAt.Sub(proof.IssuedAt) > maxApprovalWindow ||
		now.Before(proof.IssuedAt) || !now.Before(proof.ExpiresAt) {
		return deny()
	}
	return proof, nil
}
