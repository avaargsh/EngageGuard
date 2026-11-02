package action

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	maxSubmissionBytes     = 64 * 1024
	submissionDigestDomain = "engageguard/submission-bytes/v1\x00"
)

// ActionCapabilitySelector is an untrusted capability name/version selector.
// Guard resolves the immutable contract digest from its trusted registry.
type ActionCapabilitySelector struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// ActionSubmission is *untrusted intent* supplied by a caller. Deliberately
// absent: tenant, subject, agent, operation ID, policy, executor and binding.
// Guard must resolve all those values from authenticated authoritative state.
// This is not a permit, an executable action or an authorization decision.
type ActionSubmission struct {
	SchemaVersion string                   `json:"schema_version"`
	RunID         string                   `json:"run_id"`
	DecisionID    string                   `json:"decision_id"`
	PlanID        string                   `json:"plan_id"`
	PlanHash      string                   `json:"plan_hash"`
	StepID        string                   `json:"step_id"`
	Capability    ActionCapabilitySelector `json:"capability"`
	ResourceRef   string                   `json:"resource_ref"`
	Arguments     json.RawMessage          `json:"arguments"`
}

func (s ActionSubmission) Validate() error {
	if s.SchemaVersion != "action-submission.v1" ||
		!validActionField(s.RunID) || !validActionField(s.DecisionID) ||
		!validActionField(s.PlanID) || !validSHA256(s.PlanHash) ||
		!validActionField(s.StepID) || !validActionField(s.Capability.ID) ||
		!validActionField(s.Capability.Version) ||
		!validActionField(s.ResourceRef) {
		return errors.New("invalid submission identity or capability reference")
	}
	if len(s.Arguments) == 0 || len(s.Arguments) > maxArgumentsBytes {
		return errors.New("invalid submission arguments size")
	}
	if _, err := canonicalJSONObject(s.Arguments); err != nil {
		return fmt.Errorf("invalid submission arguments: %w", err)
	}
	return nil
}

// ParseActionSubmission rejects duplicate keys at any nesting depth and
// unknown fields, including a caller-provided operation_id. A server must
// never use fields from this untrusted struct as authenticated identity.
func ParseActionSubmission(raw []byte) (ActionSubmission, error) {
	var result ActionSubmission
	if len(raw) == 0 || len(raw) > maxSubmissionBytes {
		return result, errors.New("invalid submission body size")
	}
	// Check nesting before recursive parsing to bound attacker-controlled
	// stack growth; replay still hashes exact bytes, not canonicalized JSON.
	if err := checkSubmissionDepth(raw); err != nil {
		return result, err
	}
	if _, err := canonicalJSONObject(raw); err != nil {
		return result, fmt.Errorf("invalid submission JSON: %w", err)
	}
	// encoding/json accepts case-insensitive field aliases even with
	// DisallowUnknownFields; check protocol keys with exact spelling.
	if err := checkSubmissionFields(raw); err != nil {
		return result, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return ActionSubmission{}, fmt.Errorf("invalid submission fields: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ActionSubmission{}, errors.New("trailing submission data")
	}
	if err := result.Validate(); err != nil {
		return ActionSubmission{}, err
	}
	return result, nil
}

const maxSubmissionDepth = 128

func checkSubmissionDepth(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	depth := 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil // canonicalJSONObject checks full syntax and trailing data
		}
		if err != nil {
			return fmt.Errorf("invalid submission JSON: %w", err)
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{', '[':
				depth++
				if depth > maxSubmissionDepth {
					return errors.New("submission JSON nesting exceeds limit")
				}
			case '}', ']':
				depth--
			}
		}
	}
}

func checkSubmissionFields(raw []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return err
	}
	allowed := map[string]bool{
		"schema_version": true, "run_id": true, "decision_id": true,
		"plan_id": true, "plan_hash": true, "step_id": true,
		"capability": true, "resource_ref": true, "arguments": true,
	}
	for key := range root {
		if !allowed[key] {
			return fmt.Errorf("unknown or noncanonical submission field %q", key)
		}
	}
	var capability map[string]json.RawMessage
	if err := json.Unmarshal(root["capability"], &capability); err != nil || capability == nil {
		return errors.New("invalid submission capability")
	}
	for key := range capability {
		if key != "id" && key != "version" {
			return fmt.Errorf("unknown or noncanonical capability field %q", key)
		}
	}
	return nil
}

// ValidateSubmissionKey validates the caller-generated Idempotency-Key header.
// Uniqueness and atomic (tenant, key, digest)->operation ID binding belong in
// Guard's future PostgreSQL submission handler, never this pure helper.
func ValidateSubmissionKey(key string) error {
	if len(key) < 1 || len(key) > 128 {
		return errors.New("invalid idempotency key length")
	}
	for i := 0; i < len(key); i++ {
		ch := key[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			continue
		}
		if i > 0 && (ch == '.' || ch == '_' || ch == ':' || ch == '-') {
			continue
		}
		return errors.New("invalid idempotency key character")
	}
	return nil
}

// SubmissionDigest hashes exact submitted bytes, not a canonical ActionHash.
// Byte-different retries conflict (even if JSON-semantically equivalent),
// which is conservative while cross-language RFC8785 vectors are unresolved.
// This is a replay fingerprint only and MUST NOT be used as a Permit binding.
func SubmissionDigest(raw []byte) (string, error) {
	if _, err := ParseActionSubmission(raw); err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(submissionDigestDomain))
	_, _ = digest.Write(raw)
	return hex.EncodeToString(digest.Sum(nil)), nil
}
