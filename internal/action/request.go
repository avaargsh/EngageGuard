package action

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"unicode/utf8"
)

const maxArgumentsBytes = 64 * 1024

// ActionCapabilityRef is resolved by Guard from the trusted capability
// registry. Its contract digest is not accepted from the caller submission.
type ActionCapabilityRef struct {
	ID             string `json:"id"`
	Version        string `json:"version"`
	ContractSHA256 string `json:"contract_sha256"`
}

// ActionRequest is a Guard-internal resolved action. It is never accepted as
// Runtime wire input: ActionSubmission is the untrusted caller contract.
// OperationID, identity, capability digest, ToolBinding, policy and audience
// are populated by trusted Guard authorities before hashing.
type ActionRequest struct {
	SchemaVersion     string              `json:"schema_version"`
	TenantID          string              `json:"tenant_id"`
	SubjectID         string              `json:"subject_id"`
	ActorID           string              `json:"actor_id"`
	WorkloadID        string              `json:"workload_id"`
	AgentID           string              `json:"agent_id"`
	RunID             string              `json:"run_id"`
	DecisionID        string              `json:"decision_id"`
	PlanID            string              `json:"plan_id"`
	PlanHash          string              `json:"plan_hash"`
	StepID            string              `json:"step_id"`
	OperationID       string              `json:"operation_id"`
	Capability        ActionCapabilityRef `json:"capability"`
	ResourceRef       string              `json:"resource_ref"`
	Arguments         json.RawMessage     `json:"arguments"`
	ToolBindingDigest string              `json:"tool_binding_digest"`
	PolicyVersion     string              `json:"policy_version"`
	Audience          string              `json:"audience"`
}

func validActionField(value string) bool {
	return value != "" && len(value) <= 512 && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n\t ")
}

func validSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func (a ActionRequest) Validate() error {
	for _, value := range []string{
		a.SchemaVersion, a.TenantID, a.SubjectID, a.ActorID, a.WorkloadID,
		a.AgentID, a.RunID, a.DecisionID, a.PlanID, a.StepID, a.OperationID,
		a.ResourceRef, a.PolicyVersion, a.Audience,
	} {
		if !validActionField(value) {
			return errors.New("invalid resolved ActionRequest identity or binding field")
		}
	}
	if a.SchemaVersion != "action-request.v1" ||
		!validSHA256(a.PlanHash) ||
		!validActionField(a.Capability.ID) ||
		!validActionField(a.Capability.Version) ||
		!validSHA256(a.Capability.ContractSHA256) ||
		!validSHA256(a.ToolBindingDigest) {
		return errors.New("invalid resolved ActionRequest schema or capability binding")
	}
	if len(a.Arguments) == 0 || len(a.Arguments) > maxArgumentsBytes {
		return errors.New("resolved ActionRequest arguments missing or oversized")
	}
	canonical, err := canonicalJSONObject(a.Arguments)
	if err != nil {
		return fmt.Errorf("invalid resolved ActionRequest arguments: %w", err)
	}
	if a.Capability.ID == "workspace.write" {
		if err := validateWorkspaceWriteArguments(canonical); err != nil {
			return err
		}
	}
	return nil
}

// ActionHash computes the normative, versioned RFC 8785 digest of the exact
// Guard-resolved ActionRequest. Caller-supplied values and hashes are never
// used as authorization evidence. Approval and Permit must bind this digest.
func ActionHash(action ActionRequest) (string, error) {
	if err := action.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(action)
	if err != nil {
		return "", err
	}
	canonical, err := canonicalJSONObject(raw)
	if err != nil {
		return "", err
	}
	preimage := make([]byte, 0, len(actionHashDomain)+len(canonical))
	preimage = append(preimage, actionHashDomain...)
	preimage = append(preimage, canonical...)
	digest := sha256.Sum256(preimage)
	return hex.EncodeToString(digest[:]), nil
}

// ApprovalMatchesActionHash compares against a freshly validated resolved
// action. Revocation, policy freshness and expiry are separate checks.
func ApprovalMatchesActionHash(approvedHash string, action ActionRequest) bool {
	current, err := ActionHash(action)
	if err != nil || !validSHA256(approvedHash) {
		return false
	}
	expected, _ := hex.DecodeString(approvedHash)
	actual, _ := hex.DecodeString(current)
	return subtle.ConstantTimeCompare(expected, actual) == 1
}

func validateWorkspaceWriteArguments(canonical []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &fields); err != nil {
		return fmt.Errorf("invalid workspace.write arguments: %w", err)
	}
	if len(fields) != 2 || fields["path"] == nil || fields["content_sha256"] == nil {
		return errors.New("workspace.write arguments must contain exactly path and content_sha256")
	}
	var relativePath, contentSHA256 string
	if err := json.Unmarshal(fields["path"], &relativePath); err != nil {
		return errors.New("workspace.write path must be a string")
	}
	if err := json.Unmarshal(fields["content_sha256"], &contentSHA256); err != nil {
		return errors.New("workspace.write content_sha256 must be a string")
	}
	if !validWorkspaceRelativePath(relativePath) {
		return errors.New("workspace.write path must be a canonical relative path without traversal")
	}
	if !validSHA256(contentSHA256) {
		return errors.New("workspace.write content_sha256 must be a lowercase SHA-256 digest")
	}
	return nil
}

// This is a lexical guard only. The Trusted Executor must separately enforce
// root-relative, symlink-safe and TOCTOU-resistant filesystem operations.
func validWorkspaceRelativePath(value string) bool {
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) ||
		strings.HasPrefix(value, "/") || hasWindowsDrivePrefix(value) ||
		strings.ContainsAny(value, "\\\x00") || path.Clean(value) != value || value == "." {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." || segment == "." || segment == "" {
			return false
		}
	}
	return true
}

func hasWindowsDrivePrefix(value string) bool {
	if len(value) < 2 || value[1] != ':' {
		return false
	}
	letter := value[0]
	return (letter >= 'a' && letter <= 'z') || (letter >= 'A' && letter <= 'Z')
}
