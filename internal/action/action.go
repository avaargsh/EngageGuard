package action

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"strings"
	"unicode/utf8"
)

// WorkspaceWrite is a *trusted, resolved* action. The PEP must derive identity
// and binding attributes from authenticated context, not model-provided JSON.
type WorkspaceWrite struct {
	SchemaVersion     string `json:"schema_version"`
	TenantID          string `json:"tenant_id"`
	SubjectID         string `json:"subject_id"`
	AgentID           string `json:"agent_id"`
	OperationID       string `json:"operation_id"`
	CapabilityID      string `json:"capability_id"`
	ToolBindingDigest string `json:"tool_binding_digest"`
	PolicyVersion     string `json:"policy_version"`
	Audience          string `json:"audience"`
	WorkspaceID       string `json:"workspace_id"`
	RelativePath      string `json:"relative_path"`
	ContentDigest     string `json:"content_digest"`
}

func (a WorkspaceWrite) Validate() error {
	if a.SchemaVersion != "v0.1" || a.CapabilityID != "workspace.write" {
		return errors.New("unsupported action schema or capability")
	}
	for _, s := range []string{a.TenantID, a.SubjectID, a.AgentID, a.OperationID,
		a.CapabilityID, a.ToolBindingDigest, a.PolicyVersion, a.Audience, a.WorkspaceID,
		a.RelativePath, a.ContentDigest} {
		if !utf8.ValidString(s) || strings.TrimSpace(s) == "" || len(s) > 4096 || strings.IndexByte(s, 0) >= 0 {
			return errors.New("invalid action field")
		}
	}
	if strings.HasPrefix(a.RelativePath, "/") || a.RelativePath == ".." || strings.HasPrefix(a.RelativePath, "../") || strings.Contains(a.RelativePath, "\\") ||
		path.Clean(a.RelativePath) != a.RelativePath || a.RelativePath == "." {
		return errors.New("noncanonical relative path")
	}
	for _, digest := range []string{a.ToolBindingDigest, a.ContentDigest} {
		if len(digest) != 64 || digest != strings.ToLower(digest) {
			return errors.New("invalid digest")
		}
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != sha256.Size {
			return errors.New("invalid digest")
		}
	}
	return nil
}

// Hash binds the exact normalized action to its identity and policy context.
// A digest is not a Permit or authorization decision.
func Hash(a WorkspaceWrite) (string, error) {
	if err := a.Validate(); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

// ApprovalMatches compares the approved action digest without trusting an
// action-supplied approval claim. Revocation must still be checked separately.
func ApprovalMatches(approvedDigest string, proposed WorkspaceWrite) bool {
	current, err := Hash(proposed)
	if err != nil || len(approvedDigest) != 64 {
		return false
	}
	expected, err := hex.DecodeString(approvedDigest)
	if err != nil || len(expected) != sha256.Size {
		return false
	}
	actual, _ := hex.DecodeString(current)
	return subtle.ConstantTimeCompare(expected, actual) == 1
}
