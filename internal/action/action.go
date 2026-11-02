package action

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"path"
	"strings"
	"unicode/utf8"
)

const actionHashDomain = "engageguard/action-hash/v1\x00"

// Deprecated: WorkspaceWrite is retained only as a frozen v0.1 reference vector.
// Production approval and Permit binding must use CanonicalAction.
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

// canonicalJSON emits RFC 8785 JCS for this fixed all-string object.
// All property names are ASCII and are listed in UTF-16 lexical order.
// The schema intentionally has no numeric fields, avoiding cross-runtime
// IEEE-754 number serialization differences in this ActionHash version.
func canonicalJSON(a WorkspaceWrite) []byte {
	fields := [...]struct {
		key   string
		value string
	}{
		{"agent_id", a.AgentID},
		{"audience", a.Audience},
		{"capability_id", a.CapabilityID},
		{"content_digest", a.ContentDigest},
		{"operation_id", a.OperationID},
		{"policy_version", a.PolicyVersion},
		{"relative_path", a.RelativePath},
		{"schema_version", a.SchemaVersion},
		{"subject_id", a.SubjectID},
		{"tenant_id", a.TenantID},
		{"tool_binding_digest", a.ToolBindingDigest},
		{"workspace_id", a.WorkspaceID},
	}

	out := make([]byte, 0, 512)
	out = append(out, '{')
	for i, field := range fields {
		if i > 0 {
			out = append(out, ',')
		}
		out = appendJSONString(out, field.key)
		out = append(out, ':')
		out = appendJSONString(out, field.value)
	}
	return append(out, '}')
}

// appendJSONString follows the ECMAScript JSON string escaping used by JCS:
// quote/backslash and controls are escaped; HTML characters, slash and
// non-control Unicode are emitted as UTF-8 without normalization.
func appendJSONString(dst []byte, value string) []byte {
	const hexDigits = "0123456789abcdef"
	dst = append(dst, '"')
	for _, r := range value {
		switch r {
		case '"':
			dst = append(dst, '\\', '"')
		case '\\':
			dst = append(dst, '\\', '\\')
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\t':
			dst = append(dst, '\\', 't')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\f':
			dst = append(dst, '\\', 'f')
		case '\r':
			dst = append(dst, '\\', 'r')
		default:
			if r < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[byte(r)>>4], hexDigits[byte(r)&0x0f])
			} else {
				dst = utf8.AppendRune(dst, r)
			}
		}
	}
	return append(dst, '"')
}

// Deprecated: Hash computes the frozen WorkspaceWrite v0.1 reference digest.
// Use ActionHash(CanonicalAction) for production approval and Permit binding.
func Hash(a WorkspaceWrite) (string, error) {
	if err := a.Validate(); err != nil {
		return "", err
	}
	canonical := canonicalJSON(a)
	preimage := make([]byte, 0, len(actionHashDomain)+len(canonical))
	preimage = append(preimage, actionHashDomain...)
	preimage = append(preimage, canonical...)
	digest := sha256.Sum256(preimage)
	return hex.EncodeToString(digest[:]), nil
}

// Deprecated: ApprovalMatches only supports the frozen WorkspaceWrite v0.1 vector.
// Use ApprovalMatchesActionHash with a trusted CanonicalAction.
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
