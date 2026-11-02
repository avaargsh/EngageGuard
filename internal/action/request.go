package action

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const maxArgumentsBytes = 64 * 1024

type ActionCapabilityRef struct {
	ID             string `json:"id"`
	Version        string `json:"version"`
	ContractSHA256 string `json:"contract_sha256"`
}

// ActionRequest is a Guard-INTERNAL, resolved side-effect record. It is NOT
// the Runtime-to-Guard wire request; use ActionSubmission for caller intent.
// Guard alone allocates OperationID and resolves all identity, policy and
// tool-binding attributes from authenticated authoritative context.
type ActionRequest struct {
	SchemaVersion     string              `json:"schema_version"`
	TenantID          string              `json:"tenant_id"`
	SubjectID         string              `json:"subject_id"`
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
	return value != "" && len(value) <= 512 && strings.TrimSpace(value) == value &&
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
		a.SchemaVersion, a.TenantID, a.SubjectID, a.AgentID, a.RunID,
		a.DecisionID, a.PlanID, a.PlanHash, a.StepID, a.OperationID, a.ResourceRef,
		a.PolicyVersion, a.Audience,
	} {
		if !validActionField(value) {
			return errors.New("invalid ActionRequest identity or binding field")
		}
	}
	if a.SchemaVersion != "action-request.v1" || !validActionField(a.Capability.ID) ||
		!validActionField(a.Capability.Version) || !validSHA256(a.Capability.ContractSHA256) ||
		!validSHA256(a.ToolBindingDigest) {
		return errors.New("invalid ActionRequest schema or capability binding")
	}
	if !validSHA256(a.PlanHash) {
		return errors.New("invalid plan hash")
	}
	if len(a.Arguments) == 0 || len(a.Arguments) > maxArgumentsBytes {
		return errors.New("ActionRequest arguments missing or oversized")
	}
	if _, err := canonicalArguments(a.Arguments); err != nil {
		return fmt.Errorf("invalid ActionRequest arguments: %w", err)
	}
	return nil
}

// ActionHash is an EXPERIMENTAL Go-only digest for the resolved-action draft.
// Its use of json.Marshal is NOT RFC8785 JCS for arbitrary numbers/Unicode;
// do not use this output for cross-language approval or Permit binding until
// normative canonicalization vectors and the versioned domain are ratified.
// It currently binds tenant, subject, agent, Run, Decision, Plan, Step, operation,
// capability, resource, tool binding, policy version and executor audience.
func ActionHash(a ActionRequest) (string, error) {
	if err := a.Validate(); err != nil {
		return "", err
	}
	arguments, err := canonicalArguments(a.Arguments)
	if err != nil {
		return "", err
	}
	a.Arguments = json.RawMessage(arguments)
	payload, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func ApprovalMatchesActionHash(approvedHash string, action ActionRequest) bool {
	current, err := ActionHash(action)
	if err != nil || !validSHA256(approvedHash) {
		return false
	}
	expected, _ := hex.DecodeString(approvedHash)
	actual, _ := hex.DecodeString(current)
	return subtle.ConstantTimeCompare(expected, actual) == 1
}

// canonicalArguments rejects duplicate object keys at every depth. Object keys
// are sorted by encoding/json during re-encoding; numbers retain json.Number
// lexical form so the hash is deterministic and never passes through float64.
func canonicalArguments(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > maxArgumentsBytes || !utf8.Valid(raw) {
		return nil, errors.New("invalid argument byte sequence")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := readJSONValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, errors.New("arguments must be a JSON object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing argument data")
	}
	return json.Marshal(value)
}

func readJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delim {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("invalid object key")
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("duplicate object key %q", key)
			}
			value, err := readJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("unterminated JSON object")
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for decoder.More() {
			value, err := readJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("unterminated JSON array")
		}
		return array, nil
	default:
		return nil, errors.New("unexpected JSON delimiter")
	}
}
