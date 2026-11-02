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
const maxJSONDepth = 128

type ActionCapabilityRef struct {
	ID             string `json:"id"`
	Version        string `json:"version"`
	ContractSHA256 string `json:"contract_sha256"`
}

// ActionRequest is one concrete proposed side effect. The PEP must derive
// identity and tool-binding values from authenticated control-plane context.
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
		a.DecisionID, a.PlanID, a.PlanHash, a.StepID, a.ResourceRef,
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

// ActionHash canonicalizes the argument object, then binds it to the exact
// tenant, subject, agent, Run, Decision, Plan, Step, capability,
// resource, tool binding, policy version and executor audience.
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
	value, err := readJSONValueAtDepth(decoder, depth+1)
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
	return readJSONValueAtDepth(decoder, 0)
}

func readJSONValueAtDepth(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, errors.New("JSON nesting depth exceeds limit")
	}
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
			value, err := readJSONValueAtDepth(decoder, depth+1)
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
			value, err := readJSONValueAtDepth(decoder, depth+1)
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

func validateExactSubmissionKeys(value any) error {
	object, ok := value.(map[string]any)
	if !ok {
		return errors.New("ActionRequest submission must be a JSON object")
	}
	topLevel := map[string]struct{}{
		"schema_version": {}, "tenant_id": {}, "subject_id": {}, "agent_id": {},
		"run_id": {}, "decision_id": {}, "plan_id": {}, "plan_hash": {},
		"step_id": {}, "capability": {}, "resource_ref": {}, "arguments": {},
		"tool_binding_digest": {}, "policy_version": {}, "audience": {},
	}
	for key := range object {
		if _, allowed := topLevel[key]; !allowed {
			return fmt.Errorf("unknown or noncanonical ActionRequest field %q", key)
		}
	}
	capability, ok := object["capability"].(map[string]any)
	if !ok {
		return errors.New("capability must be an object")
	}
	capabilityFields := map[string]struct{}{
		"id": {}, "version": {}, "contract_sha256": {},
	}
	for key := range capability {
		if _, allowed := capabilityFields[key]; !allowed {
			return fmt.Errorf("unknown or noncanonical capability field %q", key)
		}
	}
	return nil
}

// Submission is a proposed Runtime-to-Guard input. The key belongs to the
// HTTP Idempotency-Key header and must be persisted by Runtime across retries.
// Guard, not Runtime, creates the operation_id only after a durable claim.
type Submission struct {
	IdempotencyKey string
	Action         ActionRequest
}

// DecodeSubmission enforces the draft ingress boundary. This function does
// not claim, persist, authorize or execute an operation. The HTTP handler must
// derive and cross-check all identity fields from a trusted principal.
func DecodeSubmission(idempotencyKey string, raw []byte) (Submission, error) {
	if !validActionField(idempotencyKey) || len(idempotencyKey) > 128 {
		return Submission{}, errors.New("invalid Guard Idempotency-Key")
	}
	if len(raw) == 0 || len(raw) > maxArgumentsBytes+16*1024 || !utf8.Valid(raw) {
		return Submission{}, errors.New("invalid submission body")
	}

	// Detect ambiguous duplicate fields even when JSON decoding into a Go
	// struct would silently keep the last occurrence.
	first := json.NewDecoder(bytes.NewReader(raw))
	first.UseNumber()
	parsed, err := readJSONValue(first)
	if err != nil {
		return Submission{}, fmt.Errorf("invalid submission JSON: %w", err)
	}
	if err := validateExactSubmissionKeys(parsed); err != nil {
		return Submission{}, err
	}
	if _, err := first.Token(); !errors.Is(err, io.EOF) {
		return Submission{}, errors.New("trailing submission JSON")
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var action ActionRequest
	if err := decoder.Decode(&action); err != nil {
		return Submission{}, fmt.Errorf("invalid submission fields: %w", err)
	}
	if err := action.Validate(); err != nil {
		return Submission{}, err
	}
	return Submission{IdempotencyKey: idempotencyKey, Action: action}, nil
}
