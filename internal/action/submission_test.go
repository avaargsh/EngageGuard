package action

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func exampleSubmission() []byte {
	return []byte(`{"schema_version":"action-submission.v1","run_id":"run-1","decision_id":"dec-1","plan_id":"plan-1","plan_hash":"` + strings.Repeat("a", 64) + `","step_id":"step-1","capability":{"id":"workspace.write","version":"1.0.0"},"resource_ref":"workspace-1","arguments":{"path":"docs/a.txt","content":"hi","metadata":{"revision":2}}}`)
}

func TestSubmissionAcceptsOnlyUntrustedIntent(t *testing.T) {
	s, err := ParseActionSubmission(exampleSubmission())
	if err != nil {
		t.Fatal(err)
	}
	if s.RunID != "run-1" || s.Capability.ID != "workspace.write" {
		t.Fatalf("wrong input: %+v", s)
	}
	forbidden := []string{"operation_id", "tenant_id", "subject_id", "agent_id", "policy_version", "tool_binding_digest", "audience", "approval_id", "executor_url"}
	for _, field := range forbidden {
		t.Run(field, func(t *testing.T) {
			raw := bytes.Replace(exampleSubmission(), []byte(`"run_id":`), []byte(`"`+field+`":"attacker", "run_id":`), 1)
			if _, err := ParseActionSubmission(raw); err == nil {
				t.Fatalf("accepted caller-controlled %s", field)
			}
		})
	}
}

func TestSubmissionReplayDigestIsByteExact(t *testing.T) {
	original := exampleSubmission()
	digest, err := SubmissionDigest(original)
	if err != nil || len(digest) != 64 {
		t.Fatalf("digest: %s %v", digest, err)
	}
	again, err := SubmissionDigest(append([]byte(nil), original...))
	if err != nil || again != digest {
		t.Fatal("same submitted bytes must replay")
	}
	changed := bytes.Replace(original, []byte("docs/a.txt"), []byte("docs/b.txt"), 1)
	altered, err := SubmissionDigest(changed)
	if err != nil || altered == digest {
		t.Fatal("mutated submission must conflict")
	}
	reformatted := bytes.Replace(original, []byte(`"run_id"`), []byte(` "run_id"`), 1)
	different, err := SubmissionDigest(reformatted)
	if err != nil || different == digest {
		t.Fatal("byte-distinct retry must conflict until normative JCS is frozen")
	}
}

func TestSubmissionRejectsDuplicateAndMalformedJSON(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"run_id":"one","run_id":"two"}`),
		bytes.Replace(exampleSubmission(), []byte(`"metadata":{"revision":2}`), []byte(`"metadata":{"revision":1,"revision":2}`), 1),
		[]byte(`[]`),
		append(exampleSubmission(), []byte(` true`)...),
		bytes.Repeat([]byte("x"), maxSubmissionBytes+1),
		[]byte(`{"schema_version":"action-submission.v1","arguments":`),
		append([]byte{}, 0xff),
	}
	for i, raw := range cases {
		if _, err := ParseActionSubmission(raw); err == nil {
			t.Errorf("bad body %d accepted", i)
		}
	}
}

func TestSubmissionKeyValidation(t *testing.T) {
	for _, s := range []string{"run-1:step.2", "submission_key_123", "A-9"} {
		if err := ValidateSubmissionKey(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "a b", "\tfoo", "hello\nworld", strings.Repeat("a", 129), "é", "a/b"} {
		if err := ValidateSubmissionKey(s); err == nil {
			t.Errorf("bad key %q accepted", s)
		}
	}
}

func TestSubmissionRejectsCallerCapabilityContractDigest(t *testing.T) {
	forged := bytes.Replace(exampleSubmission(), []byte(`"version":"1.0.0"`), []byte(`"version":"1.0.0","contract_sha256":"`+strings.Repeat("b",64)+`"`), 1)
	if _, err := ParseActionSubmission(forged); err == nil {
		t.Fatal("accepted caller-provided capability contract digest")
	}
}

func TestSubmissionSchemaHasNoServerOwnedFields(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal(exampleSubmission(), &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"operation_id", "tenant_id", "policy_version", "tool_binding_digest"} {
		if _, ok := m[key]; ok {
			t.Fatalf("server-owned field present: %s", key)
		}
	}
}
