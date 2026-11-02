package action

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func submissionBody(t *testing.T) []byte {
	t.Helper()
	source, err := json.Marshal(validActionRequest())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(source, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "operation_id")
	body, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestSubmissionCarriesKeyButNeverCallerOperationID(t *testing.T) {
	if _, exists := reflect.TypeOf(ActionRequest{}).FieldByName("OperationID"); exists {
		t.Fatal("caller-supplied operation_id still exists on ActionRequest")
	}
	submission, err := DecodeSubmission("runtime-guard-key-1", submissionBody(t))
	if err != nil {
		t.Fatal(err)
	}
	if submission.IdempotencyKey != "runtime-guard-key-1" {
		t.Fatal("lost durable Runtime submission key")
	}
	if submission.Action.RunID != "run-1" || submission.Action.TenantID != "tenant-a" {
		t.Fatal("submission identity was changed")
	}
}

func TestSubmissionRejectsSpoofedOperationAndUnknownFields(t *testing.T) {
	good := submissionBody(t)
	for _, field := range [][]byte{
		[]byte(`"operation_id":"client-forged",`),
		[]byte(`"untrusted_executor":"shell",`),
	} {
		forged := bytes.Replace(good, []byte("{"), append([]byte("{"), field...), 1)
		if _, err := DecodeSubmission("runtime-key", forged); err == nil {
			t.Fatalf("accepted untrusted submission field: %s", field)
		}
	}
}

func TestSubmissionRejectsDuplicateTopLevelIdentity(t *testing.T) {
	forged := bytes.Replace(submissionBody(t), []byte("{"), []byte(`{"tenant_id":"other-tenant",`), 1)
	if _, err := DecodeSubmission("runtime-key", forged); err == nil {
		t.Fatal("duplicate top-level tenant_id was accepted")
	}
}

func TestSubmissionRejectsUnstableKeyAndTrailingData(t *testing.T) {
	body := submissionBody(t)
	for _, key := range []string{"", " whitespace", "two words", "line\nfeed"} {
		if _, err := DecodeSubmission(key, body); err == nil {
			t.Fatalf("accepted invalid idempotency key: %q", key)
		}
	}
	if _, err := DecodeSubmission("runtime-key", append(body, []byte(` {}`)...)); err == nil {
		t.Fatal("accepted trailing JSON")
	}
}

func TestSubmissionRejectsCaseVariantFieldAliases(t *testing.T) {
	body := submissionBody(t)
	for _, replacement := range [][2]string{
		{"tenant_id", "TENANT_ID"},
		{"contract_sha256", "CONTRACT_SHA256"},
	} {
		forged := bytes.Replace(body, []byte(replacement[0]), []byte(replacement[1]), 1)
		if _, err := DecodeSubmission("runtime-key", forged); err == nil {
			t.Fatalf("accepted noncanonical field alias %q", replacement[1])
		}
	}
}

func TestSubmissionRejectsExcessiveJSONDepth(t *testing.T) {
	body := []byte("{\"schema_version\":\"action-request.v1\",\"tenant_id\":\"tenant\",\"subject_id\":\"subject\",\"agent_id\":\"agent\",\"run_id\":\"run\",\"decision_id\":\"decision\",\"plan_id\":\"plan\",\"plan_hash\":\"" + strings.Repeat("a", 64) + "\",\"step_id\":\"step\",\"capability\":{\"id\":\"workspace.write\",\"version\":\"1\",\"contract_sha256\":\"" + strings.Repeat("b", 64) + "\"},\"resource_ref\":\"resource\",\"arguments\":{\"x\":" + strings.Repeat("[", maxJSONDepth+1) + "0" + strings.Repeat("]", maxJSONDepth+1) + "},\"tool_binding_digest\":\"" + strings.Repeat("c", 64) + "\",\"policy_version\":\"p1\",\"audience\":\"executor\"}")
	if _, err := DecodeSubmission("runtime-key", body); err == nil {
		t.Fatal("accepted excessive JSON nesting")
	}
}
