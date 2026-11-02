package action

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func validActionRequest() ActionRequest {
	return ActionRequest{
		SchemaVersion: "action-request.v1", AgentID: "agent-1", RunID: "run-1",
		DecisionID: "decision-1", PlanID: "plan-1", PlanHash: strings.Repeat("f", 64),
		StepID: "step-1", Capability: ActionCapabilityRequest{ID: "workspace.write", Version: "1.0.0"},
		ResourceRef: "workspace-1",
		Arguments:   []byte(`{"path":"reports/out.txt","content_sha256":"` + strings.Repeat("b", 64) + `"}`),
	}
}

func validAuthenticatedContext() AuthenticatedContext {
	return AuthenticatedContext{TenantID: "tenant-1", SubjectID: "user-1", ActorID: "actor-1", WorkloadID: "runtime-1"}
}

func validCanonicalAction() CanonicalAction {
	return CanonicalAction{
		SchemaVersion: "canonical-action.v1", TenantID: "tenant-1", SubjectID: "user-1",
		ActorID: "actor-1", WorkloadID: "runtime-1", AgentID: "agent-1", RunID: "run-1",
		DecisionID: "decision-1", PlanID: "plan-1", PlanHash: strings.Repeat("f", 64),
		StepID: "step-1", OperationID: "operation-server-1",
		Capability:        ActionCapabilityRef{ID: "workspace.write", Version: "1.0.0", ContractSHA256: strings.Repeat("a", 64)},
		ResourceRef:       "workspace-1",
		Arguments:         []byte(`{"path":"reports/out.txt","content_sha256":"` + strings.Repeat("b", 64) + `"}`),
		ToolBindingDigest: strings.Repeat("c", 64), PolicyVersion: "policy-v1", Audience: "workspace-executor",
	}
}

func TestDecodeActionRequestRejectsGuardOwnedAndUnknownFields(t *testing.T) {
	for _, field := range []string{`"operation_id":"caller-op"`, `"tenant_id":"tenant-forged"`, `"subject_id":"user-forged"`, `"tool_binding_digest":"` + strings.Repeat("c", 64) + `"`, `"policy_version":"policy-v1"`, `"audience":"workspace-executor"`, `"unknown_field":"value"`} {
		raw := []byte(`{"schema_version":"action-request.v1","agent_id":"agent-1","run_id":"run-1","decision_id":"decision-1","plan_id":"plan-1","plan_hash":"` + strings.Repeat("f", 64) + `","step_id":"step-1","capability":{"id":"workspace.write","version":"1.0.0"},"resource_ref":"workspace-1","arguments":{"path":"reports/out.txt","content_sha256":"` + strings.Repeat("b", 64) + `"},` + field + `}`)
		if _, err := DecodeActionRequest(raw); err == nil {
			t.Errorf("accepted Guard-owned field %s", field)
		}
	}
}

func TestDecodeActionRequestReturnsCanonicalArguments(t *testing.T) {
	raw := []byte(`{"schema_version":"action-request.v1","agent_id":"agent-1","run_id":"run-1","decision_id":"decision-1","plan_id":"plan-1","plan_hash":"` + strings.Repeat("f", 64) + `","step_id":"step-1","capability":{"id":"workspace.write","version":"1.0.0"},"resource_ref":"workspace-1","arguments":{ "path":"reports/out.txt", "content_sha256":"` + strings.Repeat("b", 64) + `" }}`)
	decoded, err := DecodeActionRequest(raw)
	if err != nil { t.Fatal(err) }
	want := `{"content_sha256":"` + strings.Repeat("b", 64) + `","path":"reports/out.txt"}`
	if string(decoded.Arguments) != want {
		t.Fatalf("arguments not canonicalized: got %s want %s", decoded.Arguments, want)
	}
}

func TestDecodeActionRequestRejectsDuplicateAndTrailingJSON(t *testing.T) {
	base, _ := json.Marshal(validActionRequest())
	duplicate := strings.TrimSuffix(string(base), "}") + `,"agent_id":"agent-2"}`
	for _, raw := range []string{duplicate, string(base) + ` {}`} {
		if _, err := DecodeActionRequest([]byte(raw)); err == nil {
			t.Errorf("accepted invalid request JSON: %s", raw)
		}
	}
}

func TestRequestHashCanonicalAndBoundToAuthenticatedContext(t *testing.T) {
	request := validActionRequest()
	first, err := RequestHash(request, validAuthenticatedContext())
	if err != nil { t.Fatal(err) }
	request.Arguments = []byte(`{ "content_sha256":"` + strings.Repeat("b", 64) + `", "path":"reports/out.txt" }`)
	second, err := RequestHash(request, validAuthenticatedContext())
	if err != nil { t.Fatal(err) }
	if first != second { t.Fatal("equivalent request objects must have the same RequestHash") }
	otherTenant := validAuthenticatedContext()
	otherTenant.TenantID = "tenant-2"
	third, err := RequestHash(request, otherTenant)
	if err != nil { t.Fatal(err) }
	if third == first { t.Fatal("RequestHash must bind authenticated tenant identity") }
	otherActor := validAuthenticatedContext()
	otherActor.ActorID = "actor-2"
	fourth, err := RequestHash(request, otherActor)
	if err != nil { t.Fatal(err) }
	if fourth == first { t.Fatal("RequestHash must bind authenticated actor identity") }
}

func TestRequestHashRejectsInvalidUTF8Identity(t *testing.T) {
	request := validActionRequest()
	request.AgentID = string([]byte{0xff})
	if _, err := RequestHash(request, validAuthenticatedContext()); err == nil {
		t.Fatal("accepted invalid UTF-8 request identity")
	}
	context := validAuthenticatedContext()
	context.SubjectID = string([]byte{0xff})
	if _, err := RequestHash(validActionRequest(), context); err == nil {
		t.Fatal("accepted invalid UTF-8 authenticated identity")
	}
}

func TestIdempotencyKeyValidation(t *testing.T) {
	for _, key := range []string{"key-1", "01JDGZ3F0J4Z7D2A3VQ2P2M8XZ", strings.Repeat("a", 128)} {
		if err := ValidateIdempotencyKey(key); err != nil { t.Errorf("rejected valid key %q: %v", key, err) }
	}
	for _, key := range []string{"", " leading", "trailing ", "two words", "line\nbreak", strings.Repeat("a", 129), "é"} {
		if err := ValidateIdempotencyKey(key); err == nil { t.Errorf("accepted invalid key %q", key) }
	}
}

func TestActionHashBindsEveryResolvedAuthorizationDimension(t *testing.T) {
	original := validCanonicalAction()
	approved, err := ActionHash(original)
	if err != nil { t.Fatal(err) }
	mutations := map[string]func(*CanonicalAction){
		"tenant": func(a *CanonicalAction) { a.TenantID = "tenant-2" },
		"subject": func(a *CanonicalAction) { a.SubjectID = "user-2" },
		"actor": func(a *CanonicalAction) { a.ActorID = "actor-2" },
		"workload": func(a *CanonicalAction) { a.WorkloadID = "runtime-2" },
		"agent": func(a *CanonicalAction) { a.AgentID = "agent-2" },
		"run": func(a *CanonicalAction) { a.RunID = "run-2" },
		"decision": func(a *CanonicalAction) { a.DecisionID = "decision-2" },
		"plan": func(a *CanonicalAction) { a.PlanID = "plan-2" },
		"plan-hash": func(a *CanonicalAction) { a.PlanHash = strings.Repeat("9", 64) },
		"step": func(a *CanonicalAction) { a.StepID = "step-2" },
		"operation": func(a *CanonicalAction) { a.OperationID = "operation-server-2" },
		"capability-version": func(a *CanonicalAction) { a.Capability.Version = "2.0.0" },
		"capability-contract": func(a *CanonicalAction) { a.Capability.ContractSHA256 = strings.Repeat("d", 64) },
		"resource": func(a *CanonicalAction) { a.ResourceRef = "workspace-2" },
		"arguments": func(a *CanonicalAction) { a.Arguments = []byte(`{"path":"reports/other.txt","content_sha256":"` + strings.Repeat("b", 64) + `"}`) },
		"tool-binding": func(a *CanonicalAction) { a.ToolBindingDigest = strings.Repeat("e", 64) },
		"policy": func(a *CanonicalAction) { a.PolicyVersion = "policy-v2" },
		"audience": func(a *CanonicalAction) { a.Audience = "other-executor" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := original
			mutate(&changed)
			if ApprovalMatchesActionHash(approved, changed) { t.Fatal("modified action reused approval") }
		})
	}
	if !ApprovalMatchesActionHash(approved, original) { t.Fatal("unchanged action did not match approval") }
}

func TestCanonicalJSONRejectsAmbiguousOrExcessiveArguments(t *testing.T) {
	bad := []string{
		`[]`, `{"x":1,"x":2}`, `{"outer":{"x":1,"x":2}}`,
		`{"x":1} trailing`, `{"x":`, `{"x":"\uD800"}`, `{"x":"\uDC00"}`,
	}
	for _, raw := range bad {
		t.Run(fmt.Sprintf("%x", []byte(raw)), func(t *testing.T) {
			if _, err := canonicalJSONObject([]byte(raw)); err == nil { t.Fatalf("accepted %s", raw) }
		})
	}
	deep := `{"x":` + strings.Repeat("[", maxJSONDepth+2) + `0` + strings.Repeat("]", maxJSONDepth+2) + `}`
	if _, err := canonicalJSONObject([]byte(deep)); err == nil { t.Fatal("accepted over-deep JSON") }
}

func TestJCSAcceptsValidSurrogatePair(t *testing.T) {
	got, err := canonicalJSONObject([]byte(`{"x":"\\uD83D\\uDE00"}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"x":"😀"}` {
		t.Fatalf("unexpected canonical Unicode: %q", got)
	}
}

func TestWorkspaceWriteRejectsUnknownArgumentFields(t *testing.T) {
	a := validCanonicalAction()
	a.Arguments = []byte(`{"path":"reports/out.txt","content_sha256":"` + strings.Repeat("b", 64) + `","overwrite":true}`)
	if _, err := ActionHash(a); err == nil { t.Fatal("accepted unsupported workspace.write argument") }
}

func TestWorkspaceWriteRejectsLexicallyUnsafePaths(t *testing.T) {
	for _, value := range []string{"../secret", "./reports/a", "/etc/passwd", "reports/../secret", "reports\\secret", "reports//a", ".", "C:/secret", "reports/a/"} {
		a := validCanonicalAction()
		a.Arguments = []byte(`{"path":` + strconvQuote(value) + `,"content_sha256":"` + strings.Repeat("b", 64) + `"}`)
		if _, err := ActionHash(a); err == nil { t.Errorf("accepted unsafe workspace path %q", value) }
	}
}

func strconvQuote(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func TestJCSNumberFormattingVectors(t *testing.T) {
	vectors := map[string]string{
		"0": "0", "-0": "0", "-0.0": "0", "4.50": "4.5", "2e-3": "0.002",
		"1e-6": "0.000001", "1e-7": "1e-7", "1e20": "100000000000000000000",
		"1e21": "1e+21", "1e30": "1e+30", "1e-27": "1e-27", "1e-324": "0", "5e-324": "5e-324",
		"333333333.33333329": "333333333.3333333",
	}
	for input, want := range vectors {
		t.Run(input, func(t *testing.T) {
			got, err := canonicalJSONObject([]byte(`{"n":` + input + `}`))
			if err != nil { t.Fatal(err) }
			if string(got) != `{"n":`+want+`}` { t.Fatalf("got %s, want %s", got, want) }
		})
	}
	for _, input := range []string{"1e400", "-1e400"} {
		if _, err := canonicalJSONObject([]byte(`{"n":` + input + `}`)); err == nil { t.Errorf("accepted out-of-range number %s", input) }
	}
}

func TestJCSUTF16PropertyOrderingAndUnicodeEscaping(t *testing.T) {
	raw := []byte("{\"\uE000\":1,\"\U00010000\":2,\"text\":\"<>&/\\u2028\\n\"}")
	got, err := canonicalJSONObject(raw)
	if err != nil { t.Fatal(err) }
	canonical := string(got)
	bmp := strings.Index(canonical, "\uE000")
	nonBMP := strings.Index(canonical, "\U00010000")
	if nonBMP < 0 || bmp < 0 || nonBMP >= bmp { t.Fatalf("keys are not sorted by UTF-16 code units: %q", canonical) }
	wantText := "\"text\":\"<>&/" + "\u2028" + "\\n\""
	if !strings.Contains(canonical, wantText) { t.Fatalf("unexpected JCS string escaping: %q", canonical) }
}
