package action

import (
	"strings"
	"testing"
)

func validActionRequest() ActionRequest {
	return ActionRequest{
		SchemaVersion: "action-request.v1", TenantID: "tenant-a", SubjectID: "user-1",
		AgentID: "agent-1", RunID: "run-1", DecisionID: "dec_aaaaaaaa",
		PlanID: "plan-1", PlanHash: strings.Repeat("f", 64), StepID: "step-1", OperationID: "op-1",
		Capability: ActionCapabilityRef{ID: "workspace.write", Version: "1.0.0", ContractSHA256: strings.Repeat("a", 64)},
		ResourceRef: "workspace-1", Arguments: []byte(`{"path":"reports/out.txt","content_sha256":"bbbb"}`),
		ToolBindingDigest: strings.Repeat("c", 64), PolicyVersion: "policy-v1", Audience: "workspace-executor",
	}
}

func TestActionHashStableAndCanonicalizesArgumentObject(t *testing.T) {
	a := validActionRequest()
	first, err := ActionHash(a)
	if err != nil { t.Fatal(err) }
	a.Arguments = []byte(`{ "content_sha256":"bbbb", "path":"reports/out.txt" }`)
	second, err := ActionHash(a)
	if err != nil { t.Fatal(err) }
	if first != second { t.Fatal("equivalent argument objects must hash identically") }
	if !ApprovalMatchesActionHash(first, a) { t.Fatal("matching approved action hash rejected") }
}

func TestActionHashBindsEveryAuthorizationDimension(t *testing.T) {
	original := validActionRequest()
	approved, err := ActionHash(original)
	if err != nil { t.Fatal(err) }
	mutations := map[string]func(*ActionRequest){
		"tenant": func(a *ActionRequest) { a.TenantID = "tenant-b" },
		"subject": func(a *ActionRequest) { a.SubjectID = "user-2" },
		"agent": func(a *ActionRequest) { a.AgentID = "agent-2" },
		"run": func(a *ActionRequest) { a.RunID = "run-2" },
		"decision": func(a *ActionRequest) { a.DecisionID = "dec_bbbbbbbb" },
		"plan": func(a *ActionRequest) { a.PlanID = "plan-2" },
		"plan-hash": func(a *ActionRequest) { a.PlanHash = strings.Repeat("9", 64) },
		"step": func(a *ActionRequest) { a.StepID = "step-2" },
		"operation": func(a *ActionRequest) { a.OperationID = "op-2" },
		"capability-version": func(a *ActionRequest) { a.Capability.Version = "2.0.0" },
		"capability-contract": func(a *ActionRequest) { a.Capability.ContractSHA256 = strings.Repeat("d", 64) },
		"resource": func(a *ActionRequest) { a.ResourceRef = "workspace-2" },
		"arguments": func(a *ActionRequest) { a.Arguments = []byte(`{"path":"reports/other.txt"}`) },
		"tool-binding": func(a *ActionRequest) { a.ToolBindingDigest = strings.Repeat("e", 64) },
		"policy": func(a *ActionRequest) { a.PolicyVersion = "policy-v2" },
		"audience": func(a *ActionRequest) { a.Audience = "other-executor" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := original
			mutate(&changed)
			if ApprovalMatchesActionHash(approved, changed) { t.Fatal("modified action reused approval") }
		})
	}
}

func TestActionHashRejectsAmbiguousArguments(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"x":1,"x":2}`),
		[]byte(`{"outer":{"x":1,"x":2}}`),
		[]byte(`[]`),
		[]byte(`{"x":1} trailing`),
		[]byte(`{"x":`),
	} {
		a := validActionRequest()
		a.Arguments = raw
		if _, err := ActionHash(a); err == nil { t.Errorf("accepted ambiguous arguments %s", raw) }
	}
}

func TestActionHashRejectsInvalidBindings(t *testing.T) {
	cases := []func(*ActionRequest){
		func(a *ActionRequest) { a.SchemaVersion = "v0" },
		func(a *ActionRequest) { a.ToolBindingDigest = "invalid" },
		func(a *ActionRequest) { a.Capability.ContractSHA256 = "invalid" },
		func(a *ActionRequest) { a.Audience = " " },
		func(a *ActionRequest) { a.Arguments = []byte(strings.Repeat(" ", maxArgumentsBytes+1)) },
	}
	for i, mutate := range cases {
		a := validActionRequest()
		mutate(&a)
		if _, err := ActionHash(a); err == nil { t.Errorf("case %d accepted", i) }
	}
}

func TestApprovalMatchFailsClosedForMalformedDigest(t *testing.T) {
	if ApprovalMatchesActionHash("invalid", validActionRequest()) { t.Fatal("malformed digest matched") }
}
