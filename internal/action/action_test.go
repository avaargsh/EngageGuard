package action

import (
	"strings"
	"testing"
)

func sample() WorkspaceWrite {
	return WorkspaceWrite{SchemaVersion: "v0.1", TenantID: "tenant-1", SubjectID: "user-1",
		AgentID: "agent-1", OperationID: "op-1", CapabilityID: "workspace.write",
		ToolBindingDigest: strings.Repeat("a", 64), PolicyVersion: "policy-v1", Audience: "workspace-executor",
		WorkspaceID: "workspace-1", RelativePath: "docs/report.txt", ContentDigest: strings.Repeat("b", 64)}
}

func TestHashStableAndApproved(t *testing.T) {
	action := sample()
	a, err := Hash(action)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Hash(action)
	if err != nil {
		t.Fatal(err)
	}
	if a != b || len(a) != 64 || !ApprovalMatches(a, action) {
		t.Fatal("hash stability failure")
	}
}

func TestCanonicalJSONUsesJCSPropertyOrderAndStringEscaping(t *testing.T) {
	a := sample()
	a.WorkspaceID = "ws<>&/\"line\\break\n" + "\u2028" + "tail"
	got := string(canonicalJSON(a))
	wantFragment := `"workspace_id":"ws<>&/\\\"line\\\\break\\n` + "\u2028" + `tail"`
	if !strings.Contains(got, wantFragment) {
		t.Fatalf("JCS string escaping mismatch: %q", got)
	}
	keys := []string{
		`"agent_id":`, `"audience":`, `"capability_id":`, `"content_digest":`,
		`"operation_id":`, `"policy_version":`, `"relative_path":`, `"schema_version":`,
		`"subject_id":`, `"tenant_id":`, `"tool_binding_digest":`, `"workspace_id":`,
	}
	last := -1
	for _, key := range keys {
		position := strings.Index(got, key)
		if position <= last {
			t.Fatalf("property %q is not in canonical order: %q", key, got)
		}
		last = position
	}
}

func TestApprovalInvalidatedByAnyBindingChange(t *testing.T) {
	orig := sample()
	approved, _ := Hash(orig)
	edits := map[string]func(*WorkspaceWrite){
		"tenant":    func(a *WorkspaceWrite) { a.TenantID = "tenant-2" },
		"subject":   func(a *WorkspaceWrite) { a.SubjectID = "user-2" },
		"agent":     func(a *WorkspaceWrite) { a.AgentID = "agent-2" },
		"operation": func(a *WorkspaceWrite) { a.OperationID = "op-2" },
		"binding":   func(a *WorkspaceWrite) { a.ToolBindingDigest = strings.Repeat("c", 64) },
		"policy":    func(a *WorkspaceWrite) { a.PolicyVersion = "policy-v2" },
		"audience":  func(a *WorkspaceWrite) { a.Audience = "other-executor" },
		"workspace": func(a *WorkspaceWrite) { a.WorkspaceID = "workspace-2" },
		"path":      func(a *WorkspaceWrite) { a.RelativePath = "docs/other.txt" },
		"content":   func(a *WorkspaceWrite) { a.ContentDigest = strings.Repeat("d", 64) },
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			changed := orig
			edit(&changed)
			if ApprovalMatches(approved, changed) {
				t.Fatal("changed action accepted")
			}
		})
	}
}

func TestRejectNoncanonicalPaths(t *testing.T) {
	for _, p := range []string{"../secret", "./docs/file", "/etc/passwd", "dir/../file", "dir\\file", "file/", ".", "a//b", "file\x00txt"} {
		t.Run(p, func(t *testing.T) {
			a := sample()
			a.RelativePath = p
			if _, err := Hash(a); err == nil {
				t.Fatal("path accepted")
			}
		})
	}
}

func TestRejectBadDigestAndCapability(t *testing.T) {
	a := sample()
	a.ContentDigest = "wrong"
	if _, err := Hash(a); err == nil {
		t.Fatal("bad digest accepted")
	}
	a = sample()
	a.CapabilityID = "shell.run"
	if _, err := Hash(a); err == nil {
		t.Fatal("unbound capability accepted")
	}
}

func TestRejectForgedApprovedDigest(t *testing.T) {
	if ApprovalMatches(strings.Repeat("0", 64), sample()) {
		t.Fatal("wrong approval matched")
	}
	if ApprovalMatches("bad", sample()) {
		t.Fatal("invalid approval matched")
	}
}

func TestHashMatchesV01GoldenVector(t *testing.T) {
	a := sample()
	wantCanonical := `{"agent_id":"agent-1","audience":"workspace-executor","capability_id":"workspace.write","content_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","operation_id":"op-1","policy_version":"policy-v1","relative_path":"docs/report.txt","schema_version":"v0.1","subject_id":"user-1","tenant_id":"tenant-1","tool_binding_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","workspace_id":"workspace-1"}`
	if got := string(canonicalJSON(a)); got != wantCanonical {
		t.Fatalf("canonical JSON mismatch:\n got: %s\nwant: %s", got, wantCanonical)
	}
	got, err := Hash(a)
	if err != nil {
		t.Fatal(err)
	}
	const wantHash = "5dbeace589dcd3578e124aa8a90959e394822872bd973f41a36f88226681fa8f"
	if got != wantHash {
		t.Fatalf("ActionHash mismatch: got %s want %s", got, wantHash)
	}
}

func TestHashMatchesUnicodeJCSVectors(t *testing.T) {
	a := sample()
\ta.WorkspaceID = "ws<>&/\"line\\break\n" + "\u2028" + "tail"
	got, err := Hash(a)
	if err != nil {
		t.Fatal(err)
	}
	const wantHash = "411e40272cb19ddc868174ec995f3cda73d41c18451c903d6a75854e02c473a9"
	if got != wantHash {
		t.Fatalf("Unicode ActionHash mismatch: got %s want %s", got, wantHash)
	}
}
