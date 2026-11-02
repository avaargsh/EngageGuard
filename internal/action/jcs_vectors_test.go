package action

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceActionHashCrossLanguageGoldenVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "workspace-actionhash-v01.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SchemaVersion   string `json:"schema_version"`
		DomainSeparator string `json:"domain_separator"`
		Vectors         []struct {
			Name      string         `json:"name"`
			Action    WorkspaceWrite `json:"action"`
			Canonical string         `json:"canonical"`
			SHA256    string         `json:"sha256"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.SchemaVersion != "workspace-actionhash-fixtures.v0.1" ||
		fixture.DomainSeparator != "engageguard/action-hash/v1\\u0000" ||
		len(fixture.Vectors) != 4 {
		t.Fatal("unexpected fixture protocol or vector count")
	}
	unique := make(map[string]struct{})
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			if err := vector.Action.Validate(); err != nil {
				t.Fatal(err)
			}
			if string(canonicalJSON(vector.Action)) != vector.Canonical {
				t.Fatalf("canonical JSON mismatch for %s", vector.Name)
			}
			digest, err := Hash(vector.Action)
			if err != nil || digest != vector.SHA256 {
				t.Fatalf("hash mismatch for %s: got %q; want %q; err=%v", vector.Name, digest, vector.SHA256, err)
			}
			if !ApprovalMatches(vector.SHA256, vector.Action) {
				t.Fatal("matching action cannot be approved")
			}
			mutated := vector.Action
			mutated.WorkspaceID += "-mutated"
			if ApprovalMatches(vector.SHA256, mutated) {
				t.Fatal("mutated action reused existing approval")
			}
			if _, exists := unique[digest]; exists {
				t.Fatal("nonunique fixture ActionHash")
			}
			unique[digest] = struct{}{}
		})
	}
}
