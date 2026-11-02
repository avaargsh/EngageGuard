package action

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSharedJCSNumberVectors(t *testing.T) {
	data, err := os.ReadFile("../../docs/contracts/jcs-number-vectors.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SchemaVersion string `json:"schema_version"`
		Vectors []struct {
			Input string `json:"input"`
			Canonical string `json:"canonical"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.SchemaVersion != "jcs-number-vectors.v1" || len(fixture.Vectors) == 0 {
		t.Fatal("invalid shared JCS numeric fixture")
	}
	for _, vector := range fixture.Vectors {
		t.Run(vector.Input, func(t *testing.T) {
			got, err := canonicalJSONObject([]byte(`{"n":` + vector.Input + `}`))
			if err != nil {
				t.Fatal(err)
			}
			want := `{"n":` + vector.Canonical + `}`
			if string(got) != want {
				t.Fatalf("got %s, want %s", got, want)
			}
		})
	}
}

func TestSharedResolvedActionHashVector(t *testing.T) {
	data, err := os.ReadFile("../../docs/contracts/resolved-action-v1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SchemaVersion string `json:"schema_version"`
		ActionHash struct {
			DomainSeparator string `json:"domain_separator"`
			ActionRequest ActionRequest `json:"action_request"`
			CanonicalJSON string `json:"canonical_json"`
			ExpectedSHA256 string `json:"expected_sha256"`
		} `json:"action_hash"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.SchemaVersion != "resolved-action-v1-vectors" ||
		fixture.ActionHash.DomainSeparator != actionHashDomain {
		t.Fatal("unexpected resolved action hash fixture version or domain separator")
	}
	raw, err := json.Marshal(fixture.ActionHash.ActionRequest)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalJSONObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != fixture.ActionHash.CanonicalJSON {
		t.Fatalf("canonical JSON mismatch: got %s want %s", canonical, fixture.ActionHash.CanonicalJSON)
	}
	got, err := ActionHash(fixture.ActionHash.ActionRequest)
	if err != nil {
		t.Fatal(err)
	}
	if got != fixture.ActionHash.ExpectedSHA256 {
		t.Fatalf("ActionHash mismatch: got %s want %s", got, fixture.ActionHash.ExpectedSHA256)
	}
}
