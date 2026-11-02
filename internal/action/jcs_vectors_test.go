package action

import (
	"encoding/json"
	"fmt"
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
		Vectors       []struct {
			Input     string `json:"input"`
			Canonical string `json:"canonical"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.SchemaVersion != "jcs-number-vectors.v1" || len(fixture.Vectors) == 0 {
		t.Fatal("invalid shared JCS fixture")
	}
	for _, vector := range fixture.Vectors {
		t.Run(vector.Input, func(t *testing.T) {
			got, err := canonicalJSONObject([]byte(`{"n":` + vector.Input + `}`))
			if err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf(`{"n":%s}`, vector.Canonical)
			if string(got) != want {
				t.Fatalf("got %s, want %s", got, want)
			}
		})
	}
}
