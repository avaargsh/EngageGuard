package action

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSharedActionHashVectors(t *testing.T) {
	data, err := os.ReadFile("../../docs/contracts/action-hash-vectors.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SchemaVersion string `json:"schema_version"`
		RequestHash   struct {
			DomainSeparator      string               `json:"domain_separator"`
			AuthenticatedContext AuthenticatedContext `json:"authenticated_context"`
			Request              ActionRequest        `json:"request"`
			ExpectedSHA256       string               `json:"expected_sha256"`
		} `json:"request_hash"`
		ActionHash struct {
			DomainSeparator string          `json:"domain_separator"`
			CanonicalAction CanonicalAction `json:"canonical_action"`
			ExpectedSHA256  string          `json:"expected_sha256"`
		} `json:"action_hash"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.SchemaVersion != "engageguard-hash-vectors.v1" {
		t.Fatalf("unexpected fixture version %q", fixture.SchemaVersion)
	}
	if fixture.RequestHash.DomainSeparator != requestHashDomain || fixture.ActionHash.DomainSeparator != actionHashDomain {
		t.Fatal("shared vector domain separators do not match implementation")
	}
	requestHash, err := RequestHash(fixture.RequestHash.Request, fixture.RequestHash.AuthenticatedContext)
	if err != nil {
		t.Fatal(err)
	}
	if requestHash != fixture.RequestHash.ExpectedSHA256 {
		t.Fatalf("RequestHash vector mismatch: got %s want %s", requestHash, fixture.RequestHash.ExpectedSHA256)
	}
	actionHash, err := ActionHash(fixture.ActionHash.CanonicalAction)
	if err != nil {
		t.Fatal(err)
	}
	if actionHash != fixture.ActionHash.ExpectedSHA256 {
		t.Fatalf("ActionHash vector mismatch: got %s want %s", actionHash, fixture.ActionHash.ExpectedSHA256)
	}
}
