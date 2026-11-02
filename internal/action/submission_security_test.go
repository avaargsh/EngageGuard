package action

import (
	"bytes"
	"strings"
	"testing"
)

func TestSubmissionRejectsCaseInsensitiveIdentityAliases(t *testing.T) {
	for _, tc := range []struct {
		name        string
		old         string
		replacement string
	}{
		{"top-level alias", `"run_id"`, `"RUN_ID"`},
		{"nested capability version alias", `"version":"1.0.0"`, `"VERSION":"1.0.0"`},
		{"nested capability id alias", `"id":"workspace.write"`, `"ID":"workspace.write"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			malformed := bytes.Replace(exampleSubmission(), []byte(tc.old), []byte(tc.replacement), 1)
			if bytes.Equal(malformed, exampleSubmission()) {
				t.Fatal("fixture did not change")
			}
			if _, err := ParseActionSubmission(malformed); err == nil {
				t.Fatal("accepted case-insensitive alias")
			}
		})
	}
}

func TestSubmissionRejectsCaseConflictingDuplicateFields(t *testing.T) {
	forged := bytes.Replace(exampleSubmission(), []byte("\"run_id\":"), []byte("\"RUN_ID\":\"attacker\", \"run_id\":"), 1)
	if _, err := ParseActionSubmission(forged); err == nil {
		t.Fatal("accepted case-conflicting alias")
	}
}

func TestSubmissionRejectsExcessiveNestingBeforeRecursiveParse(t *testing.T) {
	origin := exampleSubmission()
	deep := "\"chain\":" + strings.Repeat("[", 129) + "0" + strings.Repeat("]", 129)
	forged := bytes.Replace(origin, []byte("\"metadata\":{\"revision\":2}"), []byte("\"metadata\":{"+deep+"}"), 1)
	if _, err := ParseActionSubmission(forged); err == nil {
		t.Fatal("accepted excessive depth")
	}
}
