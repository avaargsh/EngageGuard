package postgres

import "testing"

func TestValidPermitEvidenceRequiresPrintableASCII(t *testing.T) {
	for _, value := range []string{
		"run-\u202e1",
		"attempt-\u200b1",
		"approval-\u0085-1",
		"risk-\u00e9",
	} {
		if validPermitEvidence(value) {
			t.Errorf("non-ASCII authority evidence accepted: %q", value)
		}
	}
	for _, value := range []string{
		"run-1",
		"attempt-2",
		"approval-3",
		"risk-17",
	} {
		if !validPermitEvidence(value) {
			t.Errorf("printable ASCII authority evidence rejected: %q", value)
		}
	}
}
