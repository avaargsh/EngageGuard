package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The accepted-source reader is a recovery-only interface. An external
// OperationID selector must be canonical before reaching a PostgreSQL UUID
// coercion, rather than surfacing driver-specific 22P02 or accepting an
// alternate spelling for the same authenticated operation.
func TestReadAcceptedSubmissionRejectsNoncanonicalOperationSelector(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	op, created, err := store.Accept(ctx, "tenant-a", "canonical-source-selector", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("seed original accepted source: op=%+v created=%t err=%v", op, created, err)
	}
	selectors := []string{
		"not-a-uuid",
		op.OperationID + "' OR TRUE",
	}
	if upper := strings.ToUpper(op.OperationID); upper != op.OperationID {
		selectors = append(selectors, upper)
	}
	for _, selector := range selectors {
		t.Run(selector, func(t *testing.T) {
			got, err := store.ReadAcceptedSubmission(ctx, "tenant-a", selector)
			if !errors.Is(err, ErrSnapshotMissing) || got.Operation.OperationID != "" || len(got.Raw) != 0 {
				t.Fatalf("untrusted source selector %q returned record=%+v bytes=%d err=%v; want ErrSnapshotMissing",
					selector, got.Operation, len(got.Raw), err)
			}
		})
	}
	original, err := store.ReadAcceptedSubmission(ctx, "tenant-a", op.OperationID)
	if err != nil || original.Operation.OperationID != op.OperationID || len(original.Raw) == 0 {
		t.Fatalf("canonical authentic source changed by selector rejection: %+v bytes=%d err=%v",
			original.Operation, len(original.Raw), err)
	}
}
