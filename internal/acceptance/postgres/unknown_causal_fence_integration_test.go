package postgres

import (
	"context"
	"testing"
)

// Test the durable state/journal invariant independently of the Go helper.
// These are isolated database fixtures, not provider execution.
func TestUnknownCausalFenceRequiresMatchingStateAndJournal(t *testing.T) {
	for _, tc := range []struct {
		name      string
		state     bool
		journal   bool
		wantValid bool
	}{
		{name: "state-only", state: true},
		{name: "journal-only", journal: true},
		{name: "matching", state: true, journal: true, wantValid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, resolved, permitID := seededWorkspacePermit(t)
			ctx := context.Background()
			intent, err := store.ClaimAuthorizedIntent(ctx, permitID, resolved)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := store.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if tc.state {
				if _, err := tx.ExecContext(ctx, `
					UPDATE guard_operation_intents SET state='UNKNOWN'
					WHERE tenant_id=$1 AND attempt_id=$2::uuid
				`, intent.TenantID, intent.AttemptID); err != nil {
					t.Fatalf("stage UNKNOWN state: %v", err)
				}
			}
			if tc.journal {
				if _, err := tx.ExecContext(ctx, `
					INSERT INTO guard_operation_unknown_events
						(tenant_id,operation_id,permit_id,attempt_id,action_hash,reason)
					VALUES ($1,$2::uuid,$3::uuid,$4::uuid,$5,'ACK_LOST')
				`, intent.TenantID, intent.OperationID, intent.PermitID, intent.AttemptID, intent.ActionHash); err != nil {
					t.Fatalf("stage UNKNOWN journal: %v", err)
				}
			}
			err = tx.Commit()
			if tc.wantValid && err != nil {
				t.Fatalf("valid state and journal rejected: %v", err)
			}
			if !tc.wantValid && err == nil {
				t.Error("inconsistent UNKNOWN state/journal committed")
			}
			var state string
			var count int
			if err := store.db.QueryRowContext(ctx, `
				SELECT i.state, (SELECT count(*) FROM guard_operation_unknown_events e
					WHERE e.tenant_id=i.tenant_id AND e.attempt_id=i.attempt_id)
				FROM guard_operation_intents i
				WHERE i.tenant_id=$1 AND i.attempt_id=$2::uuid
			`, intent.TenantID, intent.AttemptID).Scan(&state, &count); err != nil {
				t.Fatal(err)
			}
			wantState, wantCount := "DISPATCHING", 0
			if tc.wantValid {
				wantState, wantCount = "UNKNOWN", 1
			}
			if state != wantState || count != wantCount {
				t.Fatalf("durable state/journal = %s/%d; want %s/%d", state, count, wantState, wantCount)
			}
		})
	}
}

func TestUnknownCausalFenceRejectsReturnToDispatching(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	ctx := context.Background()
	intent, err := store.ClaimAuthorizedIntent(ctx, permitID, resolved)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkDispatchUnknown(ctx, intent.TenantID, intent.OperationID, intent.AttemptID, "ACK_LOST"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `
		UPDATE guard_operation_intents SET state='DISPATCHING'
		WHERE tenant_id=$1 AND attempt_id=$2::uuid
	`, intent.TenantID, intent.AttemptID); err == nil {
		t.Error("durable UNKNOWN attempt returned to DISPATCHING")
	}
	state, err := store.GetDispatchState(ctx, intent.TenantID, intent.OperationID, intent.AttemptID)
	if err != nil || state.State != "UNKNOWN" || state.Reason != "ACK_LOST" {
		t.Fatalf("UNKNOWN evidence did not survive reversal attempt: %+v %v", state, err)
	}
}
