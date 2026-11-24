package postgres

import (
	"context"
	"errors"
	"testing"
)

// An immutable UNKNOWN journal must never be interpreted as a dispatch grant,
// even if a legacy or inconsistent ledger still labels the Intent DISPATCHING.
// This is a local PostgreSQL fixture; no provider or external effect is called.
func TestPreEffectLedgerRejectsUnknownJournalWithoutStateTransition(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	ctx := context.Background()
	intent, err := store.ClaimAuthorizedIntent(ctx, permitID, resolved)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.InspectPreEffectLedger(ctx, permitID, intent.AttemptID, resolved); err != nil {
		t.Fatalf("valid control rejected: %v", err)
	}

	// v15 normally makes this mismatch impossible. Simulate a privileged
	// historical/catalog corruption without weakening the final runtime
	// configuration: suppress only the v15 journal trigger for this insert,
	// restore ENABLE ALWAYS before commit, then test the read-side fence.
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		"ALTER TABLE guard_operation_unknown_events DISABLE TRIGGER guard_unknown_journal_commit_v15"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO guard_operation_unknown_events
		    (tenant_id,operation_id,permit_id,attempt_id,action_hash,reason)
		VALUES ($1,$2::uuid,$3::uuid,$4::uuid,$5,'ACK_LOST')
	`, intent.TenantID, intent.OperationID, intent.PermitID, intent.AttemptID, intent.ActionHash); err != nil {
		t.Fatalf("fixture could not persist exact UNKNOWN evidence: %v", err)
	}
	if _, err := tx.ExecContext(ctx,
		"ALTER TABLE guard_operation_unknown_events ENABLE ALWAYS TRIGGER guard_unknown_journal_commit_v15"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	var state string
	if err := store.db.QueryRowContext(ctx, `
		SELECT state FROM guard_operation_intents WHERE attempt_id=$1::uuid
	`, intent.AttemptID).Scan(&state); err != nil || state != "DISPATCHING" {
		t.Fatalf("fixture did not retain DISPATCHING state: %s, %v", state, err)
	}

	if err := store.InspectPreEffectLedger(ctx, permitID, intent.AttemptID, resolved); !errors.Is(err, ErrPreEffectBlocked) {
		t.Fatalf("pre-effect inspection accepted DISPATCHING despite durable UNKNOWN evidence: %v", err)
	}
}
