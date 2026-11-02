package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// These tests intentionally use direct SQL to verify the database boundary,
// not only the trusted Go writer. Invalid rows must fail on a real PG16 DB.
func TestLedgerRejectsPermitAttachedToDifferentOperation(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	second, created, err := store.Accept(context.Background(), resolved.TenantID, "key-other-operation", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("second operation: created=%v err=%v", created, err)
	}
	hash, err := action.Hash(resolved)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.db.Exec(`
		INSERT INTO guard_operation_intents
			(tenant_id, operation_id, permit_id, action_hash, binding_digest, state)
		VALUES ($1,$2::uuid,$3::uuid,$4,$5,'DISPATCHING')
	`, resolved.TenantID, second.OperationID, permitID, hash, resolved.ToolBindingDigest)
	if err == nil {
		t.Fatal("ledger accepted an intent bound to a permit for another operation")
	}
}

func TestLedgerRejectsAuditOperationMismatch(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	intent, err := store.ClaimAuthorizedIntent(context.Background(), permitID, resolved)
	if err != nil {
		t.Fatal(err)
	}
	second, created, err := store.Accept(context.Background(), resolved.TenantID, "key-other-audit", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("second operation: created=%v err=%v", created, err)
	}
	_, err = store.db.Exec(`
		INSERT INTO guard_execution_audit
			(tenant_id, operation_id, permit_id, attempt_id, event_type, action_hash)
		VALUES ($1,$2::uuid,$3::uuid,$4::uuid,'guard.operation.dispatching.v1',$5)
	`, resolved.TenantID, second.OperationID, permitID, intent.AttemptID, intent.ActionHash)
	if err == nil {
		t.Fatal("ledger accepted audit with an unrelated operation ID")
	}
}

func TestLedgerRejectsPostClaimBindingOrHashTampering(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query string
	}{
		{
			name: "intent binding",
			query: `UPDATE guard_operation_intents SET binding_digest=$2
				WHERE permit_id=$1::uuid`,
		},
		{
			name: "intent action hash",
			query: `UPDATE guard_operation_intents SET action_hash=$2
				WHERE permit_id=$1::uuid`,
		},
		{
			name: "audit action hash",
			query: `UPDATE guard_execution_audit SET action_hash=$2
				WHERE permit_id=$1::uuid`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, resolved, permitID := seededWorkspacePermit(t)
			if _, err := store.ClaimAuthorizedIntent(context.Background(), permitID, resolved); err != nil {
				t.Fatal(err)
			}
			_, err := store.db.Exec(tc.query, permitID, strings.Repeat("e", 64))
			if err == nil {
				t.Fatal("post-claim binding or hash tampering was accepted by DB")
			}
		})
	}
}
