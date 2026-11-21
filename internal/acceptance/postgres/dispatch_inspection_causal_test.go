package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// These are deliberately inconsistent, directly persisted fixture rows.
// Neither case has an actual claimed authorization. The read-only recovery
// inspection must not mistake an injected Intent for a trusted dispatch.
func TestDispatchInspectionRejectsIncompletePermitCausalChain(t *testing.T) {
	for _, tc := range []struct {
		name          string
		withFakeAudit bool
	}{
		{"intent without claim or audit", false},
		{"intent and audit without permit claim", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, resolved, permitID := seededWorkspacePermit(t)
			ctx := context.Background()
			hash, err := action.Hash(resolved)
			if err != nil {
				t.Fatal(err)
			}
			var attemptID string
			err = store.db.QueryRowContext(ctx, `
				INSERT INTO guard_operation_intents
				    (tenant_id, operation_id, permit_id, action_hash, binding_digest, state)
				VALUES ($1,$2::uuid,$3::uuid,$4,$5,'DISPATCHING')
				RETURNING attempt_id::text
			`, resolved.TenantID, resolved.OperationID, permitID,
				hash, resolved.ToolBindingDigest).Scan(&attemptID)
			if err != nil {
				t.Fatal("seed unclaimed intent:", err)
			}
			if tc.withFakeAudit {
				_, err = store.db.ExecContext(ctx, `
					INSERT INTO guard_execution_audit
						(tenant_id, operation_id, permit_id, attempt_id, event_type, action_hash)
					VALUES ($1,$2::uuid,$3::uuid,$4::uuid,'guard.operation.dispatching.v1',$5)
				`, resolved.TenantID, resolved.OperationID, permitID, attemptID, hash)
				if err != nil {
					t.Fatal("seed audit without claim:", err)
				}
			}
			var state string
			if err := store.db.QueryRowContext(ctx,
				"SELECT state FROM guard_permits WHERE permit_id=$1::uuid", permitID).
				Scan(&state); err != nil || state != "ISSUED" {
				t.Fatalf("test fixture unexpectedly claimed permit: state=%s err=%v", state, err)
			}
			got, err := store.GetDispatchState(ctx, resolved.TenantID, resolved.OperationID, attemptID)
			if !errors.Is(err, ErrUnknownConflict) {
				t.Fatalf("unclaimed or unaudited attempt accepted as real dispatch: %+v %v", got, err)
			}
		})
	}
}

func TestDispatchInspectionAcceptsCompleteClaimAuditIncludingAfterRevocation(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	ctx := context.Background()
	intent, err := store.ClaimAuthorizedIntent(ctx, permitID, resolved)
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.GetDispatchState(ctx, resolved.TenantID, resolved.OperationID, intent.AttemptID)
	if err != nil || state.State != "DISPATCHING" || state.Reason != "" || state.PermitID != permitID {
		t.Fatalf("legitimate committed claim/audit unreadable: %+v %v", state, err)
	}
	if revoked, err := store.RevokeScopedPermit(ctx, resolved.TenantID, permitID,
		"incident-claim-read-1", "SECURITY_RESPONSE"); err != nil || !revoked {
		t.Fatalf("revoke already claimed permit: %t %v", revoked, err)
	}
	// Revocation prevents *new* execution rights; it must not erase evidence
	// of an already claimed attempt or imply the external side effect failed.
	state, err = New(store.db).GetDispatchState(ctx, resolved.TenantID, resolved.OperationID, intent.AttemptID)
	if err != nil || state.State != "DISPATCHING" || state.AttemptID != intent.AttemptID {
		t.Fatalf("revocation erased uncertain attempt evidence: %+v %v", state, err)
	}
}
