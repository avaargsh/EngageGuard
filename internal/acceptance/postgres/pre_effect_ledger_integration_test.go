package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// This method returns no executable capability; only a necessary local
// ledger check. An independent PEP must still authenticate the executor and
// recheck live sources immediately at the actual side-effect boundary.
func TestPreEffectLedgerValidClaimAndAuditOnly(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	intent, err := store.ClaimAuthorizedIntent(context.Background(), permitID, resolved)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.InspectPreEffectLedger(context.Background(), permitID, intent.AttemptID, resolved); err != nil {
		t.Fatalf("intact unexpired claimed Permit, Intent and Audit rejected: %v", err)
	}
}

func TestPreEffectLedgerDeniesModifiedActionTenantRevokedAndUnknown(t *testing.T) {
	for _, tc := range []struct {
		name string
		change func(context.Context, *Store, string, string, *action.WorkspaceWrite) error
	}{
		{"changed content", func(_ context.Context, _ *Store, _, _ string, a *action.WorkspaceWrite) error {
			a.ContentDigest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
			return nil
		}},
		{"wrong tenant", func(_ context.Context, _ *Store, _, _ string, a *action.WorkspaceWrite) error {
			a.TenantID = "tenant-b"
			return nil
		}},
		{"different audience", func(_ context.Context, _ *Store, _, _ string, a *action.WorkspaceWrite) error {
			a.Audience = "another-executor"
			return nil
		}},
		{"revoked after claim", func(ctx context.Context, store *Store, permitID, _ string, a *action.WorkspaceWrite) error {
			_, err := store.RevokeScopedPermit(ctx, a.TenantID, permitID, "pre-effect-revocation", "SECURITY_RESPONSE")
			return err
		}},
		{"UNKNOWN attempt", func(ctx context.Context, store *Store, _, attemptID string, a *action.WorkspaceWrite) error {
			_, err := store.MarkDispatchUnknown(ctx, a.TenantID, a.OperationID, attemptID, "ACK_LOST")
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, resolved, permitID := seededWorkspacePermit(t)
			intent, err := store.ClaimAuthorizedIntent(context.Background(), permitID, resolved)
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.change(context.Background(), store, permitID, intent.AttemptID, &resolved); err != nil {
				t.Fatal(err)
			}
			if err := store.InspectPreEffectLedger(context.Background(), permitID, intent.AttemptID, resolved); !errors.Is(err, ErrPreEffectBlocked) {
				t.Fatalf("unsafe pre-effect ledger accepted: case=%s err=%v", tc.name, err)
			}
		})
	}
}

// PostgreSQL permits SET CONSTRAINTS IMMEDIATE. This is a deliberate local
// raw-SQL bypass of the v11 deferred expiry check; it MUST NOT result in a
// trusted, valid pre-effect observation once the Permit has expired.
// No real external protected effect or provider is invoked.
func TestPreEffectLedgerRejectsExpiredClaimWithEarlyEvaluatedV11Constraint(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermitWithExpiry(t, time.Now().Add(3*time.Second))
	ctx := context.Background()
	hash, err := action.Hash(resolved)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "SET CONSTRAINTS guard_permit_claim_expiry_v11 IMMEDIATE"); err != nil {
		t.Fatal("v11 constraint cannot be forced immediate:", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE guard_permits
		SET state='CLAIMED', claimed_at=clock_timestamp()
		WHERE tenant_id=$1 AND permit_id=$2::uuid AND state='ISSUED'
			AND expires_at>clock_timestamp()`, resolved.TenantID, permitID); err != nil {
		t.Fatal("pre-expiry claim update:", err)
	}
	var attemptID string
	if err := tx.QueryRowContext(ctx, `INSERT INTO guard_operation_intents
		(tenant_id,operation_id,permit_id,action_hash,binding_digest,state)
		VALUES ($1,$2::uuid,$3::uuid,$4,$5,'DISPATCHING')
		RETURNING attempt_id::text`, resolved.TenantID, resolved.OperationID, permitID, hash, resolved.ToolBindingDigest).Scan(&attemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO guard_execution_audit
		(tenant_id,operation_id,permit_id,attempt_id,event_type,action_hash)
		VALUES ($1,$2::uuid,$3::uuid,$4::uuid,'guard.operation.dispatching.v1',$5)`,
		resolved.TenantID, resolved.OperationID, permitID, attemptID, hash); err != nil {
		t.Fatal(err)
	}
	// The v11 check already ran at UPDATE; at COMMIT the v10 causal
	// constraint can still succeed because the exact Audit now exists.
	if _, err := tx.ExecContext(ctx, "SELECT pg_sleep(3.6)"); err != nil {
		t.Fatal(err)
	}
	var expired bool
	if err := tx.QueryRowContext(ctx, "SELECT expires_at <= clock_timestamp() FROM guard_permits WHERE permit_id=$1::uuid", permitID).Scan(&expired); err != nil || !expired {
		t.Fatalf("did not cross actual DB-clock expiry: expired=%t err=%v", expired, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("expected known SET CONSTRAINTS early-evaluation bypass; update threat model if PostgreSQL now rejects it: %v", err)
	}
	if err := store.InspectPreEffectLedger(ctx, permitID, attemptID, resolved); !errors.Is(err, ErrPreEffectBlocked) {
		t.Fatalf("expired permit with committed causal records accepted as pre-effect-valid: %v", err)
	}
}
