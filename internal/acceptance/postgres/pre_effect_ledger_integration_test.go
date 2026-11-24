package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// This method is a necessary local ledger check only. It is not an execution
// grant, Permit issuer, provider receipt, or independently deployed Executor PEP.
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
		name   string
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

// A session-local copy must not be allowed to hide a revoked permanent Permit.
// The three rows are copied after startup and altered only inside pg_temp.
func TestPreEffectInspectionRejectsPostMigrationTemporaryLedgerShadows(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	ctx := context.Background()
	intent, err := store.ClaimAuthorizedIntent(ctx, permitID, resolved)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := store.RevokeScopedPermit(ctx, resolved.TenantID, permitID,
		"pre-effect-shadow-test", "SECURITY_RESPONSE")
	if err != nil || !revoked {
		t.Fatalf("revoke permanent Permit before shadow fixture: revoked=%t err=%v", revoked, err)
	}
	if err := store.InspectPreEffectLedger(ctx, permitID, intent.AttemptID, resolved); !errors.Is(err, ErrPreEffectBlocked) {
		t.Fatalf("permanently revoked Permit accepted before shadow: %v", err)
	}

	store.db.SetMaxOpenConns(1)
	store.db.SetMaxIdleConns(1)
	for _, relation := range []string{
		"guard_permits", "guard_operation_intents", "guard_execution_audit",
	} {
		createTempGuardTableLikePermanent(t, store, relation)
		copyPermanentGuardRowsToTemp(t, store, relation)
	}
	if _, err := store.db.ExecContext(ctx, `
		UPDATE pg_temp.guard_permits SET revoked_at=NULL WHERE permit_id=$1::uuid
	`, permitID); err != nil {
		t.Fatal(err)
	}
	var permanentQuery string
	if err := store.db.QueryRowContext(ctx, `
		SELECT pg_catalog.format(
			'SELECT revoked_at IS NOT NULL FROM %I.guard_permits WHERE permit_id=$1::uuid',
			pg_catalog.current_schema())
	`).Scan(&permanentQuery); err != nil {
		t.Fatal(err)
	}
	var permanentRevoked bool
	if err := store.db.QueryRowContext(ctx, permanentQuery, permitID).Scan(&permanentRevoked); err != nil || !permanentRevoked {
		t.Fatalf("temporary fixture changed permanent revocation: revoked=%t err=%v", permanentRevoked, err)
	}
	err = store.InspectPreEffectLedger(ctx, permitID, intent.AttemptID, resolved)
	if !errors.Is(err, ErrPreEffectUnavailable) || !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("pre-effect inspection trusted pg_temp unrevoked Permit/Intent/Audit over permanent revocation: %v; want ErrPreEffectUnavailable and ErrSchemaDrift", err)
	}
}


// A deferred constraint can be deliberately evaluated early by a direct SQL
// writer. Even if that transaction commits an already-expired CLAIMED row
// with matching Intent/Audit, a later pre-effect read must sample DB time and
// reject it. No provider or external effect is involved.
func TestPreEffectLedgerRejectsExpiredClaimAfterEarlyV12ConstraintEvaluation(t *testing.T) {
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
	if _, err := tx.ExecContext(ctx, "SET CONSTRAINTS guard_permit_claim_expiry_v12 IMMEDIATE"); err != nil {
		t.Fatal("v12 expiry constraint cannot be forced immediate:", err)
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
		RETURNING attempt_id::text`,
		resolved.TenantID, resolved.OperationID, permitID, hash, resolved.ToolBindingDigest).Scan(&attemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO guard_execution_audit
		(tenant_id,operation_id,permit_id,attempt_id,event_type,action_hash)
		VALUES ($1,$2::uuid,$3::uuid,$4::uuid,'guard.operation.dispatching.v1',$5)`,
		resolved.TenantID, resolved.OperationID, permitID, attemptID, hash); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, "SELECT pg_sleep(3.6)"); err != nil {
		t.Fatal(err)
	}
	var expired bool
	if err := tx.QueryRowContext(ctx,
		"SELECT expires_at <= clock_timestamp() FROM guard_permits WHERE permit_id=$1::uuid",
		permitID).Scan(&expired); err != nil || !expired {
		t.Fatalf("fixture did not cross DB-clock expiry: expired=%t err=%v", expired, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("expected the deliberately early-evaluated v12 constraint to leave a late-commit window: %v", err)
	}
	if err := store.InspectPreEffectLedger(ctx, permitID, attemptID, resolved); !errors.Is(err, ErrPreEffectBlocked) {
		t.Fatalf("expired CLAIMED Permit with committed Intent/Audit accepted as pre-effect-valid: %v", err)
	}
}
