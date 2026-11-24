package postgres

import (
	"context"
	"errors"
	"testing"

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
