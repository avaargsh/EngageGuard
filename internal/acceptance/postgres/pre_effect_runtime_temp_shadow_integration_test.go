package postgres

import (
	"context"
	"errors"
	"testing"
)

// An issuer/PEP must never treat a session-local Permit, Intent and Audit
// copy as authoritative just because all three contain mutually consistent
// rows. The real, permanently stored Permit is revoked before this test
// creates the misleading pg_temp copies on the pooled physical session.
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
		t.Fatalf("revoke real Permit before attack fixture: revoked=%t err=%v", revoked, err)
	}
	if err := store.InspectPreEffectLedger(ctx, permitID, intent.AttemptID, resolved); !errors.Is(err, ErrPreEffectBlocked) {
		t.Fatalf("permanently revoked Permit was accepted before shadow: %v", err)
	}

	store.db.SetMaxOpenConns(1)
	store.db.SetMaxIdleConns(1)
	for _, relation := range []string{
		"guard_permits", "guard_operation_intents", "guard_execution_audit",
	} {
		createTempGuardTableLikePermanent(t, store, relation)
		copyPermanentGuardRowsToTemp(t, store, relation)
	}
	// Temporary rows intentionally have no Guard immutable-row triggers:
	// only the copied temp Permit is unrevoked. The permanent revocation
	// remains unchanged and is the sole source of authority.
	if _, err := store.db.ExecContext(ctx, `
		UPDATE pg_temp.guard_permits SET revoked_at=NULL WHERE permit_id=$1::uuid
	`, permitID); err != nil {
		t.Fatal(err)
	}
	err = store.InspectPreEffectLedger(ctx, permitID, intent.AttemptID, resolved)
	if !errors.Is(err, ErrPreEffectUnavailable) || !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("executor pre-effect read trusted pg_temp Permit/Intent/Audit over revoked permanent Permit: %v; want ErrPreEffectUnavailable and ErrSchemaDrift", err)
	}

	var qualifiedSQL string
	if err := store.db.QueryRowContext(ctx, `
		SELECT pg_catalog.format(
			'SELECT revoked_at IS NOT NULL FROM %I.guard_permits WHERE permit_id=$1::uuid',
			pg_catalog.current_schema())
	`).Scan(&qualifiedSQL); err != nil {
		t.Fatal(err)
	}
	var permanentRevoked bool
	if err := store.db.QueryRowContext(ctx, qualifiedSQL, permitID).Scan(&permanentRevoked); err != nil || !permanentRevoked {
		t.Fatalf("permanent Permit revocation lost during shadow fixture: revoked=%t err=%v", permanentRevoked, err)
	}
}
