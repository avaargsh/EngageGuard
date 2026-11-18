package postgres

import (
	"context"
	"errors"
	"testing"
)

// A matching v9 migration checksum alone must not approve a database whose
// write-once trigger was disabled after installation.
func TestPermitV9CatalogRejectsDisabledRevocationTrigger(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx,
		"ALTER TABLE guard_permits DISABLE TRIGGER guard_permit_immutable_row_v9"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, store.db); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("disabled revocation trigger passed catalog validation: %v", err)
	}
}

// Existing issued and claimed Permits must retain valid state transitions
// when the v9 SQL guards are enabled.
func TestPermitV9StillAllowsLegitimateClaimAndRevoke(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	ctx := context.Background()
	intent, err := store.ClaimAuthorizedIntent(ctx, permitID, resolved)
	if err != nil || intent.AttemptID == "" {
		t.Fatalf("v9 blocked a valid one-time claim: %+v %v", intent, err)
	}
	ok, err := store.RevokeScopedPermit(ctx, resolved.TenantID, permitID,
		"policy-live-001", "POLICY_REVOKED")
	if err != nil || !ok {
		t.Fatalf("v9 blocked post-claim revocation: %t %v", ok, err)
	}
	if _, err := store.ClaimAuthorizedIntent(ctx, permitID, resolved); !errors.Is(err, ErrPermitAlreadyClaimed) {
		t.Fatalf("v9 allowed a second dispatch claim: %v", err)
	}
}
