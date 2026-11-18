package postgres

import (
    "context"
    "errors"
    "testing"
)

// A matching v8 migration checksum alone must not approve a database whose
// write-once trigger was disabled after installation.
func TestPermitV8CatalogRejectsDisabledRevocationTrigger(t *testing.T) {
    store, _ := integrationStore(t)
    ctx := context.Background()
    if _, err := store.db.ExecContext(ctx,
        "ALTER TABLE guard_permit_revocations DISABLE TRIGGER guard_revocation_immutable_row_v8"); err != nil {
        t.Fatal(err)
    }
    if err := Migrate(ctx, store.db); !errors.Is(err, ErrSchemaDrift) {
        t.Fatalf("disabled revocation trigger passed catalog validation: %v", err)
    }
}

// Existing issued and claimed Permits must retain valid state transitions
// when the v8 SQL guards are enabled.
func TestPermitV8StillAllowsLegitimateClaimAndRevoke(t *testing.T) {
    store, resolved, permitID := seededWorkspacePermit(t)
    ctx := context.Background()
    intent, err := store.ClaimAuthorizedIntent(ctx, permitID, resolved)
    if err != nil || intent.AttemptID == "" {
        t.Fatalf("v8 blocked a valid one-time claim: %+v %v", intent, err)
    }
    ok, err := store.RevokeScopedPermit(ctx, resolved.TenantID, permitID,
        "policy-live-001", "POLICY_REVOKED")
    if err != nil || !ok {
        t.Fatalf("v8 blocked post-claim revocation: %t %v", ok, err)
    }
    if _, err := store.ClaimAuthorizedIntent(ctx, permitID, resolved); !errors.Is(err, ErrPermitAlreadyClaimed) {
        t.Fatalf("v8 allowed a second dispatch claim: %v", err)
    }
}
