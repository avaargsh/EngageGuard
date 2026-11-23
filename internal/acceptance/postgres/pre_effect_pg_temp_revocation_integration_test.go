package postgres

import (
	"context"
	"errors"
	"testing"
)

// A pooled PostgreSQL session may acquire pg_temp copies after Migrate.
// A revoked permanent Permit must never be considered safe for pre-effect
// inspection merely because a session-local copy still looks unrevoked.
func TestPreEffectLedgerRejectsTemporaryUnrevokedCopyOfRevokedPermit(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	ctx := context.Background()
	intent, err := store.ClaimAuthorizedIntent(ctx, permitID, resolved)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := store.RevokeScopedPermit(ctx, resolved.TenantID, permitID,
		"pg-temp-pre-effect-revocation", "SECURITY_RESPONSE")
	if err != nil || !revoked {
		t.Fatalf("permanent Permit revocation failed: revoked=%t err=%v", revoked, err)
	}
	store.db.SetMaxOpenConns(1)
	store.db.SetMaxIdleConns(1)
	var schema string
	if err := store.db.QueryRowContext(ctx, "SELECT pg_catalog.current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"guard_permits", "guard_operation_intents", "guard_execution_audit"} {
		var ddl, copyDML string
		if err := store.db.QueryRowContext(ctx, `
			SELECT pg_catalog.format(
				'CREATE TEMP TABLE %I (LIKE %I.%I INCLUDING ALL)',
				$1::text, $2::text, $1::text),
			       pg_catalog.format(
				'INSERT INTO pg_temp.%I SELECT * FROM %I.%I',
				$1::text, $2::text, $1::text)
		`, name, schema).Scan(&ddl, &copyDML); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, ddl); err != nil {
			t.Fatalf("clone %s: %v", name, err)
		}
		if _, err := store.db.ExecContext(ctx, copyDML); err != nil {
			t.Fatalf("copy %s: %v", name, err)
		}
	}
	if _, err := store.db.ExecContext(ctx, `
		UPDATE pg_temp.guard_permits SET revoked_at=NULL WHERE permit_id=$1::uuid
	`, permitID); err != nil {
		t.Fatal(err)
	}
	var permanentStillRevoked bool
	var query string
	if err := store.db.QueryRowContext(ctx, `
		SELECT pg_catalog.format(
			'SELECT revoked_at IS NOT NULL FROM %I.guard_permits WHERE permit_id=$1::uuid',
			$1::text)
	`, schema).Scan(&query); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, query, permitID).Scan(&permanentStillRevoked); err != nil || !permanentStillRevoked {
		t.Fatalf("permanent revocation not durable: revoked=%t err=%v", permanentStillRevoked, err)
	}
	err = store.InspectPreEffectLedger(ctx, permitID, intent.AttemptID, resolved)
	if !errors.Is(err, ErrPreEffectUnavailable) || !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("pre-effect check trusted temporary unrevoked Permit over permanently revoked Permit: %v; want unavailable schema drift", err)
	}
}
