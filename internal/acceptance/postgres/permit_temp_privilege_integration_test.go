package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// PostgreSQL generally grants TEMPORARY on new databases to PUBLIC. This
// makes a role able to create pg_temp relations even when it cannot CREATE
// in the Guard application schema. An issuer/claimer role preflight must
// reject this inherited privilege before certifying safe separation.
func TestPermitRoleSeparationRejectsInheritedDatabaseTemporaryPrivilege(t *testing.T) {
	_, db := integrationStore(t)
	ctx := context.Background()
	var schema string
	if err := db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	suffix := time.Now().UnixNano()
	issuer := fmt.Sprintf("guard_temp_issuer_%d", suffix)
	claimer := fmt.Sprintf("guard_temp_claimer_%d", suffix)
	for _, role := range []string{issuer, claimer} {
		if _, err := db.ExecContext(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), "DROP OWNED BY "+role)
			_, _ = db.ExecContext(context.Background(), "DROP ROLE "+role)
		})
	}
	for _, stmt := range []string{
		"GRANT USAGE ON SCHEMA " + schema + " TO " + issuer + "," + claimer,
		"GRANT SELECT, INSERT ON guard_permits TO " + issuer,
		"GRANT SELECT ON guard_action_operations TO " + issuer,
		"GRANT SELECT ON guard_accepted_submission_snapshots TO " + issuer,
		"GRANT SELECT ON guard_permits TO " + claimer,
		"GRANT UPDATE (state, claimed_at) ON guard_permits TO " + claimer,
		"GRANT SELECT, INSERT ON guard_operation_intents TO " + claimer,
		"GRANT SELECT, INSERT ON guard_execution_audit TO " + claimer,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	var issuerTemp, claimerTemp bool
	if err := db.QueryRowContext(ctx, `
		SELECT pg_catalog.has_database_privilege($1::name, pg_catalog.current_database(), 'TEMPORARY'),
		       pg_catalog.has_database_privilege($2::name, pg_catalog.current_database(), 'TEMPORARY')
	`, issuer, claimer).Scan(&issuerTemp, &claimerTemp); err != nil {
		t.Fatal(err)
	}
	if !issuerTemp || !claimerTemp {
		t.Skip("database already revokes inherited TEMPORARY; no unsafe default to reproduce")
	}
	if err := VerifyPermitRoleSeparation(ctx, db, schema, issuer, claimer); !errors.Is(err, ErrPermitRoleUnsafe) {
		t.Fatalf("inherited database TEMPORARY privileges accepted as safe issuer/claimer: %v", err)
	}
}
