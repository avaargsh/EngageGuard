package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// A current_schema()/search_path.reset_val-only audit can be redirected to a
// complete, safe-looking decoy schema. The actual operator-pinned schema has
// an unsafe issuer UPDATE grant; only an explicit schema pin distinguishes it.
func TestPermitRoleSeparationRejectsOperatorSchemaMismatch(t *testing.T) {
	store, db := integrationStore(t)
	restrictPublicDatabaseTempForPermitTest(t, db)
	ctx := context.Background()
	trusted := store.trustedSchema
	suffix := time.Now().UnixNano()
	decoy := fmt.Sprintf("guard_role_decoy_startup_%d", suffix)
	issuer := fmt.Sprintf("guard_decoy_issuer_%d", suffix)
	claimer := fmt.Sprintf("guard_decoy_claimer_%d", suffix)

	if _, err := db.ExecContext(ctx, "CREATE SCHEMA "+decoy); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP SCHEMA "+decoy+" CASCADE")
	})
	for _, role := range []string{issuer, claimer} {
		if _, err := db.ExecContext(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), "DROP OWNED BY "+role)
			_, _ = db.ExecContext(context.Background(), "DROP ROLE "+role)
		})
	}

	// Build all relations the legacy schema-relative audit expects. The decoy
	// carries the exact least-privilege grants, while the trusted schema does not.
	for _, relation := range []string{
		"guard_action_operations", "guard_accepted_submission_snapshots",
		"guard_outbox_events", "guard_schema_migrations", "guard_permits",
		"guard_operation_intents", "guard_execution_audit",
		"guard_operation_unknown_events", "guard_permit_revocations",
		"guard_permit_authority_evidence", "guard_provider_observations",
	} {
		var statement string
		if err := db.QueryRowContext(ctx,
			"SELECT pg_catalog.format('CREATE TABLE %I.%I (LIKE %I.%I INCLUDING ALL)', $1::text, $2::text, $3::text, $2::text)",
			decoy, relation, trusted).Scan(&statement); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("create decoy relation %s: %v", relation, err)
		}
	}
	for _, grant := range []string{
		"GRANT USAGE ON SCHEMA " + decoy + " TO " + issuer + ", " + claimer,
		"GRANT SELECT, INSERT ON " + decoy + ".guard_permits TO " + issuer,
		"GRANT SELECT, INSERT ON " + decoy + ".guard_permit_authority_evidence TO " + issuer,
		"GRANT SELECT ON " + decoy + ".guard_action_operations TO " + issuer,
		"GRANT SELECT ON " + decoy + ".guard_accepted_submission_snapshots TO " + issuer,
		"GRANT SELECT ON " + decoy + ".guard_permits TO " + claimer,
		"GRANT SELECT ON " + decoy + ".guard_permit_authority_evidence TO " + claimer,
		"GRANT UPDATE (state, claimed_at) ON " + decoy + ".guard_permits TO " + claimer,
		"GRANT SELECT, INSERT ON " + decoy + ".guard_operation_intents TO " + claimer,
		"GRANT SELECT, INSERT ON " + decoy + ".guard_execution_audit TO " + claimer,
		"GRANT UPDATE (state) ON " + trusted + ".guard_permits TO " + issuer,
	} {
		if _, err := db.ExecContext(ctx, grant); err != nil {
			t.Fatalf("fixture grant %q: %v", grant, err)
		}
	}

	config, err := pgx.ParseConfig(os.Getenv("GUARD_PG_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = decoy
	decoyDB := stdlib.OpenDB(*config)
	t.Cleanup(func() { _ = decoyDB.Close() })
	var active string
	var baseline bool
	if err := decoyDB.QueryRowContext(ctx, `
		SELECT pg_catalog.current_schema(),
		       EXISTS (
		           SELECT 1 FROM pg_catalog.pg_settings
		           WHERE name='search_path' AND setting=reset_val
		       )
	`).Scan(&active, &baseline); err != nil {
		t.Fatal(err)
	}
	if active != decoy || !baseline {
		t.Fatalf("decoy startup baseline not established: schema=%q baseline=%t", active, baseline)
	}
	// Prove the decoy itself carries a complete, safe-looking role boundary.
	// A current_schema-only audit would certify this namespace even though the
	// actual operator-pinned Guard schema has a dangerous issuer UPDATE grant.
	if err := VerifyPermitRoleSeparation(ctx, decoyDB, decoy, issuer, claimer); err != nil {
		t.Fatalf("decoy fixture should pass when incorrectly selected as trusted: %v", err)
	}

	err = VerifyPermitRoleSeparation(ctx, decoyDB, trusted, issuer, claimer)
	if !errors.Is(err, ErrPermitRoleUnsafe) || err == nil {
		t.Fatalf("role audit accepted safe-looking startup decoy %q instead of operator-pinned %q: %v",
			decoy, trusted, err)
	}
	if !containsPermitRoleReason(err, "trusted schema") {
		t.Fatalf("role audit rejected for unrelated reason; want trusted-schema mismatch: %v", err)
	}
}

func containsPermitRoleReason(err error, reason string) bool {
	return err != nil && strings.Contains(err.Error(), reason)
}
