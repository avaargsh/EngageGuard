package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// Disposable PostgreSQL roles demonstrate the actual database permission
// boundary. The role grants in this fixture are NOT a production rollout or
// a substitute for an independently authenticated Permit issuer.
func TestPermitIssuerAndClaimerRoleSeparation(t *testing.T) {
	_, db := integrationStore(t)
	ctx := context.Background()
	var schema string
	if err := db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	serial := time.Now().UnixNano()
	issuer := fmt.Sprintf("guard_issuer_%d", serial)
	claimer := fmt.Sprintf("guard_claimer_%d", serial)
	for _, role := range []string{issuer, claimer} {
		if _, err := db.ExecContext(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), "DROP OWNED BY "+role)
			_, _ = db.ExecContext(context.Background(), "DROP ROLE "+role)
		})
	}
	for _, grant := range []string{
		"GRANT USAGE ON SCHEMA " + schema + " TO " + issuer + ", " + claimer,
		"GRANT SELECT, INSERT ON guard_permits TO " + issuer,
		"GRANT SELECT ON guard_permits TO " + claimer,
		"GRANT UPDATE (state, claimed_at) ON guard_permits TO " + claimer,
		"GRANT SELECT, INSERT ON guard_operation_intents TO " + claimer,
		"GRANT SELECT, INSERT ON guard_execution_audit TO " + claimer,
	} {
		if _, err := db.ExecContext(ctx, grant); err != nil {
			t.Fatalf("fixture grant %q: %v", grant, err)
		}
	}
	if err := VerifyPermitRoleSeparation(ctx, db, issuer, claimer); err != nil {
		t.Fatalf("correctly segregated roles failed admission: %v", err)
	}

	// Attempt an actual SQL Permit INSERT as the claimer, rather than
	// relying only on introspection of pg_catalog grants.
	tx, err := db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "SET LOCAL ROLE "+claimer); err != nil {
		t.Fatalf("cannot assume disposable claim role: %v", err)
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO guard_permits DEFAULT VALUES")
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("claimer direct Permit issue must fail with SQLSTATE 42501: %v", err)
	}
	_ = tx.Rollback()

	// Privilege drift must be detected before a real issuer/claimer starts.
	for _, tc := range []struct {
		name, grant, revoke string
	}{
		{"claimer gained Permit INSERT",
			"GRANT INSERT ON guard_permits TO " + claimer,
			"REVOKE INSERT ON guard_permits FROM " + claimer},
		{"claimer gained Permit identity UPDATE",
			"GRANT UPDATE (action_hash) ON guard_permits TO " + claimer,
			"REVOKE UPDATE (action_hash) ON guard_permits FROM " + claimer},
		{"issuer gained CLAIMED-state UPDATE",
			"GRANT UPDATE (state) ON guard_permits TO " + issuer,
			"REVOKE UPDATE (state) ON guard_permits FROM " + issuer},
		{"issuer gained audit INSERT",
			"GRANT INSERT ON guard_execution_audit TO " + issuer,
			"REVOKE INSERT ON guard_execution_audit FROM " + issuer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := db.ExecContext(ctx, tc.grant); err != nil {
				t.Fatal(err)
			}
			if err := VerifyPermitRoleSeparation(ctx, db, issuer, claimer); !errors.Is(err, ErrPermitRoleUnsafe) {
				t.Fatalf("dangerous Permit role grant accepted: %v", err)
			}
			if _, err := db.ExecContext(ctx, tc.revoke); err != nil {
				t.Fatal(err)
			}
			if err := VerifyPermitRoleSeparation(ctx, db, issuer, claimer); err != nil {
				t.Fatalf("restored least privilege still rejected: %v", err)
			}
		})
	}
}
