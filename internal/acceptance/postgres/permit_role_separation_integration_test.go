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
		"GRANT SELECT ON guard_action_operations TO " + issuer,
		"GRANT SELECT ON guard_accepted_submission_snapshots TO " + issuer,
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

	// The issuer's accepted-source access is read-only, not FOR SHARE /
	// UPDATE. A valid separate admission record remains observable.
	store := New(db)
	op, created, err := store.Accept(ctx, "tenant-a", "role-audit-source", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("source acceptance fixture: created=%t err=%v", created, err)
	}
	readTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readTx.ExecContext(ctx, "SET LOCAL ROLE "+issuer); err != nil {
		t.Fatal(err)
	}
	var status string
	err = readTx.QueryRowContext(ctx, `
		SELECT o.status
		FROM guard_action_operations o
		JOIN guard_accepted_submission_snapshots s
		  ON s.tenant_id=o.tenant_id AND s.operation_id=o.operation_id
		WHERE o.tenant_id=$1 AND o.operation_id=$2::uuid
	`, "tenant-a", op.OperationID).Scan(&status)
	if err != nil || status != "ACCEPTED" {
		t.Fatalf("least-privilege issuer cannot read accepted source: status=%q err=%v", status, err)
	}
	if err := readTx.Rollback(); err != nil {
		t.Fatal(err)
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
		{"issuer gained original operation INSERT",
			"GRANT INSERT ON guard_action_operations TO " + issuer,
			"REVOKE INSERT ON guard_action_operations FROM " + issuer},
		{"issuer gained accepted source bytes UPDATE",
			"GRANT UPDATE (submission_bytes) ON guard_accepted_submission_snapshots TO " + issuer,
			"REVOKE UPDATE (submission_bytes) ON guard_accepted_submission_snapshots FROM " + issuer},
		{"issuer gained accepted source INSERT",
			"GRANT INSERT ON guard_accepted_submission_snapshots TO " + issuer,
			"REVOKE INSERT ON guard_accepted_submission_snapshots FROM " + issuer},
		{"claimer gained original operation INSERT",
			"GRANT INSERT ON guard_action_operations TO " + claimer,
			"REVOKE INSERT ON guard_action_operations FROM " + claimer},
		{"claimer gained accepted source UPDATE",
			"GRANT UPDATE (submission_bytes) ON guard_accepted_submission_snapshots TO " + claimer,
			"REVOKE UPDATE (submission_bytes) ON guard_accepted_submission_snapshots FROM " + claimer},
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
