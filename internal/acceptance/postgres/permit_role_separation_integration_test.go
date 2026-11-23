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


// TestPermitRoleSeparationDoesNotTrustTemporaryRelationShadow reproduces a
// PostgreSQL pg_temp name-resolution bypass. Unqualified to_regclass('guard_permits')
// resolves a same-named temporary relation before the authoritative table. The
// checker must inspect the relation in current_schema(), not the session shadow.
func TestPermitRoleSeparationDoesNotTrustTemporaryRelationShadow(t *testing.T) {
	_, db := integrationStore(t)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ctx := context.Background()
	var schema string
	if err := db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	serial := time.Now().UnixNano()
	issuer := fmt.Sprintf("guard_shadow_issuer_%d", serial)
	claimer := fmt.Sprintf("guard_shadow_claimer_%d", serial)
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
		"GRANT SELECT, INSERT ON " + schema + ".guard_permits TO " + issuer,
		"GRANT SELECT ON " + schema + ".guard_action_operations TO " + issuer,
		"GRANT SELECT ON " + schema + ".guard_accepted_submission_snapshots TO " + issuer,
		"GRANT SELECT ON " + schema + ".guard_permits TO " + claimer,
		"GRANT UPDATE (state, claimed_at) ON " + schema + ".guard_permits TO " + claimer,
		"GRANT SELECT, INSERT ON " + schema + ".guard_operation_intents TO " + claimer,
		"GRANT SELECT, INSERT ON " + schema + ".guard_execution_audit TO " + claimer,
		"GRANT UPDATE (state) ON " + schema + ".guard_permits TO " + issuer,
	} {
		if _, err := db.ExecContext(ctx, grant); err != nil {
			t.Fatalf("fixture grant %q: %v", grant, err)
		}
	}

	// Pin the pool to one physical session so VerifyPermitRoleSeparation
	// necessarily reuses the session that owns this temporary shadow table.
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.ExecContext(ctx, `
		CREATE TEMP TABLE guard_permits (
			permit_id uuid, tenant_id text, operation_id uuid, action_hash text,
			binding_digest text, audience text, policy_version text, issued_by text,
			issued_at timestamptz, expires_at timestamptz, revoked_at timestamptz,
			state text, claimed_at timestamptz
		)
	`)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	for _, grant := range []string{
		"GRANT SELECT, INSERT ON pg_temp.guard_permits TO " + issuer,
		"GRANT SELECT ON pg_temp.guard_permits TO " + claimer,
		"GRANT UPDATE (state, claimed_at) ON pg_temp.guard_permits TO " + claimer,
	} {
		if _, err := conn.ExecContext(ctx, grant); err != nil {
			conn.Close()
			t.Fatalf("temporary shadow grant %q: %v", grant, err)
		}
	}
	var shadowed bool
	if err := conn.QueryRowContext(ctx,
		"SELECT to_regclass('guard_permits') = to_regclass('pg_temp.guard_permits')",
	).Scan(&shadowed); err != nil || !shadowed {
		conn.Close()
		t.Fatalf("test did not establish pg_temp relation shadow: shadowed=%t err=%v", shadowed, err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	// The authoritative table has an unsafe issuer UPDATE grant, while the
	// temp shadow exposes only the expected safe grants. A checker that probes
	// the shadow instead of the authoritative relation will incorrectly pass.
	if err := VerifyPermitRoleSeparation(ctx, db, issuer, claimer); !errors.Is(err, ErrPermitRoleUnsafe) {
		t.Fatalf("unsafe UPDATE on authoritative guard_permits hidden by pg_temp shadow: got %v, want ErrPermitRoleUnsafe", err)
	}
}
