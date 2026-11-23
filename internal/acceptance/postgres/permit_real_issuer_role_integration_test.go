package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

// The actual private pending-issue transaction must work under a separate,
// least-privileged PostgreSQL session identity, not just a schema-owner fixture.
// CI provisions a random SCRAM password for this disposable LOGIN role.
// This does NOT provision or authenticate production service credentials.
func TestPendingPermitInsertAsDistinctLeastPrivilegeDatabaseIssuer(t *testing.T) {
	owner, req := pendingPermitFixture(t)
	restrictPublicDatabaseTempForPermitTest(t, owner.db)
	ctx := context.Background()
	var schema string
	if err := owner.db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	suffix := time.Now().UnixNano()
	issuer := fmt.Sprintf("guard_pending_issuer_%d", suffix)
	claimer := fmt.Sprintf("guard_pending_claimer_%d", suffix)
	var passwordBytes [32]byte
	if _, err := rand.Read(passwordBytes[:]); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(passwordBytes[:])
	for _, role := range []string{issuer, claimer} {
		attr := "NOLOGIN"
		if role == issuer {
			// CI uses SCRAM TCP authentication, not local trust. This
			// cryptographically random password exists only for this test.
			attr = "LOGIN PASSWORD '" + password + "'"
		}
		if _, err := owner.db.ExecContext(ctx, "CREATE ROLE "+role+" "+attr+" NOINHERIT"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = owner.db.ExecContext(context.Background(), "DROP OWNED BY "+role)
			_, _ = owner.db.ExecContext(context.Background(), "DROP ROLE "+role)
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
		if _, err := owner.db.ExecContext(ctx, grant); err != nil {
			t.Fatalf("test-only role grant %q failed: %v", grant, err)
		}
	}
	if err := VerifyPermitRoleSeparation(ctx, owner.db, issuer, claimer); err != nil {
		t.Fatalf("disposable issuer/claimer permissions unsafe: %v", err)
	}
	config, err := pgx.ParseConfig(os.Getenv("GUARD_PG_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	config.User = issuer
	config.Password = password
	config.RuntimeParams["search_path"] = schema
	issuerDB := stdlib.OpenDB(*config)
	issuerDB.SetMaxOpenConns(2)
	t.Cleanup(func() { issuerDB.Close() })
	if err := issuerDB.PingContext(ctx); err != nil {
		t.Fatalf("separate password-authenticated test-only LOGIN role cannot connect: %v", err)
	}
	var loggedIn string
	if err := issuerDB.QueryRowContext(ctx, "SELECT current_user").Scan(&loggedIn); err != nil || loggedIn != issuer {
		t.Fatalf("issuer connection did not assume least-privilege identity: role=%s err=%v", loggedIn, err)
	}
	// No owner privileges are available through this Store.
	permitID, err := New(issuerDB).insertPendingPermit(ctx, req)
	if err != nil || !validDispatchUUID(permitID) {
		t.Fatalf("least-privilege issuance transaction did not commit: id=%q err=%v", permitID, err)
	}
	// The audit identity must be the effective PostgreSQL principal
	// that actually wrote the Permit, not caller-provided Issuer text.
	var recordedIssuer string
	if err := owner.db.QueryRowContext(ctx,
		"SELECT issued_by FROM guard_permits WHERE permit_id=$1::uuid", permitID).
		Scan(&recordedIssuer); err != nil || recordedIssuer != issuer {
		t.Fatalf("Permit audit identity can be impersonated by caller: recorded=%q dbActor=%q err=%v",
			recordedIssuer, issuer, err)
	}
	if _, err := New(issuerDB).insertPendingPermit(ctx, req); !errors.Is(err, ErrPermitAlreadyIssued) {
		t.Fatalf("least-privilege replay did not reject duplicate: %v", err)
	}
	// The issuer may not alter the immutable accepted bytes even if an
	// application bug attempts it; this must fail by SQL privilege, not just
	// by a trigger owned by the test database administrator.
	_, err = issuerDB.ExecContext(ctx,
		"UPDATE guard_accepted_submission_snapshots SET submission_bytes=$1 WHERE tenant_id=$2 AND operation_id=$3::uuid",
		[]byte("{}"), req.Resolved.TenantID, req.Resolved.OperationID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("least-privilege issuer could UPDATE accepted bytes: %v", err)
	}
	if _, err := New(issuerDB).ClaimAuthorizedIntent(ctx, permitID, req.Resolved); err == nil {
		t.Fatal("least-privilege issuer claimed its own Permit or wrote dispatch evidence")
	}
	var state string
	if err := owner.db.QueryRowContext(ctx,
		"SELECT state FROM guard_permits WHERE permit_id=$1::uuid", permitID).Scan(&state); err != nil || state != "ISSUED" {
		t.Fatalf("issuer-side claim attempt modified state: state=%s err=%v", state, err)
	}
	for _, table := range []string{"guard_operation_intents", "guard_execution_audit"} {
		var count int
		if err := owner.db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("issuer left dispatch evidence in %s: count=%d err=%v", table, count, err)
		}
	}
}
