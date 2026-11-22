package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// A role with INSERT-only access to guard_permits must never be able to mint a
// Permit that appears already CLAIMED or revoked without causal evidence.
// Existing v10/v11 deferred fences cover UPDATE, not INSERT, transitions.
func TestPermitIssuerCannotInsertPreclaimedOrPreRevokedPermit(t *testing.T) {
	for _, tc := range []struct {
		name       string
		state      string
		claimedAt  bool
		revokedAt  bool
		wantReject bool
	}{
		{"legitimate initial ISSUED", "ISSUED", false, false, false},
		{"forged initial CLAIMED without Intent and Audit", "CLAIMED", true, false, true},
		{"forged initial revoked Permit without revocation journal", "ISSUED", false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, db := integrationStore(t)
			ctx := context.Background()
			op, created, err := store.Accept(ctx, "tenant-a", "initial-state-case", sampleSubmission())
			if err != nil || !created {
				t.Fatalf("accept authentic operation: created=%v err=%v", created, err)
			}
			role := fmt.Sprintf("guard_insert_only_%d", time.Now().UnixNano())
			if _, err := db.ExecContext(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_, _ = db.ExecContext(context.Background(), "DROP OWNED BY "+role)
				_, _ = db.ExecContext(context.Background(), "DROP ROLE "+role)
			})
			var schema string
			if err := db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
				t.Fatal(err)
			}
			for _, grant := range []string{
				"GRANT USAGE ON SCHEMA " + schema + " TO " + role,
				"GRANT SELECT, INSERT ON guard_permits TO " + role,
			} {
				if _, err := db.ExecContext(ctx, grant); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err := tx.ExecContext(ctx, "SET LOCAL ROLE "+role); err != nil {
				t.Fatal(err)
			}
			var claimedAt, revokedAt any
			if tc.claimedAt {
				claimedAt = time.Now().UTC()
			}
			if tc.revokedAt {
				revokedAt = time.Now().UTC()
			}
			_, err = tx.ExecContext(ctx, `
				INSERT INTO guard_permits (
					tenant_id, operation_id, action_hash, binding_digest,
					audience, policy_version, issued_by, issued_at, expires_at,
					state, claimed_at, revoked_at
				) VALUES (
					$1, $2::uuid, $3, $4, $5, $6, $7,
					clock_timestamp()-interval '1 minute',
					clock_timestamp()+interval '1 hour',
					$8, $9, $10
				)
			`, "tenant-a", op.OperationID, strings.Repeat("a", 64),
				strings.Repeat("b", 64), "trusted-workspace-executor",
				"policy-test", "test-only-issuer", tc.state, claimedAt, revokedAt)
			if tc.wantReject {
				var pgErr *pgconn.PgError
				if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
					t.Fatalf("invalid initial Permit bypassed database fence: err=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("legitimate ISSUED insert rejected: %v", err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatalf("legitimate ISSUED commit rejected: %v", err)
			}
			var state string
			if err := db.QueryRowContext(ctx,
				"SELECT state FROM guard_permits WHERE tenant_id=$1 AND operation_id=$2::uuid",
				"tenant-a", op.OperationID).Scan(&state); err != nil || state != "ISSUED" {
				t.Fatalf("legitimate permit missing or wrong state: state=%q err=%v", state, err)
			}
		})
	}
}

func TestPermitV12MigrationRejectsDisabledOrDowngradedInsertFence(t *testing.T) {
	for _, command := range []string{"DISABLE TRIGGER", "ENABLE TRIGGER"} {
		t.Run(command, func(t *testing.T) {
			_, db := integrationStore(t)
			_, err := db.ExecContext(context.Background(),
				"ALTER TABLE guard_permits "+command+" guard_permit_initial_state_v12")
			if err != nil {
				t.Fatal(err)
			}
			if err := Migrate(context.Background(), db); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("weakened initial Permit INSERT fence accepted: %v", err)
			}
		})
	}
}

func TestPermitV12UpgradeRefusesPreexistingForgedClaimOrRevocation(t *testing.T) {
	for _, tc := range []struct {
		name, state string
		claimed    bool
		revoked    bool
	}{
		{"orphan historical CLAIMED", "CLAIMED", true, false},
		{"historical revoked without immutable journal", "ISSUED", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, db := integrationStore(t)
			ctx := context.Background()
			// Simulate an exact v11 installation with v12 unapplied.
			// This mutates only the disposable schema, never a live database.
			for _, sql := range []string{
				"DROP TRIGGER guard_permit_initial_state_v12 ON guard_permits",
				"DROP FUNCTION guard_permit_initial_state_v12()",
				"DELETE FROM guard_schema_migrations WHERE version=12",
			} {
				if _, err := db.ExecContext(ctx, sql); err != nil {
					t.Fatal(err)
				}
			}
			op, created, err := store.Accept(ctx, "tenant-a", "historical-forgery", sampleSubmission())
			if err != nil || !created {
				t.Fatalf("accept prior operation: created=%v err=%v", created, err)
			}
			var claimedAt, revokedAt any
			if tc.claimed {
				claimedAt = time.Now().UTC()
			}
			if tc.revoked {
				revokedAt = time.Now().UTC()
			}
			_, err = db.ExecContext(ctx, `
				INSERT INTO guard_permits (
					tenant_id, operation_id, action_hash, binding_digest,
					audience, policy_version, issued_by, issued_at, expires_at,
					state, claimed_at, revoked_at
				) VALUES (
					$1, $2::uuid, $3, $4, $5, $6, $7,
					clock_timestamp()-interval '1 minute',
					clock_timestamp()+interval '1 hour',
					$8, $9, $10
				)
			`, "tenant-a", op.OperationID, strings.Repeat("a", 64),
				strings.Repeat("b", 64), "trusted-workspace-executor",
				"policy-test", "test-only-issuer", tc.state, claimedAt, revokedAt)
			if err != nil {
				t.Fatalf("fixture v11 forged row must be accepted: %v", err)
			}
			err = Migrate(ctx, db)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
				t.Fatalf("v12 upgrade silently stamped historical invalid Permit: %v", err)
			}
			var count int
			if err := db.QueryRowContext(ctx,
				"SELECT count(*) FROM guard_schema_migrations").Scan(&count); err != nil || count != 11 {
				t.Fatalf("failed v12 historical scan stamped schema: rows=%d err=%v", count, err)
			}
		})
	}
}
