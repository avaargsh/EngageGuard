package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// A newly inserted Permit must begin ISSUED and not revoked. The canonical
// v10/v11 causal triggers already check CLAIMED journal evidence, but an
// initially revoked ISSUED row also needs an explicit issuance-state fence.
func TestCanonicalPermitInitialRevocationRequiresRejection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		revoked bool
	}{
		{name: "normal-initial-issued"},
		{name: "initially-revoked-without-journal", revoked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, db := integrationStore(t)
			ctx := context.Background()
			op, created, err := store.Accept(ctx, "tenant-a", "canonical-initial-state", sampleSubmission())
			if err != nil || !created {
				t.Fatalf("accept: created=%t err=%v", created, err)
			}
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			_, err = tx.ExecContext(ctx, `
				INSERT INTO guard_permits
					(tenant_id, operation_id, action_hash, binding_digest, audience,
					 policy_version, issued_by, expires_at, state, revoked_at)
				VALUES ($1,$2::uuid,$3,$4,'test-executor','test-policy','test-only-issuer',
				        clock_timestamp()+interval '1 hour','ISSUED',
				        CASE WHEN $5::boolean THEN clock_timestamp() ELSE NULL END)
			`, "tenant-a", op.OperationID, strings.Repeat("a", 64), strings.Repeat("b", 64), tc.revoked)
			if err == nil {
				err = tx.Commit()
			} else {
				_ = tx.Rollback()
			}
			if tc.revoked {
				var pgErr *pgconn.PgError
				if !errors.As(err, &pgErr) || pgErr.Code != "23514" ||
					!strings.Contains(pgErr.Message, "Guard Permit INSERT must start ISSUED") {
					t.Fatalf("expected initial-state constraint rejection, got %v", err)
				}
			}
			if !tc.revoked && err != nil {
				t.Fatalf("valid initial ISSUED Permit rejected: %v", err)
			}
			var count int
			if err := db.QueryRowContext(ctx, `
				SELECT count(*) FROM guard_permits WHERE tenant_id=$1 AND operation_id=$2::uuid
			`, "tenant-a", op.OperationID).Scan(&count); err != nil {
				t.Fatal(err)
			}
			want := 1
			if tc.revoked {
				want = 0
			}
			if count != want {
				t.Fatalf("durable Permit count=%d want=%d", count, want)
			}
		})
	}
}

func TestCanonicalPermitInitialStateFenceRejectsDisabledTrigger(t *testing.T) {
	store, _, _ := seededWorkspacePermit(t)
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, "ALTER TABLE guard_permits DISABLE TRIGGER guard_permit_initial_state_v13"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, store.db); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("disabled initial-state trigger accepted: %v", err)
	}
}

// Historical tampering must not be blessed by a subsequent startup.
func TestCanonicalPermitInitialStateFenceRejectsMissingRevocationEvidence(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, `
		UPDATE guard_permits SET revoked_at=clock_timestamp()
		WHERE tenant_id=$1 AND permit_id=$2::uuid
	`, resolved.TenantID, permitID); err != nil {
		t.Fatalf("prepare isolated historical revocation drift: %v", err)
	}
	if err := Migrate(ctx, store.db); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("historical revocation without durable evidence accepted: %v", err)
	}
}
