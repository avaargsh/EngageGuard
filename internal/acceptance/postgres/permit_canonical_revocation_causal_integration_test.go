package postgres

import (
	"context"
	"errors"
	"testing"
)

// The Permit flag and immutable revocation journal must be atomic in both
// directions even when a storage writer bypasses the Go revocation helper.
// These fixtures exercise internal database integrity, not authorization.
func TestCanonicalRevocationRequiresMatchingFlagAndJournal(t *testing.T) {
	for _, tc := range []struct {
		name      string
		flag      bool
		journal   bool
		prior     string
		wantValid bool
	}{
		{name: "flag-only", flag: true},
		{name: "journal-only", journal: true, prior: "ISSUED"},
		{name: "mismatched-prior-state", flag: true, journal: true, prior: "CLAIMED"},
		{name: "matching-revocation", flag: true, journal: true, prior: "ISSUED", wantValid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, resolved, permitID := seededWorkspacePermit(t)
			ctx := context.Background()
			tx, err := store.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if tc.flag {
				if _, err := tx.ExecContext(ctx, `
					UPDATE guard_permits SET revoked_at=clock_timestamp()
					WHERE tenant_id=$1 AND permit_id=$2::uuid
				`, resolved.TenantID, permitID); err != nil {
					t.Fatalf("stage revocation flag: %v", err)
				}
			}
			if tc.journal {
				if _, err := tx.ExecContext(ctx, `
					INSERT INTO guard_permit_revocations
						(tenant_id,permit_id,evidence_ref,reason,prior_state)
					VALUES ($1,$2::uuid,'test-revocation','POLICY_REVOKED',$3)
				`, resolved.TenantID, permitID, tc.prior); err != nil {
					t.Fatalf("stage revocation journal: %v", err)
				}
			}
			err = tx.Commit()
			if tc.wantValid && err != nil {
				t.Fatalf("valid revocation rejected: %v", err)
			}
			if !tc.wantValid && err == nil {
				t.Fatal("invalid revocation committed without matching flag and journal")
			}
			var revoked bool
			var count int
			if err := store.db.QueryRowContext(ctx, `
				SELECT p.revoked_at IS NOT NULL,
				       (SELECT count(*) FROM guard_permit_revocations r
				        WHERE r.tenant_id=p.tenant_id AND r.permit_id=p.permit_id)
				FROM guard_permits p WHERE p.tenant_id=$1 AND p.permit_id=$2::uuid
			`, resolved.TenantID, permitID).Scan(&revoked, &count); err != nil {
				t.Fatal(err)
			}
			wantCount := 0
			if tc.wantValid {
				wantCount = 1
			}
			if revoked != tc.wantValid || count != wantCount {
				t.Fatalf("unexpected durable revocation: flag=%t rows=%d", revoked, count)
			}
		})
	}
}

func TestCanonicalRevocationCausalFenceRejectsDisabledTrigger(t *testing.T) {
	for _, target := range []struct {
		table, trigger string
	}{
		{"guard_permits", "guard_permit_revocation_commit_v14"},
		{"guard_permit_revocations", "guard_revocation_journal_commit_v14"},
	} {
		t.Run(target.trigger, func(t *testing.T) {
			store, _, _ := seededWorkspacePermit(t)
			ctx := context.Background()
			if _, err := store.db.ExecContext(ctx, "ALTER TABLE "+target.table+" DISABLE TRIGGER "+target.trigger); err != nil {
				t.Fatal(err)
			}
			if err := Migrate(ctx, store.db); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("disabled revocation causal trigger accepted: %v", err)
			}
		})
	}
}
