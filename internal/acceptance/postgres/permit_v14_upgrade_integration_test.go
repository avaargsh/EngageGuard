package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Construct an authentic historical catalog from the immutable SQL sources,
// never by deleting ledger versions from a current v14 installation.
func installCanonicalPermitHistory(t *testing.T, db *sql.DB, version int) {
	t.Helper()
	if version < 11 || version > 13 {
		t.Fatalf("unsupported historical fixture version %d", version)
	}
	installPermitV10ForUpgradeTest(t, db)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for i, source := range []string{permitCausalPinnedSchema, permitExpiryFenceSchema, permitInitialStateSchema} {
		v := i + 11
		if v > version {
			break
		}
		for _, stmt := range strings.Split(source, "-- statement break") {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("install historical v%d: %v", v, err)
			}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO guard_schema_migrations(version,checksum) VALUES ($1,$2)", v, fmt.Sprintf("%x", sha256.Sum256([]byte(source)))); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalV14UpgradesAuthenticHistoricalCatalogs(t *testing.T) {
	for _, version := range []int{11, 12, 13} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			db := unmigratedDatabase(t)
			installCanonicalPermitHistory(t, db, version)
			ctx := context.Background()
			store := New(db)
			op, created, err := store.Accept(ctx, "tenant-a", "historical-v14-upgrade", sampleSubmission())
			if err != nil || !created {
				t.Fatalf("historical acceptance fixture: created=%t err=%v", created, err)
			}
			var permitID string
			if err := db.QueryRowContext(ctx, `
				INSERT INTO guard_permits
					(tenant_id,operation_id,action_hash,binding_digest,audience,
					 policy_version,issued_by,expires_at,state)
				VALUES ($1,$2::uuid,$3,$4,'test-executor','test-policy','test-only-issuer',
				        clock_timestamp()+interval '1 hour','ISSUED')
				RETURNING permit_id::text
			`, op.TenantID, op.OperationID, strings.Repeat("a", 64), strings.Repeat("b", 64)).Scan(&permitID); err != nil {
				t.Fatal(err)
			}
			if changed, err := store.RevokeScopedPermit(ctx, op.TenantID, permitID, "historical-revocation", "POLICY_REVOKED"); err != nil || !changed {
				t.Fatalf("historical revocation fixture: changed=%t err=%v", changed, err)
			}
			for range 2 {
				if err := Migrate(ctx, db); err != nil {
					t.Fatalf("upgrade/restart from v%d: %v", version, err)
				}
			}
			for i, source := range []string{
				initialSchema, snapshotSchema, snapshotReplicaSchema, permitClaimSchema,
				permitIdentitySchema, permitUnknownSchema, permitRevocationSchema,
				permitEvidenceFenceSchema, permitIdentityFenceSchema, permitCausalCommitSchema,
				permitCausalPinnedSchema, permitExpiryFenceSchema, permitInitialStateSchema,
				permitRevocationCausalSchema,
			} {
				var actual string
				if err := db.QueryRowContext(ctx, "SELECT checksum FROM guard_schema_migrations WHERE version=$1", i+1).Scan(&actual); err != nil || actual != fmt.Sprintf("%x", sha256.Sum256([]byte(source))) {
					t.Fatalf("migration v%d checksum mismatch: %v", i+1, err)
				}
			}
			record, err := store.ReadAcceptedSubmission(ctx, op.TenantID, op.OperationID)
			if err != nil || record.Operation.OperationID != op.OperationID {
				t.Fatalf("historical acceptance lost: %v", err)
			}
			var intact bool
			if err := db.QueryRowContext(ctx, `
				SELECT EXISTS (
					SELECT 1 FROM guard_permits p
					JOIN guard_permit_revocations r USING (tenant_id,permit_id)
					WHERE p.tenant_id=$1 AND p.permit_id=$2::uuid
					  AND p.state='ISSUED' AND p.revoked_at IS NOT NULL
					  AND r.prior_state='ISSUED' AND r.evidence_ref='historical-revocation'
				)
			`, op.TenantID, permitID).Scan(&intact); err != nil || !intact {
				t.Fatalf("historical revocation lost: %v", err)
			}
		})
	}
}

func TestCanonicalV14RejectsHistoricalOrphanJournalWithoutStamping(t *testing.T) {
	db := unmigratedDatabase(t)
	installCanonicalPermitHistory(t, db, 13)
	ctx := context.Background()
	op, created, err := New(db).Accept(ctx, "tenant-a", "historical-orphan-journal", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("historical acceptance fixture: created=%t err=%v", created, err)
	}
	var permitID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO guard_permits
			(tenant_id,operation_id,action_hash,binding_digest,audience,
			 policy_version,issued_by,expires_at,state)
		VALUES ($1,$2::uuid,$3,$4,'test-executor','test-policy','test-only-issuer',
		        clock_timestamp()+interval '1 hour','ISSUED')
		RETURNING permit_id::text
	`, op.TenantID, op.OperationID, strings.Repeat("a", 64), strings.Repeat("b", 64)).Scan(&permitID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO guard_permit_revocations
			(tenant_id,permit_id,evidence_ref,reason,prior_state)
		VALUES ($1,$2::uuid,'historical-orphan','POLICY_REVOKED','ISSUED')
	`, op.TenantID, permitID); err != nil {
		t.Fatalf("historical orphan journal fixture: %v", err)
	}
	if err := Migrate(ctx, db); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("historical inconsistent revocation passed upgrade: %v", err)
	}
	var versions int
	var installed bool
	if err := db.QueryRowContext(ctx, `
		SELECT count(*), pg_catalog.to_regprocedure('guard_revocation_causal_commit_v14()') IS NOT NULL
		FROM guard_schema_migrations
	`).Scan(&versions, &installed); err != nil || versions != 13 || installed {
		t.Fatalf("failed upgrade stamped history or left v14 function: versions=%d installed=%t err=%v", versions, installed, err)
	}
}
