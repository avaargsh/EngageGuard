package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
)

func installCanonicalPermitV14(t *testing.T, db *sql.DB) {
	t.Helper()
	installCanonicalPermitHistory(t, db, 13)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, stmt := range strings.Split(permitRevocationCausalSchema, "-- statement break") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("install historical v14: %v", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO guard_schema_migrations(version,checksum) VALUES (14,$1)",
		fmt.Sprintf("%x", sha256.Sum256([]byte(permitRevocationCausalSchema)))); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func seedV14Claim(t *testing.T, db *sql.DB) (*Store, action.WorkspaceWrite, string, DispatchIntent) {
	t.Helper()
	ctx := context.Background()
	var schema string
	if err := db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	store, err := NewWithTrustedSchema(db, schema)
	if err != nil {
		t.Fatal(err)
	}
	op, created, err := store.Accept(ctx, "tenant-a", "historical-v15-upgrade", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("historical admission fixture: created=%t err=%v", created, err)
	}
	resolved := action.WorkspaceWrite{
		SchemaVersion:     "v0.1",
		TenantID:          "tenant-a",
		SubjectID:         "verified-runtime-subject",
		AgentID:           "verified-agent",
		OperationID:       op.OperationID,
		CapabilityID:      "workspace.write",
		ToolBindingDigest: strings.Repeat("a", 64),
		PolicyVersion:     "signed-policy-7",
		Audience:          "trusted-workspace-executor",
		WorkspaceID:       "workspace-1",
		RelativePath:      "docs/output.md",
		ContentDigest:     strings.Repeat("b", 64),
	}
	hash, err := action.Hash(resolved)
	if err != nil {
		t.Fatal(err)
	}
	var permitID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO guard_permits
			(tenant_id,operation_id,action_hash,binding_digest,audience,
			 policy_version,issued_by,expires_at)
		VALUES ($1,$2::uuid,$3,$4,$5,$6,'test-only-v14-issuer',$7)
		RETURNING permit_id::text
	`, resolved.TenantID, resolved.OperationID, hash, resolved.ToolBindingDigest,
		resolved.Audience, resolved.PolicyVersion, time.Now().UTC().Add(time.Hour)).Scan(&permitID); err != nil {
		t.Fatal(err)
	}
	// Historical v14 has no v16 trusted-issuer evidence relation. Seed the
	// exact pre-v15 causal claim directly so this test can exercise migration
	// preservation without invoking the current trusted claim API.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
		UPDATE guard_permits
		SET state='CLAIMED', claimed_at=clock_timestamp()
		WHERE tenant_id=$1 AND permit_id=$2::uuid AND state='ISSUED'
	`, resolved.TenantID, permitID); err != nil {
		t.Fatal(err)
	}
	intent := DispatchIntent{
		TenantID: resolved.TenantID, OperationID: resolved.OperationID,
		PermitID: permitID, ActionHash: hash, State: "DISPATCHING",
	}
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO guard_operation_intents
			(tenant_id,operation_id,permit_id,action_hash,binding_digest,state)
		VALUES ($1,$2::uuid,$3::uuid,$4,$5,'DISPATCHING')
		RETURNING attempt_id::text
	`, resolved.TenantID, resolved.OperationID, permitID, hash, resolved.ToolBindingDigest).
		Scan(&intent.AttemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO guard_execution_audit
			(tenant_id,operation_id,permit_id,attempt_id,event_type,action_hash)
		VALUES ($1,$2::uuid,$3::uuid,$4::uuid,'guard.operation.dispatching.v1',$5)
	`, resolved.TenantID, resolved.OperationID, permitID, intent.AttemptID, hash); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return store, resolved, permitID, intent
}

func TestCanonicalV15UpgradesAuthenticV14Unknown(t *testing.T) {
	db := unmigratedDatabase(t)
	installCanonicalPermitV14(t, db)
	store, resolved, permitID, intent := seedV14Claim(t, db)
	ctx := context.Background()

	if _, err := store.MarkDispatchUnknown(ctx, resolved.TenantID, resolved.OperationID,
		intent.AttemptID, "ACK_LOST"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := Migrate(ctx, db); err != nil {
			t.Fatalf("v14 -> current upgrade preserving v15 failed: %v", err)
		}
	}
	var versions int
	var checksum string
	var installed bool
	if err := db.QueryRowContext(ctx, `
		SELECT count(*),
		       max(checksum) FILTER (WHERE version=15),
		       pg_catalog.to_regprocedure('guard_unknown_causal_commit_v15()') IS NOT NULL
		FROM guard_schema_migrations
	`).Scan(&versions, &checksum, &installed); err != nil {
		t.Fatal(err)
	}
	wantChecksum := fmt.Sprintf("%x", sha256.Sum256([]byte(permitUnknownCausalSchema)))
	if versions != 16 || checksum != wantChecksum || !installed {
		t.Fatalf("v15 migration evidence invalid: versions=%d checksum=%s installed=%t",
			versions, checksum, installed)
	}
	recovered, err := store.GetDispatchState(ctx, resolved.TenantID, resolved.OperationID, intent.AttemptID)
	if err != nil || recovered.State != "UNKNOWN" || recovered.Reason != "ACK_LOST" ||
		recovered.PermitID != permitID {
		t.Fatalf("v14 UNKNOWN evidence not preserved: %+v err=%v", recovered, err)
	}
}

func TestCanonicalV15RejectsHistoricalUnknownMismatchWithoutStamping(t *testing.T) {
	db := unmigratedDatabase(t)
	installCanonicalPermitV14(t, db)
	_, resolved, _, intent := seedV14Claim(t, db)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `
		UPDATE guard_operation_intents SET state='UNKNOWN'
		WHERE tenant_id=$1 AND attempt_id=$2::uuid
	`, resolved.TenantID, intent.AttemptID); err != nil {
		t.Fatalf("v14 mismatch fixture failed: %v", err)
	}
	if err := Migrate(ctx, db); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("historical UNKNOWN mismatch passed v15 upgrade: %v", err)
	}
	var versions int
	var installed bool
	if err := db.QueryRowContext(ctx, `
		SELECT count(*),
		       pg_catalog.to_regprocedure('guard_unknown_causal_commit_v15()') IS NOT NULL
		FROM guard_schema_migrations
	`).Scan(&versions, &installed); err != nil {
		t.Fatal(err)
	}
	if versions != 14 || installed {
		t.Fatalf("failed v15 upgrade stamped history or left function: versions=%d installed=%t",
			versions, installed)
	}
}
