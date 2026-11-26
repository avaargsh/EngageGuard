package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// A legacy row in guard_permits is not proof that current trusted authority
// issued it. Once the v16 authority-evidence migration is installed, claim
// must fail closed unless the exact immutable issuance evidence exists.
func TestClaimRejectsPermitWithoutTrustedAuthorityEvidence(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	op, created, err := store.Accept(ctx, "tenant-a", "legacy-untrusted-permit", sampleSubmission())
	if err != nil || !created {
		t.Fatalf("accept source: created=%t err=%v", created, err)
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
	issuedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	expiresAt := issuedAt.Add(time.Hour)
	var permitID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO guard_permits
			(tenant_id,operation_id,action_hash,binding_digest,audience,
			 policy_version,issued_by,issued_at,expires_at)
		VALUES ($1,$2::uuid,$3,$4,$5,$6,'legacy-test-only',$7,$8)
		RETURNING permit_id::text
	`, resolved.TenantID, resolved.OperationID, hash, resolved.ToolBindingDigest,
		resolved.Audience, resolved.PolicyVersion, issuedAt, expiresAt).Scan(&permitID); err != nil {
		t.Fatal(err)
	}
	var evidence int
	if err := db.QueryRowContext(ctx,
		"SELECT count(*) FROM guard_permit_authority_evidence WHERE permit_id=$1::uuid",
		permitID).Scan(&evidence); err != nil || evidence != 0 {
		t.Fatalf("fixture unexpectedly has trusted authority evidence: rows=%d err=%v", evidence, err)
	}

	if got, err := store.ClaimAuthorizedIntent(ctx, permitID, resolved); !errors.Is(err, ErrPermitUnavailable) || got.AttemptID != "" {
		t.Fatalf("legacy Permit without trusted authority evidence was claimable: intent=%+v err=%v", got, err)
	}
	var state string
	var intents, audits int
	if err := db.QueryRowContext(ctx,
		"SELECT state FROM guard_permits WHERE permit_id=$1::uuid", permitID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM guard_operation_intents").Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM guard_execution_audit").Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if state != "ISSUED" || intents != 0 || audits != 0 {
		t.Fatalf("rejected legacy Permit mutated ledger: state=%s intents=%d audits=%d", state, intents, audits)
	}
}
