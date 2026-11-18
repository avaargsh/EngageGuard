package postgres

import (
    "context"
    "strings"
    "testing"
)

// Permit revocations are durable source evidence, not a mutable operator log.
// A normal SQL writer, including one in replica mode, cannot rewrite or
// erase a committed revocation. We keep the test transaction isolated.
func TestPermitRevocationEvidenceWriteOnceUnderDirectSQL(t *testing.T) {
    ctx := context.Background()
    for _, replica := range []bool{false, true} {
        for _, tc := range []struct {
            name, query string
            args bool
        }{
            {"update", "UPDATE guard_permit_revocations SET evidence_ref='forged-evidence' WHERE permit_id=$1::uuid", true},
            {"delete", "DELETE FROM guard_permit_revocations WHERE permit_id=$1::uuid", true},
            {"truncate", "TRUNCATE guard_permit_revocations", false},
        } {
            label := tc.name + "/origin"
            if replica { label = tc.name + "/replica" }
            t.Run(label, func(t *testing.T) {
                store, resolved, permitID := seededWorkspacePermit(t)
                if ok, err := store.RevokeScopedPermit(ctx, resolved.TenantID, permitID,
                    "original-evidence", "SECURITY_RESPONSE"); err != nil || !ok {
                    t.Fatalf("seed revocation: %t %v", ok, err)
                }
                tx, err := store.db.BeginTx(ctx, nil)
                if err != nil { t.Fatal(err) }
                defer tx.Rollback()
                if replica {
                    if _, err := tx.ExecContext(ctx, "SET LOCAL session_replication_role=replica"); err != nil {
                        t.Fatal(err)
                    }
                }
                var args []any
                if tc.args { args = []any{permitID} }
                if _, err := tx.ExecContext(ctx, tc.query, args...); err == nil {
                    t.Fatalf("committed revocation permitted %s in replica=%t", tc.name, replica)
                }
            })
        }
    }
}

// Permit issuance identity and committed revocation must remain unchanged.
// Only the claimed-at and revoke-at state transitions are legitimate DML.
func TestPermitCannotBeRewrittenAfterIssuanceOrRevocation(t *testing.T) {
    ctx := context.Background()
    cases := []struct{name, sql string}{
        {"action hash", "UPDATE guard_permits SET action_hash=$2 WHERE permit_id=$1::uuid"},
        {"expiry extension", "UPDATE guard_permits SET expires_at=expires_at+interval '7 days' WHERE permit_id=$1::uuid"},
        {"revocation reset", "UPDATE guard_permits SET revoked_at=NULL WHERE permit_id=$1::uuid"},
        {"delete", "DELETE FROM guard_permits WHERE permit_id=$1::uuid"},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            store, resolved, permitID := seededWorkspacePermit(t)
            if ok, err := store.RevokeScopedPermit(ctx, resolved.TenantID, permitID,
                "guard-audit-immutable", "HUMAN_REVOKED"); err != nil || !ok {
                t.Fatalf("seed revocation: %t %v", ok, err)
            }
            tx, err := store.db.BeginTx(ctx, nil)
            if err != nil { t.Fatal(err) }
            defer tx.Rollback()
            args := []any{permitID}
            if tc.name == "action hash" { args = append(args, strings.Repeat("f", 64)) }
            if _, err := tx.ExecContext(ctx, tc.sql, args...); err == nil {
                t.Fatalf("issued/revoked Permit allowed %s mutation", tc.name)
            }
        })
    }
}
