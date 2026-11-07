package postgres

import (
    "context"
    "crypto/sha256"
    "database/sql"
    _ "embed"
    "fmt"
    "strings"
)

//go:embed schema_v3.sql
var snapshotReplicaSchema string

const snapshotReplicaMigrationVersion int64 = 3

// applySnapshotReplicaMigration is forward-only: old v2 checksum/DDL remain
// unchanged, while the two immutable-snapshot triggers become ALWAYS enabled.
func applySnapshotReplicaMigration(ctx context.Context, tx *sql.Tx) error {
    for _, ddl := range strings.Split(snapshotReplicaSchema, "\n-- statement break\n") {
        if strings.TrimSpace(ddl) == "" {
            continue
        }
        if _, err := tx.ExecContext(ctx, ddl); err != nil {
            return fmt.Errorf("enable Guard snapshot replica-mode fence: %w", err)
        }
    }
    if err := verifySnapshotReplicaCatalog(ctx, tx); err != nil {
        return err
    }
    sum := sha256.Sum256([]byte(snapshotReplicaSchema))
    if _, err := tx.ExecContext(ctx,
        "INSERT INTO guard_schema_migrations(version,checksum) VALUES ($1,$2)",
        snapshotReplicaMigrationVersion, fmt.Sprintf("%x", sum)); err != nil {
        return fmt.Errorf("record Guard v3 migration checksum: %w", err)
    }
    return nil
}

// verifySnapshotReplicaCatalog is the post-v3 attestation. The legacy v2
// verifier accepts origin triggers during an atomic v2->v3 upgrade; after v3,
// downgrading either trigger to origin-only must fail closed on every boot.
func verifySnapshotReplicaCatalog(ctx context.Context, tx *sql.Tx) error {
    for _, trigger := range []struct {
        name string
        bits int
    }{
        {"guard_snapshot_immutable_row", 27},
        {"guard_snapshot_immutable_truncate", 34},
    } {
        var valid bool
        err := tx.QueryRowContext(ctx, `
            SELECT EXISTS (
                SELECT 1 FROM pg_catalog.pg_trigger t
                WHERE t.tgrelid=pg_catalog.to_regclass('guard_accepted_submission_snapshots')
                  AND t.tgname=$1 AND NOT t.tgisinternal
                  AND t.tgenabled='A' AND t.tgtype=$2
                  AND t.tgqual IS NULL AND t.tgattr::text=''
                  AND NOT t.tgdeferrable AND NOT t.tginitdeferred
                  AND t.tgfoid=pg_catalog.to_regprocedure('guard_reject_snapshot_mutation()')
            )`, trigger.name, trigger.bits).Scan(&valid)
        if err != nil || !valid {
            return fmt.Errorf("%w: accepted snapshot replica-mode trigger %s drift: %v",
                ErrSchemaDrift, trigger.name, err)
        }
    }
    return nil
}
