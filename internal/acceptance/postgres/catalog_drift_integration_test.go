package postgres

import (
    "context"
    "errors"
    "testing"
)

// An unchanged migration checksum cannot attest the current live DB catalog.
// Failing to detect dropped relations or constraints permits schema-drifted
// admission idempotency and cross-operation attribution after restart.
func TestMigrateRejectsLiveSchemaDriftWithValidLedger(t *testing.T) {
    cases := []struct {
        name string
        corrupt string
    }{
        {"missing outbox relation", "DROP TABLE guard_outbox_events"},
        {"missing operation idempotency uniqueness", "ALTER TABLE guard_action_operations DROP CONSTRAINT guard_action_operations_tenant_id_submission_key_key"},
        {"missing cross-operation foreign key", "ALTER TABLE guard_outbox_events DROP CONSTRAINT guard_outbox_operation_fk"},
        {"missing outbox delivery index", "DROP INDEX guard_outbox_unpublished_idx"},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            db := unmigratedDatabase(t)
            if err := Migrate(context.Background(), db); err != nil {
                t.Fatalf("initial migration: %v", err)
            }
            if _, err := db.ExecContext(context.Background(), tc.corrupt); err != nil {
                t.Fatalf("inject catalog drift: %v", err)
            }
            if err := Migrate(context.Background(), db); !errors.Is(err, ErrSchemaDrift) {
                t.Fatalf("damaged catalog passed with valid checksum: %v, want ErrSchemaDrift", err)
            }
        })
    }
}
