package postgres

import (
	"context"
	"errors"
	"testing"
)

// A constraint name/type alone is not sufficient integrity evidence:
// an operator can accidentally recreate the same FK name on operation_id
// while omitting tenant_id, breaking the tenant-bound operation lineage.
func TestMigrateRejectsSameNameWrongConstraintColumns(t *testing.T) {
	cases := []struct {
		name string
		sql  []string
	}{
		{
			name: "outbox fk loses tenant isolation",
			sql: []string{
				"ALTER TABLE guard_outbox_events DROP CONSTRAINT guard_outbox_operation_fk",
				"ALTER TABLE guard_outbox_events ADD CONSTRAINT guard_outbox_operation_fk FOREIGN KEY (operation_id) REFERENCES guard_action_operations(operation_id)",
			},
		},
		{
			name: "idempotency key unique constraint binds wrong columns",
			sql: []string{
				"ALTER TABLE guard_action_operations DROP CONSTRAINT guard_action_operations_tenant_id_submission_key_key",
				"ALTER TABLE guard_action_operations ADD CONSTRAINT guard_action_operations_tenant_id_submission_key_key UNIQUE (tenant_id, operation_id)",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := unmigratedDatabase(t)
			if err := Migrate(context.Background(), db); err != nil {
				t.Fatalf("install baseline: %v", err)
			}
			for _, statement := range tc.sql {
				if _, err := db.ExecContext(context.Background(), statement); err != nil {
					t.Fatalf("inject same-name constraint drift: %v", err)
				}
			}
			if err := Migrate(context.Background(), db); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("same-name wrong-column constraint accepted: %v, want ErrSchemaDrift", err)
			}
		})
	}
}
