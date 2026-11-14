package postgres

import (
	"context"
	"errors"
	"testing"
)

// A matching migration checksum and original catalog names are insufficient
// if an administrator accidentally recreates weaker CHECK expressions.
func TestMigrateRejectsSameNameWeakenedGuardCheckDefinitions(t *testing.T) {
	cases := []struct {
		name       string
		statements []string
	}{
		{
			name: "operation status can be promoted without permission",
			statements: []string{
				"ALTER TABLE guard_action_operations DROP CONSTRAINT guard_action_operations_status_check",
				"ALTER TABLE guard_action_operations ADD CONSTRAINT guard_action_operations_status_check CHECK (status IN ('ACCEPTED','AUTHORIZED'))",
			},
		},
		{
			name: "submission digest loses sha256 syntax",
			statements: []string{
				"ALTER TABLE guard_action_operations DROP CONSTRAINT guard_action_operations_submission_digest_check",
				"ALTER TABLE guard_action_operations ADD CONSTRAINT guard_action_operations_submission_digest_check CHECK (length(submission_digest) > 0)",
			},
		},
		{
			name: "outbox event type can be changed",
			statements: []string{
				"ALTER TABLE guard_outbox_events DROP CONSTRAINT guard_outbox_events_event_type_check",
				"ALTER TABLE guard_outbox_events ADD CONSTRAINT guard_outbox_events_event_type_check CHECK (event_type IN ('guard.submission.recorded.v1','guard.permit.issued.v1'))",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := unmigratedDatabase(t)
			ctx := context.Background()
			if err := Migrate(ctx, db); err != nil {
				t.Fatalf("initial migration: %v", err)
			}
			for _, statement := range tc.statements {
				if _, err := db.ExecContext(ctx, statement); err != nil {
					t.Fatalf("inject weakened same-named check: %v", err)
				}
			}
			if err := Migrate(ctx, db); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("same-name weakened Guard CHECK accepted: %v, want ErrSchemaDrift", err)
			}
		})
	}
}

func TestMigrateRejectsSameNameReorderedOutboxIndex(t *testing.T) {
	db := unmigratedDatabase(t)
	ctx := context.Background()
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("initial migration: %v", err)
	}
	for _, statement := range []string{
		"DROP INDEX guard_outbox_unpublished_idx",
		"CREATE INDEX guard_outbox_unpublished_idx ON guard_outbox_events (event_id,occurred_at)",
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("rewrite index while retaining its name: %v", err)
		}
	}
	if err := Migrate(ctx, db); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("same-name outbox index with wrong scan order accepted: %v, want ErrSchemaDrift", err)
	}
}
