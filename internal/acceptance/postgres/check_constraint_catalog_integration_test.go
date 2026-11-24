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
			name: "v17 printable ASCII identifiers lose the 512-character bound",
			statements: []string{
				"ALTER TABLE guard_permit_authority_evidence DROP CONSTRAINT guard_permit_authority_v17_ascii_identifiers_check",
				"ALTER TABLE guard_permit_authority_evidence ADD CONSTRAINT guard_permit_authority_v17_ascii_identifiers_check CHECK (run_id COLLATE \"C\" ~ '^[!-~]+$') NOT VALID",
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


// Every v17 authority-evidence CHECK must be attested as a complete expression.
// Keeping the original expression as a subexpression while appending OR TRUE
// preserves all expected tokens but disables the constraint semantically.
func TestPermitAuthorityEvidenceRejectsSameNameAlwaysTrueV17Checks(t *testing.T) {
	constraints := []struct {
		name     string
		notValid bool
	}{
		{"guard_permit_authority_action_request_v17_all_or_none_check", false},
		{"guard_permit_authority_action_request_v17_decision_check", false},
		{"guard_permit_authority_action_request_v17_plan_check", false},
		{"guard_permit_authority_action_request_v17_plan_hash_check", false},
		{"guard_permit_authority_action_request_v17_step_check", false},
		{"guard_permit_authority_action_request_v17_capability_check", false},
		{"guard_permit_authority_action_request_v17_capability_version_check", false},
		{"guard_permit_authority_action_request_v17_capability_contract_check", false},
		{"guard_permit_authority_action_request_v17_resource_check", false},
		{"guard_permit_authority_v17_ascii_identifiers_check", true},
	}
	for _, constraint := range constraints {
		t.Run(constraint.name, func(t *testing.T) {
			store, _ := integrationStore(t)
			ctx := context.Background()

			var original string
			if err := store.db.QueryRowContext(ctx, `
				SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
				FROM pg_catalog.pg_constraint c
				WHERE c.conrelid=pg_catalog.to_regclass('guard_permit_authority_evidence')
				  AND c.conname=$1
			`, constraint.name).Scan(&original); err != nil {
				t.Fatal(err)
			}
			t.Logf("original CHECK expression: %s", original)

			if _, err := store.db.ExecContext(ctx,
				"ALTER TABLE guard_permit_authority_evidence DROP CONSTRAINT "+constraint.name); err != nil {
				t.Fatalf("drop original CHECK: %v", err)
			}
			statement := "ALTER TABLE guard_permit_authority_evidence ADD CONSTRAINT " +
				constraint.name + " CHECK (" + original + " OR TRUE)"
			if constraint.notValid {
				statement += " NOT VALID"
			}
			if _, err := store.db.ExecContext(ctx, statement); err != nil {
				t.Fatalf("install same-name weakened CHECK: %v", err)
			}

			tx, err := store.beginLedgerTx(ctx, true)
			if err != nil {
				t.Fatalf("begin trusted Permit ledger transaction: %v", err)
			}
			defer tx.Rollback()
			if err := verifyPermitAuthorityEvidence(ctx, tx); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("same-name always-true Permit CHECK accepted; original=%q err=%v, want ErrSchemaDrift", original, err)
			}
		})
	}
}
