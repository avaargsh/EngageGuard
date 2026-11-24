package postgres

import (
	"context"
	"errors"
	"testing"
)

// A stable function OID is not evidence that the original Permit
// immutability contract is still enforced. A schema-owner change must
// be detected at startup, before trusting the ledger.
func TestPermitV9CatalogRejectsReplacedImmutableFunction(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	var before, after uint32
	if err := store.db.QueryRowContext(ctx, "SELECT to_regprocedure('guard_permit_immutable_row_v9()')::oid").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `
		CREATE OR REPLACE FUNCTION guard_permit_immutable_row_v9() RETURNS trigger
		LANGUAGE plpgsql AS $guard$
		BEGIN
			RETURN NEW;
		END;
		$guard$;
	`); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, "SELECT to_regprocedure('guard_permit_immutable_row_v9()')::oid").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("fixture changed function OID: %d != %d", before, after)
	}
	if err := Migrate(ctx, store.db); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("replaced v9 immutable function passed catalog validation: %v", err)
	}
}
