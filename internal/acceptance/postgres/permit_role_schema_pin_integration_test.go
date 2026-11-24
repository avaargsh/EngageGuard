package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// A verifier that trusts only current_schema()/search_path reset_val can be
// redirected by a connection whose startup search_path is configured to a
// complete but non-authoritative schema. The expected schema must be pinned
// independently by operator configuration.
func TestPermitRoleSeparationRejectsOperatorSchemaMismatch(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	decoy := fmt.Sprintf("guard_role_decoy_startup_%d", time.Now().UnixNano())
	if _, err := db.ExecContext(ctx, "CREATE SCHEMA "+decoy); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP SCHEMA "+decoy+" CASCADE")
	})

	config, err := pgx.ParseConfig(os.Getenv("GUARD_PG_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = decoy
	decoyDB := stdlib.OpenDB(*config)
	t.Cleanup(func() { _ = decoyDB.Close() })
	var active string
	if err := decoyDB.QueryRowContext(ctx, "SELECT current_schema()").Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != decoy {
		t.Fatalf("decoy startup search_path = %q, want %q", active, decoy)
	}

	err = VerifyPermitRoleSeparation(ctx, decoyDB, store.trustedSchema,
		"guard_issuer_test", "guard_claimer_test")
	if !errors.Is(err, ErrPermitRoleUnsafe) || err == nil {
		t.Fatalf("role audit accepted startup-selected schema %q instead of operator-pinned %q: %v",
			decoy, store.trustedSchema, err)
	}
	if !containsPermitRoleReason(err, "trusted schema") {
		t.Fatalf("role audit rejected for unrelated reason; want trusted-schema mismatch: %v", err)
	}
}


func containsPermitRoleReason(err error, reason string) bool {
	return err != nil && strings.Contains(err.Error(), reason)
}
