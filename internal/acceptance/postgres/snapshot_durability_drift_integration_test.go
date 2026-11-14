package postgres

import (
	"context"
	"errors"
	"testing"
)

// A valid migration checksum does not prove that accepted exact-byte
// submission evidence will survive a PostgreSQL crash. UNLOGGED tables
// can be truncated after an unclean shutdown, so both the snapshot and
// the authoritative version ledger must remain ordinary persistent tables.
func TestV2MigrationRejectsUnloggedAuthoritativeRelations(t *testing.T) {
	for _, tc := range []struct {
		name string
		sql  string
	}{
		{
			name: "accepted exact-byte snapshot",
			sql:  "ALTER TABLE guard_accepted_submission_snapshots SET UNLOGGED",
		},
		{
			name: "versioned migration ledger",
			sql:  "ALTER TABLE guard_schema_migrations SET UNLOGGED",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := unmigratedDatabase(t)
			ctx := context.Background()
			if err := Migrate(ctx, db); err != nil {
				t.Fatalf("create clean v2 schema: %v", err)
			}
			if _, err := db.ExecContext(ctx, tc.sql); err != nil {
				t.Fatalf("inject crash-unsafe storage drift: %v", err)
			}
			if err := Migrate(ctx, db); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("checksum-matched UNLOGGED authority accepted (%s): %v", tc.name, err)
			}
		})
	}
}
