package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
)

// In CI only, remove PostgreSQL's default PUBLIC TEMPORARY database grant
// during positive least-privilege role tests and restore it on cleanup.
// Never mutate the ACL of a developer/operator-supplied production database;
// this helper deliberately refuses to touch any database other than the
// disposable test container's "guard_ci".
func restrictPublicDatabaseTempForPermitTest(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	var databaseName, quotedDatabase string
	var publicTemp bool
	err := db.QueryRowContext(ctx, `
		SELECT pg_catalog.current_database(),
		       pg_catalog.format('%I', pg_catalog.current_database()),
		       EXISTS (
		           SELECT 1 FROM pg_catalog.pg_database d
		           CROSS JOIN LATERAL pg_catalog.aclexplode(
		               COALESCE(d.datacl, pg_catalog.acldefault('d', d.datdba))
		           ) AS acl
		           WHERE d.datname = pg_catalog.current_database()
		             AND acl.grantee = 0
		             AND acl.privilege_type = 'TEMPORARY'
		       )
	`).Scan(&databaseName, &quotedDatabase, &publicTemp)
	if err != nil {
		t.Fatal(err)
	}
	if databaseName != "guard_ci" {
		t.Skipf("refuse to modify PUBLIC TEMP ACL outside dedicated guard_ci database: %q", databaseName)
	}
	if !publicTemp {
		return
	}
	if _, err := db.ExecContext(ctx,
		"REVOKE TEMPORARY ON DATABASE "+quotedDatabase+" FROM PUBLIC"); err != nil {
		t.Fatalf("revoke CI-only default TEMP grant: %v", err)
	}
	t.Cleanup(func() {
		if _, err := db.ExecContext(context.Background(),
			"GRANT TEMPORARY ON DATABASE "+quotedDatabase+" TO PUBLIC"); err != nil {
			t.Errorf("restore CI-only public database TEMP grant: %v", err)
		}
	})
	// Explicitly prove revocation reached the database ACL. Postgres does not
	// support a per-role DENY overriding PUBLIC, so revoking PUBLIC is required.
	var effectivePublicTemp bool
	if err := db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_database d
			CROSS JOIN LATERAL pg_catalog.aclexplode(
				COALESCE(d.datacl, pg_catalog.acldefault('d', d.datdba))
			) AS acl
			WHERE d.datname = pg_catalog.current_database()
			  AND acl.grantee=0 AND acl.privilege_type='TEMPORARY'
		)
	`).Scan(&effectivePublicTemp); err != nil || effectivePublicTemp {
		t.Fatal(fmt.Errorf("CI-only database still grants PUBLIC TEMP: %t: %v", effectivePublicTemp, err))
	}
}
