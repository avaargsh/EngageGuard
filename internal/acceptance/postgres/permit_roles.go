package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrPermitRoleUnsafe means the configured PostgreSQL issuer/claim role
// privileges do not implement the necessary Permit separation boundary.
// This is not proof that Permit issuance or any external effect is authorized.
var ErrPermitRoleUnsafe = errors.New("Guard Permit issuer/claimer database role separation unsafe")

var permitRoleName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// VerifyPermitRoleSeparation audits two independently provisioned PostgreSQL
// roles against an operator-pinned Guard schema. It performs no DDL, grants, Permit
// issuance or provider effects. Run it using a migration/verification connection
// before enabling a future trusted issuer or claim worker.
//
// An issuer may INSERT an immutable Permit but not claim it or insert dispatch
// audit. A claimer may only UPDATE the Permit claim columns and INSERT the
// exact Intent/Audit, not mint a Permit, rewrite issuer identity or truncate
// evidence. Revocation requires a separate narrowly scoped actor/contract.
//
// Privilege inspection is a necessary *configuration check*, not a guarantee
// against a compromised schema owner, superuser, dynamic GRANTs after inspection,
// or a real-time execution race. Independently enforce least-privilege credentials.
func VerifyPermitRoleSeparation(
	ctx context.Context, db *sql.DB, trustedSchema, issuerRole, claimerRole string,
) error {
	unsafe := func(reason string, err error) error {
		if err == nil {
			return fmt.Errorf("%w: %s", ErrPermitRoleUnsafe, reason)
		}
		return fmt.Errorf("%w: %s: %v", ErrPermitRoleUnsafe, reason, err)
	}
	if ctx == nil || db == nil || !trustedSchemaPattern.MatchString(trustedSchema) ||
		strings.HasPrefix(trustedSchema, "pg_") || trustedSchema == "information_schema" ||
		issuerRole == claimerRole || !permitRoleName.MatchString(issuerRole) ||
		!permitRoleName.MatchString(claimerRole) {
		return unsafe("invalid or identical database roles", nil)
	}

	// Audit one physical session end-to-end. Checking privileges on different
	// pooled connections can combine contradictory search_path/schema views.
	conn, err := db.Conn(ctx)
	if err != nil {
		return unsafe("acquire dedicated role-audit PostgreSQL connection", err)
	}
	defer conn.Close()
	// A complete lookalike Permit schema with apparently safe grants must
	// never replace the configured schema after a session-level SET search_path.
	// The deployment connection baseline is necessary, but the caller must
	// independently protect that baseline against untrusted configuration.
	var pathIntact bool
	err = conn.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_settings s
			WHERE s.name='search_path'
			  AND s.setting=s.reset_val
			  AND pg_catalog.current_schema() = $1::text
		)
	`, trustedSchema).Scan(&pathIntact)
	if err != nil || !pathIntact {
		return unsafe("role audit search_path/current_schema differs from operator-pinned trusted schema or connection baseline", err)
	}
	var issuerSafe, claimerSafe bool
	err = conn.QueryRowContext(ctx, `
		SELECT
			COALESCE((SELECT NOT (rolsuper OR rolcreaterole OR rolreplication OR rolbypassrls OR rolcreatedb)
				FROM pg_catalog.pg_roles WHERE rolname=$1), false),
			COALESCE((SELECT NOT (rolsuper OR rolcreaterole OR rolreplication OR rolbypassrls OR rolcreatedb)
				FROM pg_catalog.pg_roles WHERE rolname=$2), false)
	`, issuerRole, claimerRole).Scan(&issuerSafe, &claimerSafe)
	if err != nil || !issuerSafe || !claimerSafe {
		return unsafe("missing or privileged database role", err)
	}
	var inheritedMembership bool
	err = conn.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM pg_catalog.pg_roles r
			WHERE r.rolname NOT IN ($1::name, $2::name)
			  AND (
				pg_catalog.pg_has_role($1::name, r.rolname, 'MEMBER')
				OR pg_catalog.pg_has_role($2::name, r.rolname, 'MEMBER')
			  )
		)
	`, issuerRole, claimerRole).Scan(&inheritedMembership)
	if err != nil || inheritedMembership {
		return unsafe("issuer/claimer role inherits or can SET ROLE to another database role", err)
	}

	// PostgreSQL commonly grants TEMPORARY on newly created databases to
	// PUBLIC. A role can therefore create pg_temp lookalikes without any
	// CREATE privilege on the Guard schema. Database-level CREATE also
	// permits a new writable schema and a startup search_path redirection.
	// These privileges (including those inherited from PUBLIC/other roles)
	// are incompatible with protected issuer/claimer database identities.
	for _, role := range []string{issuerRole, claimerRole} {
		var canTemp, canCreateDatabaseSchema bool
		err = conn.QueryRowContext(ctx, `
			SELECT pg_catalog.has_database_privilege($1::name, pg_catalog.current_database(), 'TEMPORARY'),
			       pg_catalog.has_database_privilege($1::name, pg_catalog.current_database(), 'CREATE')
		`, role).Scan(&canTemp, &canCreateDatabaseSchema)
		if err != nil || canTemp || canCreateDatabaseSchema {
			return unsafe("role can create temporary relations or database schemas", err)
		}
	}
	// Each role must use the schema but must not create a shadow relation or
	// function in the namespace that holds the trusted Permit ledger.
	for _, role := range []string{issuerRole, claimerRole} {
		var usage, canCreate bool
		err = conn.QueryRowContext(ctx, `
			SELECT pg_catalog.has_schema_privilege($1::name, $2::name, 'USAGE'),
			       pg_catalog.has_schema_privilege($1::name, $2::name, 'CREATE')
		`, role, trustedSchema).Scan(&usage, &canCreate)
		if err != nil || !usage || canCreate {
			return unsafe("schema usage/creation privileges", err)
		}
	}

	// Table grants and column grants are separate in PostgreSQL. Probe any
	// column-level SELECT/INSERT/UPDATE grant as well as table-level rights;
	// a narrow grant must not bypass the intended read/write boundary.
	type probe struct {
		role, table, column, privilege string
		want                           bool
	}
	probes := []probe{
		{issuerRole, "guard_permits", "", "INSERT", true},
		{issuerRole, "guard_permits", "", "SELECT", true},
		{issuerRole, "guard_permits", "", "UPDATE", false},
		{issuerRole, "guard_permits", "", "DELETE", false},
		{issuerRole, "guard_permits", "", "TRUNCATE", false},
		{issuerRole, "guard_operation_intents", "", "INSERT", false},
		{issuerRole, "guard_execution_audit", "", "INSERT", false},
		{claimerRole, "guard_permits", "", "SELECT", true},
		{claimerRole, "guard_permits", "", "INSERT", false},
		{claimerRole, "guard_permits", "", "DELETE", false},
		{claimerRole, "guard_permits", "", "TRUNCATE", false},
		{claimerRole, "guard_operation_intents", "", "INSERT", true},
		{claimerRole, "guard_execution_audit", "", "INSERT", true},
		{claimerRole, "guard_operation_intents", "", "DELETE", false},
		{claimerRole, "guard_execution_audit", "", "DELETE", false},
		{claimerRole, "guard_operation_intents", "", "TRUNCATE", false},
		{claimerRole, "guard_execution_audit", "", "TRUNCATE", false},
		{claimerRole, "guard_permits", "state", "UPDATE", true},
		{claimerRole, "guard_permits", "claimed_at", "UPDATE", true},
		{issuerRole, "guard_permits", "state", "UPDATE", false},
		{issuerRole, "guard_permits", "claimed_at", "UPDATE", false},
		{issuerRole, "guard_permits", "revoked_at", "UPDATE", false},
	}
	for _, column := range []string{
		"permit_id", "tenant_id", "operation_id", "action_hash",
		"binding_digest", "audience", "policy_version", "issued_by",
		"issued_at", "expires_at", "revoked_at",
	} {
		probes = append(probes, probe{claimerRole, "guard_permits", column, "UPDATE", false})
	}
	// A Permit writer needs to SELECT the exact accepted source, but must
	// never create or mutate that source. The claimer needs no source-table
	// privileges at all. Deny indirect writes to migration, UNKNOWN and
	// revocation journals as well as the original operation/outbox tables.
	// Check both whole-table and column-level INSERT/UPDATE grants.
	for _, role := range []string{issuerRole, claimerRole} {
		for _, table := range []string{
			"guard_action_operations",
			"guard_accepted_submission_snapshots",
			"guard_outbox_events",
			"guard_schema_migrations",
			"guard_operation_unknown_events",
			"guard_permit_revocations",
		} {
			sourceRead := role == issuerRole &&
				(table == "guard_action_operations" || table == "guard_accepted_submission_snapshots")
			probes = append(probes, probe{role, table, "", "SELECT", sourceRead})
			for _, privilege := range []string{"INSERT", "UPDATE", "DELETE", "TRUNCATE"} {
				probes = append(probes, probe{role, table, "", privilege, false})
			}
		}
	}
	// The claimer can only append Intent/Audit and update exact Permit
	// claim columns. Any UPDATE or DELETE on the causal evidence must be
	// rejected regardless of the database's immutable row triggers.
	for _, table := range []string{"guard_operation_intents", "guard_execution_audit"} {
		for _, role := range []string{issuerRole, claimerRole} {
			for _, privilege := range []string{"UPDATE", "DELETE", "TRUNCATE"} {
				probes = append(probes, probe{role, table, "", privilege, false})
			}
		}
	}
	// Resolve every relation by explicit schema qualification. This bypasses
	// pg_temp name precedence and ensures privileges are checked on the
	// operator-pinned permanent Guard objects, not session-local lookalikes.
	// Keep privilege functions in pg_catalog so search_path cannot shadow them.
	for _, pr := range probes {
		var got bool
		var q string
		if pr.column != "" {
			q = "SELECT pg_catalog.has_column_privilege($1::name, pg_catalog.to_regclass(pg_catalog.format('%I.%I', $5::text, $2::text)), $3::name, $4::text)"
			err = conn.QueryRowContext(ctx, q, pr.role, pr.table, pr.column, pr.privilege, trustedSchema).Scan(&got)
		} else if pr.privilege == "SELECT" || pr.privilege == "INSERT" || pr.privilege == "UPDATE" {
			q = "SELECT pg_catalog.has_any_column_privilege($1::name, pg_catalog.to_regclass(pg_catalog.format('%I.%I', $4::text, $2::text)), $3::text)"
			err = conn.QueryRowContext(ctx, q, pr.role, pr.table, pr.privilege, trustedSchema).Scan(&got)
		} else {
			q = "SELECT pg_catalog.has_table_privilege($1::name, pg_catalog.to_regclass(pg_catalog.format('%I.%I', $4::text, $2::text)), $3::text)"
			err = conn.QueryRowContext(ctx, q, pr.role, pr.table, pr.privilege, trustedSchema).Scan(&got)
		}
		if err != nil || got != pr.want {
			return unsafe(fmt.Sprintf("unexpected %s %s.%s privilege for %s", pr.privilege, pr.table, pr.column, pr.role), err)
		}
	}
	return nil
}
