package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
)

// ErrPermitRoleUnsafe means the configured PostgreSQL issuer/claim role
// privileges do not implement the necessary Permit separation boundary.
// This is not proof that Permit issuance or any external effect is authorized.
var ErrPermitRoleUnsafe = errors.New("Guard Permit issuer/claimer database role separation unsafe")

var permitRoleName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// VerifyPermitRoleSeparation audits two independently provisioned PostgreSQL
// roles on the caller's current_schema(). It performs no DDL, grants, Permit
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
	ctx context.Context, db *sql.DB, issuerRole, claimerRole string,
) error {
	unsafe := func(reason string, err error) error {
		if err == nil {
			return fmt.Errorf("%w: %s", ErrPermitRoleUnsafe, reason)
		}
		return fmt.Errorf("%w: %s: %v", ErrPermitRoleUnsafe, reason, err)
	}
	if ctx == nil || db == nil || issuerRole == claimerRole ||
		!permitRoleName.MatchString(issuerRole) || !permitRoleName.MatchString(claimerRole) {
		return unsafe("invalid or identical database roles", nil)
	}

	var issuerSafe, claimerSafe bool
	err := db.QueryRowContext(ctx, `
		SELECT
			COALESCE((SELECT NOT (rolsuper OR rolcreaterole OR rolreplication OR rolbypassrls OR rolcreatedb)
				FROM pg_catalog.pg_roles WHERE rolname=$1), false),
			COALESCE((SELECT NOT (rolsuper OR rolcreaterole OR rolreplication OR rolbypassrls OR rolcreatedb)
				FROM pg_catalog.pg_roles WHERE rolname=$2), false)
	`, issuerRole, claimerRole).Scan(&issuerSafe, &claimerSafe)
	if err != nil || !issuerSafe || !claimerSafe {
		return unsafe("missing or privileged database role", err)
	}
	var shared bool
	err = db.QueryRowContext(ctx, `
		SELECT pg_has_role($1::name,$2::name,'MEMBER')
		    OR pg_has_role($2::name,$1::name,'MEMBER')
	`, issuerRole, claimerRole).Scan(&shared)
	if err != nil || shared {
		return unsafe("role membership permits cross-role escalation", err)
	}

	// Each role must use the schema but must not create a shadow relation or
	// function in the namespace that holds the trusted Permit ledger.
	for _, role := range []string{issuerRole, claimerRole} {
		var usage, canCreate bool
		err = db.QueryRowContext(ctx, `
			SELECT has_schema_privilege($1::name, current_schema(), 'USAGE'),
			       has_schema_privilege($1::name, current_schema(), 'CREATE')
		`, role).Scan(&usage, &canCreate)
		if err != nil || !usage || canCreate {
			return unsafe("schema usage/creation privileges", err)
		}
	}

	// Table grants and column grants are separate in PostgreSQL. Query the
	// latter too: an INSERT(column) or UPDATE(identity_column) grant must not
	// silently pass a check looking only at whole-table privileges.
	type probe struct {
		role, table, column, privilege string
		want bool
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
	for _, pr := range probes {
		var got bool
		var q string
		if pr.column != "" {
			q = "SELECT has_column_privilege($1::name,to_regclass($2),$3::name,$4::text)"
			err = db.QueryRowContext(ctx, q, pr.role, pr.table, pr.column, pr.privilege).Scan(&got)
		} else if pr.privilege == "INSERT" || pr.privilege == "UPDATE" {
			q = "SELECT has_any_column_privilege($1::name,to_regclass($2),$3::text)"
			err = db.QueryRowContext(ctx, q, pr.role, pr.table, pr.privilege).Scan(&got)
		} else {
			q = "SELECT has_table_privilege($1::name,to_regclass($2),$3::text)"
			err = db.QueryRowContext(ctx, q, pr.role, pr.table, pr.privilege).Scan(&got)
		}
		if err != nil || got != pr.want {
			return unsafe(fmt.Sprintf("unexpected %s %s.%s privilege for %s", pr.privilege, pr.table, pr.column, pr.role), err)
		}
	}
	return nil
}
