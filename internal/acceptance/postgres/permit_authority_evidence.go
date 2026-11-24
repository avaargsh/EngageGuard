package postgres

import (
	"context"
	"database/sql"
	"fmt"
)

func verifyPermitAuthorityEvidence(ctx context.Context, tx *sql.Tx) error {
	var relationSafe bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM pg_catalog.pg_class c
			JOIN pg_catalog.pg_class m
			  ON m.oid=pg_catalog.to_regclass(
			    pg_catalog.format('%I.%I', pg_catalog.current_schema(), 'guard_schema_migrations'))
			WHERE c.oid=pg_catalog.to_regclass('guard_permit_authority_evidence')
			  AND c.relkind='r' AND c.relpersistence='p'
			  AND c.relnamespace=pg_catalog.current_schema()::regnamespace
			  AND c.relowner=m.relowner
		)
	`).Scan(&relationSafe); err != nil || !relationSafe {
		return fmt.Errorf("%w: v16 authority-evidence relation drift: %v", ErrSchemaDrift, err)
	}

	var permitIdentitySafe bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM pg_catalog.pg_constraint c
			JOIN pg_catalog.pg_index i ON i.indexrelid=c.conindid
			WHERE c.conrelid=pg_catalog.to_regclass('guard_permits')
			  AND c.conname='guard_permit_authority_identity_uq'
			  AND c.contype='u' AND c.convalidated
			  AND NOT c.condeferrable AND NOT c.condeferred
			  AND i.indrelid=c.conrelid AND i.indisunique
			  AND i.indisvalid AND i.indisready AND i.indislive AND i.indimmediate
			  AND i.indpred IS NULL AND i.indexprs IS NULL
			  AND (
			    SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			    FROM pg_catalog.unnest(c.conkey) WITH ORDINALITY k(attnum,ord)
			    JOIN pg_catalog.pg_attribute a
			      ON a.attrelid=c.conrelid AND a.attnum=k.attnum
			  )='tenant_id,operation_id,permit_id,action_hash,binding_digest,audience,policy_version,issued_by,issued_at,expires_at'
		)
	`).Scan(&permitIdentitySafe); err != nil || !permitIdentitySafe {
		return fmt.Errorf("%w: v16 Permit authority identity key drift: %v", ErrSchemaDrift, err)
	}

	for _, key := range []struct {
		name, kind, columns string
	}{
		{"guard_permit_authority_evidence_pkey", "p", "tenant_id,permit_id"},
		{"guard_permit_authority_operation_uq", "u", "tenant_id,operation_id"},
	} {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_constraint c
				WHERE c.conrelid=pg_catalog.to_regclass('guard_permit_authority_evidence')
				  AND c.conname=$1 AND c.contype=$2::"char" AND c.convalidated
				  AND NOT c.condeferrable AND NOT c.condeferred
				  AND (
				    SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
				    FROM pg_catalog.unnest(c.conkey) WITH ORDINALITY k(attnum,ord)
				    JOIN pg_catalog.pg_attribute a
				      ON a.attrelid=c.conrelid AND a.attnum=k.attnum
				  )=$3
			)
		`, key.name, key.kind, key.columns).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v16 authority-evidence key %s drift: %v", ErrSchemaDrift, key.name, err)
		}
	}

	var fkSafe bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass('guard_permit_authority_evidence')
			  AND c.conname='guard_permit_authority_exact_permit_fk'
			  AND c.contype='f' AND c.convalidated
			  AND NOT c.condeferrable AND NOT c.condeferred
			  AND c.confrelid=pg_catalog.to_regclass('guard_permits')
			  AND (
			    SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			    FROM pg_catalog.unnest(c.conkey) WITH ORDINALITY k(attnum,ord)
			    JOIN pg_catalog.pg_attribute a
			      ON a.attrelid=c.conrelid AND a.attnum=k.attnum
			  )='tenant_id,operation_id,permit_id,action_hash,binding_digest,audience,policy_version,issued_by,issued_at,expires_at'
			  AND (
			    SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			    FROM pg_catalog.unnest(c.confkey) WITH ORDINALITY k(attnum,ord)
			    JOIN pg_catalog.pg_attribute a
			      ON a.attrelid=c.confrelid AND a.attnum=k.attnum
			  )='tenant_id,operation_id,permit_id,action_hash,binding_digest,audience,policy_version,issued_by,issued_at,expires_at'
		)
	`).Scan(&fkSafe); err != nil || !fkSafe {
		return fmt.Errorf("%w: v16 authority-evidence Permit binding drift: %v", ErrSchemaDrift, err)
	}

	// v17 adds the source-resolved ActionRequest identity to new evidence.
	// Existing v16 rows remain all-NULL and are legacy-only; they are never
	// backfilled from a WorkspaceWrite because the missing Run/Plan/Capability
	// bindings cannot be reconstructed safely.
	var actionRequestColumns int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*)
		FROM (VALUES
			('decision_id'), ('plan_id'), ('plan_hash'), ('step_id'),
			('capability_id'), ('capability_version'),
			('capability_contract_sha256'), ('resource_ref')
		) AS expected(name)
		JOIN pg_catalog.pg_attribute a
		  ON a.attrelid=pg_catalog.to_regclass('guard_permit_authority_evidence')
		 AND a.attname=expected.name
		 AND a.atttypid='pg_catalog.text'::regtype
		 AND NOT a.attnotnull AND NOT a.attisdropped
	`).Scan(&actionRequestColumns); err != nil || actionRequestColumns != 8 {
		return fmt.Errorf("%w: v17 ActionRequest evidence columns drift: %v", ErrSchemaDrift, err)
	}

	for _, check := range []struct { name, expression string }{
		{"guard_permit_authority_action_request_v17_all_or_none_check", "(((decision_id IS NULL) = (plan_id IS NULL)) AND ((decision_id IS NULL) = (plan_hash IS NULL)) AND ((decision_id IS NULL) = (step_id IS NULL)) AND ((decision_id IS NULL) = (capability_id IS NULL)) AND ((decision_id IS NULL) = (capability_version IS NULL)) AND ((decision_id IS NULL) = (capability_contract_sha256 IS NULL)) AND ((decision_id IS NULL) = (resource_ref IS NULL)))"},
		{"guard_permit_authority_action_request_v17_decision_check", "((decision_id IS NULL) OR (((length(decision_id) >= 1) AND (length(decision_id) <= 512)) AND (decision_id !~ '[[:cntrl:][:space:]]'::text)))"},
		{"guard_permit_authority_action_request_v17_plan_check", "((plan_id IS NULL) OR (((length(plan_id) >= 1) AND (length(plan_id) <= 512)) AND (plan_id !~ '[[:cntrl:][:space:]]'::text)))"},
		{"guard_permit_authority_action_request_v17_plan_hash_check", "((plan_hash IS NULL) OR (plan_hash ~ '^[0-9a-f]{64}$'::text))"},
		{"guard_permit_authority_action_request_v17_step_check", "((step_id IS NULL) OR (((length(step_id) >= 1) AND (length(step_id) <= 512)) AND (step_id !~ '[[:cntrl:][:space:]]'::text)))"},
		{"guard_permit_authority_action_request_v17_capability_check", "((capability_id IS NULL) OR (((length(capability_id) >= 1) AND (length(capability_id) <= 512)) AND (capability_id !~ '[[:cntrl:][:space:]]'::text)))"},
		{"guard_permit_authority_action_request_v17_capability_version_check", "((capability_version IS NULL) OR (((length(capability_version) >= 1) AND (length(capability_version) <= 512)) AND (capability_version !~ '[[:cntrl:][:space:]]'::text)))"},
		{"guard_permit_authority_action_request_v17_capability_contract_check", "((capability_contract_sha256 IS NULL) OR (capability_contract_sha256 ~ '^[0-9a-f]{64}$'::text))"},
		{"guard_permit_authority_action_request_v17_resource_check", "((resource_ref IS NULL) OR (((length(resource_ref) >= 1) AND (length(resource_ref) <= 512)) AND (resource_ref !~ '[[:cntrl:][:space:]]'::text)))"},
	} {
		if err := verifyPermitAuthorityCheck(ctx, tx, check.name, check.expression, true); err != nil {
			return err
		}
	}

	// The ASCII constraint is intentionally NOT VALID so legacy v16 rows
	// remain readable; exact expression attestation still ensures all new
	// and changed v17 rows are constrained without OR TRUE-style weakening.
	if err := verifyPermitAuthorityCheck(ctx, tx,
		"guard_permit_authority_v17_ascii_identifiers_check",
		"(((run_id COLLATE \"C\") ~ '^[!-~]+$'::text) AND ((length(run_id) >= 1) AND (length(run_id) <= 512)) AND ((runtime_attempt_id COLLATE \"C\") ~ '^[!-~]+$'::text) AND ((length(runtime_attempt_id) >= 1) AND (length(runtime_attempt_id) <= 512)) AND ((turn_id COLLATE \"C\") ~ '^[!-~]+$'::text) AND ((length(turn_id) >= 1) AND (length(turn_id) <= 512)) AND ((approval_ref COLLATE \"C\") ~ '^[!-~]+$'::text) AND ((length(approval_ref) >= 1) AND (length(approval_ref) <= 512)) AND ((risk_revision COLLATE \"C\") ~ '^[!-~]+$'::text) AND ((length(risk_revision) >= 1) AND (length(risk_revision) <= 512)) AND ((audience COLLATE \"C\") ~ '^[!-~]+$'::text) AND ((length(audience) >= 1) AND (length(audience) <= 512)) AND ((policy_version COLLATE \"C\") ~ '^[!-~]+$'::text) AND ((length(policy_version) >= 1) AND (length(policy_version) <= 512)) AND ((issued_by COLLATE \"C\") ~ '^[!-~]+$'::text) AND ((length(issued_by) >= 1) AND (length(issued_by) <= 512)) AND ((decision_id IS NULL) OR (((decision_id COLLATE \"C\") ~ '^[!-~]+$'::text) AND ((length(decision_id) >= 1) AND (length(decision_id) <= 512)))) AND ((plan_id IS NULL) OR (((plan_id COLLATE \"C\") ~ '^[!-~]+$'::text) AND ((length(plan_id) >= 1) AND (length(plan_id) <= 512)))) AND ((step_id IS NULL) OR (((step_id COLLATE \"C\") ~ '^[!-~]+$'::text) AND ((length(step_id) >= 1) AND (length(step_id) <= 512)))) AND ((capability_id IS NULL) OR (((capability_id COLLATE \"C\") ~ '^[!-~]+$'::text) AND ((length(capability_id) >= 1) AND (length(capability_id) <= 512)))) AND ((capability_version IS NULL) OR (((capability_version COLLATE \"C\") ~ '^[!-~]+$'::text) AND ((length(capability_version) >= 1) AND (length(capability_version) <= 512)))) AND ((resource_ref IS NULL) OR (((resource_ref COLLATE \"C\") ~ '^[!-~]+$'::text) AND ((length(resource_ref) >= 1) AND (length(resource_ref) <= 512)))))", false); err != nil {
		return err
	}

	for _, trigger := range []struct {
		name string
		kind int
	}{
		{"guard_permit_authority_evidence_immutable_row", 27},
		{"guard_permit_authority_evidence_immutable_truncate", 34},
	} {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger t
				WHERE t.tgrelid=pg_catalog.to_regclass('guard_permit_authority_evidence')
				  AND t.tgname=$1 AND t.tgtype=$2
				  AND t.tgenabled='A' AND NOT t.tgisinternal
				  AND NOT t.tgdeferrable AND NOT t.tginitdeferred
				  AND t.tgqual IS NULL AND t.tgattr::text=''
				  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
				  AND t.tgfoid=pg_catalog.to_regprocedure('guard_reject_snapshot_mutation()')
			)
		`, trigger.name, trigger.kind).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v16 authority-evidence trigger %s drift: %v", ErrSchemaDrift, trigger.name, err)
		}
	}
	return nil
}

func verifyPermitAuthorityCheck(
	ctx context.Context, tx *sql.Tx, name, expected string, requireValidated bool,
) error {
	var actual string
	query := `
		SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
		FROM pg_catalog.pg_constraint c
		WHERE c.conrelid=pg_catalog.to_regclass('guard_permit_authority_evidence')
		  AND c.conname=$1 AND c.contype='c'
		  AND NOT c.condeferrable AND NOT c.condeferred
	`
	if requireValidated {
		query += " AND c.convalidated"
	}
	if err := tx.QueryRowContext(ctx, query, name).Scan(&actual); err != nil {
		return fmt.Errorf("%w: missing v17 ActionRequest check %s: %v", ErrSchemaDrift, name, err)
	}
	if actual != expected {
		return fmt.Errorf("%w: v17 ActionRequest check %s definition drifted", ErrSchemaDrift, name)
	}
	return nil
}
