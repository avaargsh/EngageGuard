package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
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

	for _, check := range []struct {
		name     string
		required []string
		expected string
	}{
		{
			"guard_permit_authority_action_request_v17_all_or_none_check",
			[]string{"decision_id", "plan_id", "plan_hash", "step_id", "capability_id", "capability_version", "capability_contract_sha256", "resource_ref", "IS NULL", "="},
		},
		{"guard_permit_authority_action_request_v17_decision_check", []string{"decision_id", "IS NULL", "length", "!~", "[[:cntrl:][:space:]]"}},
		{"guard_permit_authority_action_request_v17_plan_check", []string{"plan_id", "IS NULL", "length", "!~", "[[:cntrl:][:space:]]"}},
		{"guard_permit_authority_action_request_v17_plan_hash_check", []string{"plan_hash", "IS NULL", "~", "^[0-9a-f]{64}$"}, "((plan_hash IS NULL) OR (plan_hash ~ '^[0-9a-f]{64}		{"guard_permit_authority_action_request_v17_step_check", []string{"step_id", "IS NULL", "length", "!~", "[[:cntrl:][:space:]]"}},
		{"guard_permit_authority_action_request_v17_capability_check", []string{"capability_id", "IS NULL", "length", "!~", "[[:cntrl:][:space:]]"}},
		{"guard_permit_authority_action_request_v17_capability_version_check", []string{"capability_version", "IS NULL", "length", "!~", "[[:cntrl:][:space:]]"}},
		{"guard_permit_authority_action_request_v17_capability_contract_check", []string{"capability_contract_sha256", "IS NULL", "~", "^[0-9a-f]{64}$"}},
		{"guard_permit_authority_action_request_v17_resource_check", []string{"resource_ref", "IS NULL", "length", "!~", "[[:cntrl:][:space:]]"}},
	} {
		var expression string
		if err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
			FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass('guard_permit_authority_evidence')
			  AND c.conname=$1 AND c.contype='c' AND c.convalidated
			  AND NOT c.condeferrable AND NOT c.condeferred
		`, check.name).Scan(&expression); err != nil {
			return fmt.Errorf("%w: missing v17 ActionRequest check %s: %v", ErrSchemaDrift, check.name, err)
		}
		for _, token := range check.required {
			if !strings.Contains(expression, token) {
				return fmt.Errorf("%w: v17 ActionRequest check %s lost %q", ErrSchemaDrift, check.name, token)
			}
		}
		// Token presence alone is not a semantic attestation: a weakened
		// expression can retain every token and append "OR TRUE".
		if check.expected != "" && expression != check.expected {
			return fmt.Errorf("%w: v17 ActionRequest check %s expression drift", ErrSchemaDrift, check.name)
		}
	}

	// v17's NOT VALID ASCII constraint preserves immutable legacy v16 rows
	// without blessing them as ActionRequest v1 evidence. PostgreSQL still
	// enforces the constraint for every new/changed row, including issuer-role
	// writes which bypass Go's printable-ASCII validator.
	var asciiExpression string
	if err := tx.QueryRowContext(ctx, `
		SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
		FROM pg_catalog.pg_constraint c
		WHERE c.conrelid=pg_catalog.to_regclass('guard_permit_authority_evidence')
		  AND c.conname='guard_permit_authority_v17_ascii_identifiers_check'
		  AND c.contype='c' AND NOT c.condeferrable AND NOT c.condeferred
	`).Scan(&asciiExpression); err != nil {
		return fmt.Errorf("%w: missing v17 ASCII authority-evidence constraint: %v", ErrSchemaDrift, err)
	}
	for _, column := range []string{
		"run_id", "runtime_attempt_id", "turn_id", "approval_ref", "risk_revision",
		"audience", "policy_version", "issued_by", "decision_id", "plan_id",
		"step_id", "capability_id", "capability_version", "resource_ref",
	} {
		if !strings.Contains(asciiExpression, column) {
			return fmt.Errorf("%w: v17 ASCII evidence constraint lost %s", ErrSchemaDrift, column)
		}
	}
	if strings.Count(asciiExpression, "^[!-~]+$") != 14 ||
		strings.Count(asciiExpression, "512") != 14 ||
		!strings.Contains(asciiExpression, `COLLATE "C"`) {
		return fmt.Errorf("%w: v17 ASCII evidence constraint was weakened", ErrSchemaDrift)
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
::text))"},
		{"guard_permit_authority_action_request_v17_step_check", []string{"step_id", "IS NULL", "length", "!~", "[[:cntrl:][:space:]]"}},
		{"guard_permit_authority_action_request_v17_capability_check", []string{"capability_id", "IS NULL", "length", "!~", "[[:cntrl:][:space:]]"}},
		{"guard_permit_authority_action_request_v17_capability_version_check", []string{"capability_version", "IS NULL", "length", "!~", "[[:cntrl:][:space:]]"}},
		{"guard_permit_authority_action_request_v17_capability_contract_check", []string{"capability_contract_sha256", "IS NULL", "~", "^[0-9a-f]{64}$"}},
		{"guard_permit_authority_action_request_v17_resource_check", []string{"resource_ref", "IS NULL", "length", "!~", "[[:cntrl:][:space:]]"}},
	} {
		var expression string
		if err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
			FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass('guard_permit_authority_evidence')
			  AND c.conname=$1 AND c.contype='c' AND c.convalidated
			  AND NOT c.condeferrable AND NOT c.condeferred
		`, check.name).Scan(&expression); err != nil {
			return fmt.Errorf("%w: missing v17 ActionRequest check %s: %v", ErrSchemaDrift, check.name, err)
		}
		for _, token := range check.required {
			if !strings.Contains(expression, token) {
				return fmt.Errorf("%w: v17 ActionRequest check %s lost %q", ErrSchemaDrift, check.name, token)
			}
		}
	}

	// v17's NOT VALID ASCII constraint preserves immutable legacy v16 rows
	// without blessing them as ActionRequest v1 evidence. PostgreSQL still
	// enforces the constraint for every new/changed row, including issuer-role
	// writes which bypass Go's printable-ASCII validator.
	var asciiExpression string
	if err := tx.QueryRowContext(ctx, `
		SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
		FROM pg_catalog.pg_constraint c
		WHERE c.conrelid=pg_catalog.to_regclass('guard_permit_authority_evidence')
		  AND c.conname='guard_permit_authority_v17_ascii_identifiers_check'
		  AND c.contype='c' AND NOT c.condeferrable AND NOT c.condeferred
	`).Scan(&asciiExpression); err != nil {
		return fmt.Errorf("%w: missing v17 ASCII authority-evidence constraint: %v", ErrSchemaDrift, err)
	}
	for _, column := range []string{
		"run_id", "runtime_attempt_id", "turn_id", "approval_ref", "risk_revision",
		"audience", "policy_version", "issued_by", "decision_id", "plan_id",
		"step_id", "capability_id", "capability_version", "resource_ref",
	} {
		if !strings.Contains(asciiExpression, column) {
			return fmt.Errorf("%w: v17 ASCII evidence constraint lost %s", ErrSchemaDrift, column)
		}
	}
	if strings.Count(asciiExpression, "^[!-~]+$") != 14 ||
		strings.Count(asciiExpression, "512") != 14 ||
		!strings.Contains(asciiExpression, `COLLATE "C"`) {
		return fmt.Errorf("%w: v17 ASCII evidence constraint was weakened", ErrSchemaDrift)
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
