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
