package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func verifyProviderObservationCatalog(ctx context.Context, tx *sql.Tx) error {
	var relationSafe bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM pg_catalog.pg_class c
			JOIN pg_catalog.pg_class m
			  ON m.oid=pg_catalog.to_regclass(
			    pg_catalog.format('%I.%I', pg_catalog.current_schema(), 'guard_schema_migrations'))
			WHERE c.oid=pg_catalog.to_regclass('guard_provider_observations')
			  AND c.relkind='r' AND c.relpersistence='p'
			  AND c.relnamespace=pg_catalog.current_schema()::regnamespace
			  AND c.relowner=m.relowner
			  AND pg_catalog.to_regclass('guard_provider_observations') IS NOT DISTINCT FROM c.oid
		)
	`).Scan(&relationSafe); err != nil || !relationSafe {
		return fmt.Errorf("%w: v18 provider observation relation drift: %v", ErrSchemaDrift, err)
	}

	columns := []struct {
		name string
		typ  string
	}{
		{"observation_id", "uuid"},
		{"tenant_id", "text"},
		{"operation_id", "uuid"},
		{"permit_id", "uuid"},
		{"attempt_id", "uuid"},
		{"provider_id", "text"},
		{"idempotency_key", "text"},
		{"action_hash", "text"},
		{"outcome", "text"},
		{"evidence_digest", "text"},
		{"evidence_bytes", "bytea"},
		{"verifier_id", "text"},
		{"observed_at", "timestamptz"},
		{"recorded_at", "timestamptz"},
	}
	for _, column := range columns {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_attribute a
				WHERE a.attrelid=pg_catalog.to_regclass('guard_provider_observations')
				  AND a.attname=$1
				  AND a.atttypid=pg_catalog.to_regtype($2)
				  AND a.attnotnull AND NOT a.attisdropped
			)
		`, column.name, column.typ).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v18 provider observation column %s drift: %v", ErrSchemaDrift, column.name, err)
		}
	}

	for _, column := range []struct {
		name string
		typ  string
	}{
		{"receipt_id", "text"},
		{"effect", "text"},
	} {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_attribute a
				WHERE a.attrelid=pg_catalog.to_regclass('guard_provider_observations')
				  AND a.attname=$1
				  AND a.atttypid=pg_catalog.to_regtype($2)
				  AND NOT a.attnotnull AND NOT a.attisdropped
			)
		`, column.name, column.typ).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v18 nullable provider observation column %s drift: %v", ErrSchemaDrift, column.name, err)
		}
	}

	for _, column := range []struct {
		name, expression string
	}{
		{"observation_id", "gen_random_uuid()"},
		{"recorded_at", "clock_timestamp()"},
	} {
		var actual string
		err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_expr(d.adbin,d.adrelid)
			FROM pg_catalog.pg_attrdef d
			JOIN pg_catalog.pg_attribute a
			  ON a.attrelid=d.adrelid AND a.attnum=d.adnum
			WHERE d.adrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND a.attname=$1 AND NOT a.attisdropped
		`, column.name).Scan(&actual)
		if err != nil || actual != column.expression {
			return fmt.Errorf("%w: v18 provider observation default %s drift: got %q err=%v", ErrSchemaDrift, column.name, actual, err)
		}
	}

	for _, key := range []struct {
		name, kind, columns string
	}{
		{"guard_provider_observations_pkey", "p", "observation_id"},
		{"guard_provider_observation_attempt_digest_uq", "u", "tenant_id,attempt_id,evidence_digest"},
	} {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_constraint c
				JOIN pg_catalog.pg_index i ON i.indexrelid=c.conindid
				WHERE c.conrelid=pg_catalog.to_regclass('guard_provider_observations')
				  AND c.conname=$1 AND c.contype=$2::"char"
				  AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred
				  AND i.indrelid=c.conrelid AND i.indisvalid AND i.indisready
				  AND i.indislive AND i.indimmediate
				  AND i.indisunique AND i.indpred IS NULL AND i.indexprs IS NULL
				  AND (SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
				       FROM pg_catalog.unnest(c.conkey) WITH ORDINALITY k(attnum,ord)
				       JOIN pg_catalog.pg_attribute a
				         ON a.attrelid=c.conrelid AND a.attnum=k.attnum)=$3
			)
		`, key.name, key.kind, key.columns).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v18 provider observation key %s drift: %v", ErrSchemaDrift, key.name, err)
		}
	}

	var exactIntentFK bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND c.conname='guard_provider_observation_exact_intent_fk'
			  AND c.contype='f' AND c.convalidated
			  AND NOT c.condeferrable AND NOT c.condeferred
			  AND c.confrelid=pg_catalog.to_regclass('guard_operation_intents')
			  AND (SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			       FROM pg_catalog.unnest(c.conkey) WITH ORDINALITY k(attnum,ord)
			       JOIN pg_catalog.pg_attribute a
			         ON a.attrelid=c.conrelid AND a.attnum=k.attnum)
			      ='tenant_id,operation_id,permit_id,attempt_id,action_hash'
			  AND (SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			       FROM pg_catalog.unnest(c.confkey) WITH ORDINALITY k(attnum,ord)
			       JOIN pg_catalog.pg_attribute a
			         ON a.attrelid=c.confrelid AND a.attnum=k.attnum)
			      ='tenant_id,operation_id,permit_id,attempt_id,action_hash'
		)
	`).Scan(&exactIntentFK); err != nil || !exactIntentFK {
		return fmt.Errorf("%w: v18 provider observation exact Attempt FK drift: %v", ErrSchemaDrift, err)
	}

	checks := []struct {
		name       string
		expression string
	}{
		{"guard_provider_observations_provider_id_check", "((length(provider_id) >= 1) AND (length(provider_id) <= 256) AND ((provider_id COLLATE \"C\") ~ '^[!-~]+
		{"guard_provider_observations_idempotency_key_check", "((length(idempotency_key) >= 1) AND (length(idempotency_key) <= 256) AND ((idempotency_key COLLATE \"C\") ~ '^[!-~]+
		{"guard_provider_observations_action_hash_check", "(action_hash ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_outcome_check", "(outcome = ANY (ARRAY['FOUND'::text, 'ABSENT_UNCERTAIN'::text, 'FAILED_CONFIRMED'::text]))"},
		{"guard_provider_observations_evidence_digest_check", "(evidence_digest ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_evidence_bytes_check", "((octet_length(evidence_bytes) >= 1) AND (octet_length(evidence_bytes) <= 262144))"},
		{"guard_provider_observations_verifier_id_check", "((length(verifier_id) >= 1) AND (length(verifier_id) <= 512) AND ((verifier_id COLLATE \"C\") ~ '^[!-~]+
		{"guard_provider_observations_observed_at_check", "((observed_at > '-infinity'::timestamp with time zone) AND (observed_at < 'infinity'::timestamp with time zone))"},
		{"guard_provider_observation_receipt_id_check", "((receipt_id IS NULL) OR (((length(receipt_id) >= 1) AND (length(receipt_id) <= 256)) AND ((receipt_id COLLATE \"C\") ~ '^[!-~]+
		{"guard_provider_observation_outcome_shape_check", "(((outcome = 'FOUND'::text) AND (receipt_id IS NOT NULL) AND (effect = 'APPLIED'::text)) OR ((outcome = 'FAILED_CONFIRMED'::text) AND (receipt_id IS NOT NULL) AND (effect = 'NOT_APPLIED'::text)) OR ((outcome = 'ABSENT_UNCERTAIN'::text) AND (receipt_id IS NULL) AND (effect IS NULL)))"},
	}
	for _, check := range checks {
		var expression string
		err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
			FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND c.conname=$1 AND c.contype='c'
			  AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred
		`, check.name).Scan(&expression)
		if err != nil {
			return fmt.Errorf("%w: v18 provider observation check %s missing or invalid: %v", ErrSchemaDrift, check.name, err)
		}
		if check.expression != "" && expression != check.expression {
			return fmt.Errorf("%w: v18 provider observation check %s expression drift: got %q", ErrSchemaDrift, check.name, expression)
		}
	}

	var terminalIndex bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_index i
			JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid
			WHERE i.indrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND idx.oid=pg_catalog.to_regclass('guard_provider_observation_one_terminal_uq')
			  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
			  AND i.indimmediate AND i.indpred IS NOT NULL
			  AND i.indexprs IS NULL AND i.indnkeyatts=2 AND i.indnatts=2
			  AND (SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			       FROM pg_catalog.unnest(i.indkey) WITH ORDINALITY k(attnum,ord)
			       JOIN pg_catalog.pg_attribute a
			         ON a.attrelid=i.indrelid AND a.attnum=k.attnum)
			      ='tenant_id,attempt_id'
			  AND pg_catalog.pg_get_expr(i.indpred,i.indrelid)
			      = '(outcome = ANY (ARRAY[''FOUND''::text, ''FAILED_CONFIRMED''::text]))'
		)
	`).Scan(&terminalIndex); err != nil || !terminalIndex {
		return fmt.Errorf("%w: v18 one-terminal provider observation index drift: %v", ErrSchemaDrift, err)
	}

	const prefix = "CREATE FUNCTION guard_provider_observation_unknown_only_v18() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(providerObservationSchema, prefix) != 1 {
		return fmt.Errorf("%w: invalid v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	body := strings.SplitN(providerObservationSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	var actualBody string
	var functionSafe bool
	if err := tx.QueryRowContext(ctx, `
		SELECT p.prosrc,
		       NOT p.prosecdef AND NOT p.proleakproof
		       AND p.provolatile='v' AND NOT p.proisstrict
		       AND p.proparallel='u' AND p.proconfig IS NULL
		       AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
		       AND p.pronamespace=pg_catalog.current_schema()::regnamespace
		       AND p.prorettype='pg_catalog.trigger'::regtype AND p.pronargs=0
		FROM pg_catalog.pg_proc p
		WHERE p.oid=pg_catalog.to_regprocedure(
			pg_catalog.format('%I.%I()', pg_catalog.current_schema(), 'guard_provider_observation_unknown_only_v18'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_provider_observation_unknown_only_v18()')
	`).Scan(&actualBody, &functionSafe); err != nil || !functionSafe || actualBody != body[:end] {
		return fmt.Errorf("%w: v18 UNKNOWN-only trigger function drift: %v", ErrSchemaDrift, err)
	}

	for _, trigger := range []struct {
		name, function string
		kind           int
	}{
		{"guard_provider_observation_unknown_only_v18", "guard_provider_observation_unknown_only_v18()", 7},
		{"guard_provider_observation_immutable_row", "guard_reject_snapshot_mutation()", 27},
		{"guard_provider_observation_immutable_truncate", "guard_reject_snapshot_mutation()", 34},
	} {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger t
				WHERE t.tgrelid=pg_catalog.to_regclass('guard_provider_observations')
				  AND t.tgname=$1 AND t.tgtype=$2
				  AND t.tgenabled='A' AND NOT t.tgisinternal
				  AND t.tgqual IS NULL AND t.tgattr::text=''
				  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
				  AND NOT t.tgdeferrable AND NOT t.tginitdeferred
				  AND t.tgfoid=pg_catalog.to_regprocedure($3)
			)
		`, trigger.name, trigger.kind, trigger.function).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v18 provider observation trigger %s drift: %v", ErrSchemaDrift, trigger.name, err)
		}
	}

	var dataConsistent bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1
			FROM guard_provider_observations o
			LEFT JOIN guard_operation_intents i
			  ON i.tenant_id=o.tenant_id AND i.operation_id=o.operation_id
			 AND i.permit_id=o.permit_id AND i.attempt_id=o.attempt_id
			 AND i.action_hash=o.action_hash
			LEFT JOIN guard_permits p
			  ON p.tenant_id=i.tenant_id AND p.operation_id=i.operation_id
			 AND p.permit_id=i.permit_id AND p.action_hash=i.action_hash
			LEFT JOIN guard_operation_unknown_events u
			  ON u.tenant_id=i.tenant_id AND u.operation_id=i.operation_id
			 AND u.permit_id=i.permit_id AND u.attempt_id=i.attempt_id
			 AND u.action_hash=i.action_hash
			LEFT JOIN guard_execution_audit a
			  ON a.tenant_id=i.tenant_id AND a.operation_id=i.operation_id
			 AND a.permit_id=i.permit_id AND a.attempt_id=i.attempt_id
			 AND a.action_hash=i.action_hash
			 AND a.event_type='guard.operation.dispatching.v1'
			WHERE i.attempt_id IS NULL OR i.state <> 'UNKNOWN'
			   OR p.state <> 'CLAIMED' OR u.attempt_id IS NULL OR a.attempt_id IS NULL
		)
	`).Scan(&dataConsistent); err != nil || !dataConsistent {
		return fmt.Errorf("%w: v18 provider observation rows are not bound to durable UNKNOWN attempts: %v", ErrSchemaDrift, err)
	}
	return nil
}
::text))"},
		{"guard_provider_observations_idempotency_key_check", ""},
		{"guard_provider_observations_action_hash_check", "(action_hash ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_outcome_check", "(outcome = ANY (ARRAY['FOUND'::text, 'ABSENT_UNCERTAIN'::text, 'FAILED_CONFIRMED'::text]))"},
		{"guard_provider_observations_evidence_digest_check", "(evidence_digest ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_evidence_bytes_check", "((octet_length(evidence_bytes) >= 1) AND (octet_length(evidence_bytes) <= 262144))"},
		{"guard_provider_observations_verifier_id_check", ""},
		{"guard_provider_observations_observed_at_check", ""},
		{"guard_provider_observation_receipt_id_check", ""},
		{"guard_provider_observation_outcome_shape_check", "(((outcome = 'FOUND'::text) AND (receipt_id IS NOT NULL) AND (effect = 'APPLIED'::text)) OR ((outcome = 'FAILED_CONFIRMED'::text) AND (receipt_id IS NOT NULL) AND (effect = 'NOT_APPLIED'::text)) OR ((outcome = 'ABSENT_UNCERTAIN'::text) AND (receipt_id IS NULL) AND (effect IS NULL)))"},
	}
	for _, check := range checks {
		var expression string
		err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
			FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND c.conname=$1 AND c.contype='c'
			  AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred
		`, check.name).Scan(&expression)
		if err != nil {
			return fmt.Errorf("%w: v18 provider observation check %s missing or invalid: %v", ErrSchemaDrift, check.name, err)
		}
		if check.expression != "" && expression != check.expression {
			return fmt.Errorf("%w: v18 provider observation check %s expression drift: got %q", ErrSchemaDrift, check.name, expression)
		}
	}

	var terminalIndex bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_index i
			JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid
			WHERE i.indrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND idx.oid=pg_catalog.to_regclass('guard_provider_observation_one_terminal_uq')
			  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
			  AND i.indimmediate AND i.indpred IS NOT NULL
			  AND i.indexprs IS NULL AND i.indnkeyatts=2 AND i.indnatts=2
			  AND (SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			       FROM pg_catalog.unnest(i.indkey) WITH ORDINALITY k(attnum,ord)
			       JOIN pg_catalog.pg_attribute a
			         ON a.attrelid=i.indrelid AND a.attnum=k.attnum)
			      ='tenant_id,attempt_id'
			  AND pg_catalog.pg_get_expr(i.indpred,i.indrelid)
			      = '(outcome = ANY (ARRAY[''FOUND''::text, ''FAILED_CONFIRMED''::text]))'
		)
	`).Scan(&terminalIndex); err != nil || !terminalIndex {
		return fmt.Errorf("%w: v18 one-terminal provider observation index drift: %v", ErrSchemaDrift, err)
	}

	const prefix = "CREATE FUNCTION guard_provider_observation_unknown_only_v18() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(providerObservationSchema, prefix) != 1 {
		return fmt.Errorf("%w: invalid v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	body := strings.SplitN(providerObservationSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	var actualBody string
	var functionSafe bool
	if err := tx.QueryRowContext(ctx, `
		SELECT p.prosrc,
		       NOT p.prosecdef AND NOT p.proleakproof
		       AND p.provolatile='v' AND NOT p.proisstrict
		       AND p.proparallel='u' AND p.proconfig IS NULL
		       AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
		       AND p.pronamespace=pg_catalog.current_schema()::regnamespace
		       AND p.prorettype='pg_catalog.trigger'::regtype AND p.pronargs=0
		FROM pg_catalog.pg_proc p
		WHERE p.oid=pg_catalog.to_regprocedure(
			pg_catalog.format('%I.%I()', pg_catalog.current_schema(), 'guard_provider_observation_unknown_only_v18'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_provider_observation_unknown_only_v18()')
	`).Scan(&actualBody, &functionSafe); err != nil || !functionSafe || actualBody != body[:end] {
		return fmt.Errorf("%w: v18 UNKNOWN-only trigger function drift: %v", ErrSchemaDrift, err)
	}

	for _, trigger := range []struct {
		name, function string
		kind           int
	}{
		{"guard_provider_observation_unknown_only_v18", "guard_provider_observation_unknown_only_v18()", 7},
		{"guard_provider_observation_immutable_row", "guard_reject_snapshot_mutation()", 27},
		{"guard_provider_observation_immutable_truncate", "guard_reject_snapshot_mutation()", 34},
	} {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger t
				WHERE t.tgrelid=pg_catalog.to_regclass('guard_provider_observations')
				  AND t.tgname=$1 AND t.tgtype=$2
				  AND t.tgenabled='A' AND NOT t.tgisinternal
				  AND t.tgqual IS NULL AND t.tgattr::text=''
				  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
				  AND NOT t.tgdeferrable AND NOT t.tginitdeferred
				  AND t.tgfoid=pg_catalog.to_regprocedure($3)
			)
		`, trigger.name, trigger.kind, trigger.function).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v18 provider observation trigger %s drift: %v", ErrSchemaDrift, trigger.name, err)
		}
	}

	var dataConsistent bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1
			FROM guard_provider_observations o
			LEFT JOIN guard_operation_intents i
			  ON i.tenant_id=o.tenant_id AND i.operation_id=o.operation_id
			 AND i.permit_id=o.permit_id AND i.attempt_id=o.attempt_id
			 AND i.action_hash=o.action_hash
			LEFT JOIN guard_permits p
			  ON p.tenant_id=i.tenant_id AND p.operation_id=i.operation_id
			 AND p.permit_id=i.permit_id AND p.action_hash=i.action_hash
			LEFT JOIN guard_operation_unknown_events u
			  ON u.tenant_id=i.tenant_id AND u.operation_id=i.operation_id
			 AND u.permit_id=i.permit_id AND u.attempt_id=i.attempt_id
			 AND u.action_hash=i.action_hash
			LEFT JOIN guard_execution_audit a
			  ON a.tenant_id=i.tenant_id AND a.operation_id=i.operation_id
			 AND a.permit_id=i.permit_id AND a.attempt_id=i.attempt_id
			 AND a.action_hash=i.action_hash
			 AND a.event_type='guard.operation.dispatching.v1'
			WHERE i.attempt_id IS NULL OR i.state <> 'UNKNOWN'
			   OR p.state <> 'CLAIMED' OR u.attempt_id IS NULL OR a.attempt_id IS NULL
		)
	`).Scan(&dataConsistent); err != nil || !dataConsistent {
		return fmt.Errorf("%w: v18 provider observation rows are not bound to durable UNKNOWN attempts: %v", ErrSchemaDrift, err)
	}
	return nil
}
::text))"},
		{"guard_provider_observations_action_hash_check", "(action_hash ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_outcome_check", "(outcome = ANY (ARRAY['FOUND'::text, 'ABSENT_UNCERTAIN'::text, 'FAILED_CONFIRMED'::text]))"},
		{"guard_provider_observations_evidence_digest_check", "(evidence_digest ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_evidence_bytes_check", "((octet_length(evidence_bytes) >= 1) AND (octet_length(evidence_bytes) <= 262144))"},
		{"guard_provider_observations_verifier_id_check", ""},
		{"guard_provider_observations_observed_at_check", ""},
		{"guard_provider_observation_receipt_id_check", ""},
		{"guard_provider_observation_outcome_shape_check", "(((outcome = 'FOUND'::text) AND (receipt_id IS NOT NULL) AND (effect = 'APPLIED'::text)) OR ((outcome = 'FAILED_CONFIRMED'::text) AND (receipt_id IS NOT NULL) AND (effect = 'NOT_APPLIED'::text)) OR ((outcome = 'ABSENT_UNCERTAIN'::text) AND (receipt_id IS NULL) AND (effect IS NULL)))"},
	}
	for _, check := range checks {
		var expression string
		err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
			FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND c.conname=$1 AND c.contype='c'
			  AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred
		`, check.name).Scan(&expression)
		if err != nil {
			return fmt.Errorf("%w: v18 provider observation check %s missing or invalid: %v", ErrSchemaDrift, check.name, err)
		}
		if check.expression != "" && expression != check.expression {
			return fmt.Errorf("%w: v18 provider observation check %s expression drift: got %q", ErrSchemaDrift, check.name, expression)
		}
	}

	var terminalIndex bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_index i
			JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid
			WHERE i.indrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND idx.oid=pg_catalog.to_regclass('guard_provider_observation_one_terminal_uq')
			  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
			  AND i.indimmediate AND i.indpred IS NOT NULL
			  AND i.indexprs IS NULL AND i.indnkeyatts=2 AND i.indnatts=2
			  AND (SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			       FROM pg_catalog.unnest(i.indkey) WITH ORDINALITY k(attnum,ord)
			       JOIN pg_catalog.pg_attribute a
			         ON a.attrelid=i.indrelid AND a.attnum=k.attnum)
			      ='tenant_id,attempt_id'
			  AND pg_catalog.pg_get_expr(i.indpred,i.indrelid)
			      = '(outcome = ANY (ARRAY[''FOUND''::text, ''FAILED_CONFIRMED''::text]))'
		)
	`).Scan(&terminalIndex); err != nil || !terminalIndex {
		return fmt.Errorf("%w: v18 one-terminal provider observation index drift: %v", ErrSchemaDrift, err)
	}

	const prefix = "CREATE FUNCTION guard_provider_observation_unknown_only_v18() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(providerObservationSchema, prefix) != 1 {
		return fmt.Errorf("%w: invalid v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	body := strings.SplitN(providerObservationSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	var actualBody string
	var functionSafe bool
	if err := tx.QueryRowContext(ctx, `
		SELECT p.prosrc,
		       NOT p.prosecdef AND NOT p.proleakproof
		       AND p.provolatile='v' AND NOT p.proisstrict
		       AND p.proparallel='u' AND p.proconfig IS NULL
		       AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
		       AND p.pronamespace=pg_catalog.current_schema()::regnamespace
		       AND p.prorettype='pg_catalog.trigger'::regtype AND p.pronargs=0
		FROM pg_catalog.pg_proc p
		WHERE p.oid=pg_catalog.to_regprocedure(
			pg_catalog.format('%I.%I()', pg_catalog.current_schema(), 'guard_provider_observation_unknown_only_v18'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_provider_observation_unknown_only_v18()')
	`).Scan(&actualBody, &functionSafe); err != nil || !functionSafe || actualBody != body[:end] {
		return fmt.Errorf("%w: v18 UNKNOWN-only trigger function drift: %v", ErrSchemaDrift, err)
	}

	for _, trigger := range []struct {
		name, function string
		kind           int
	}{
		{"guard_provider_observation_unknown_only_v18", "guard_provider_observation_unknown_only_v18()", 7},
		{"guard_provider_observation_immutable_row", "guard_reject_snapshot_mutation()", 27},
		{"guard_provider_observation_immutable_truncate", "guard_reject_snapshot_mutation()", 34},
	} {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger t
				WHERE t.tgrelid=pg_catalog.to_regclass('guard_provider_observations')
				  AND t.tgname=$1 AND t.tgtype=$2
				  AND t.tgenabled='A' AND NOT t.tgisinternal
				  AND t.tgqual IS NULL AND t.tgattr::text=''
				  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
				  AND NOT t.tgdeferrable AND NOT t.tginitdeferred
				  AND t.tgfoid=pg_catalog.to_regprocedure($3)
			)
		`, trigger.name, trigger.kind, trigger.function).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v18 provider observation trigger %s drift: %v", ErrSchemaDrift, trigger.name, err)
		}
	}

	var dataConsistent bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1
			FROM guard_provider_observations o
			LEFT JOIN guard_operation_intents i
			  ON i.tenant_id=o.tenant_id AND i.operation_id=o.operation_id
			 AND i.permit_id=o.permit_id AND i.attempt_id=o.attempt_id
			 AND i.action_hash=o.action_hash
			LEFT JOIN guard_permits p
			  ON p.tenant_id=i.tenant_id AND p.operation_id=i.operation_id
			 AND p.permit_id=i.permit_id AND p.action_hash=i.action_hash
			LEFT JOIN guard_operation_unknown_events u
			  ON u.tenant_id=i.tenant_id AND u.operation_id=i.operation_id
			 AND u.permit_id=i.permit_id AND u.attempt_id=i.attempt_id
			 AND u.action_hash=i.action_hash
			LEFT JOIN guard_execution_audit a
			  ON a.tenant_id=i.tenant_id AND a.operation_id=i.operation_id
			 AND a.permit_id=i.permit_id AND a.attempt_id=i.attempt_id
			 AND a.action_hash=i.action_hash
			 AND a.event_type='guard.operation.dispatching.v1'
			WHERE i.attempt_id IS NULL OR i.state <> 'UNKNOWN'
			   OR p.state <> 'CLAIMED' OR u.attempt_id IS NULL OR a.attempt_id IS NULL
		)
	`).Scan(&dataConsistent); err != nil || !dataConsistent {
		return fmt.Errorf("%w: v18 provider observation rows are not bound to durable UNKNOWN attempts: %v", ErrSchemaDrift, err)
	}
	return nil
}
::text))"},
		{"guard_provider_observations_idempotency_key_check", ""},
		{"guard_provider_observations_action_hash_check", "(action_hash ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_outcome_check", "(outcome = ANY (ARRAY['FOUND'::text, 'ABSENT_UNCERTAIN'::text, 'FAILED_CONFIRMED'::text]))"},
		{"guard_provider_observations_evidence_digest_check", "(evidence_digest ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_evidence_bytes_check", "((octet_length(evidence_bytes) >= 1) AND (octet_length(evidence_bytes) <= 262144))"},
		{"guard_provider_observations_verifier_id_check", ""},
		{"guard_provider_observations_observed_at_check", ""},
		{"guard_provider_observation_receipt_id_check", ""},
		{"guard_provider_observation_outcome_shape_check", "(((outcome = 'FOUND'::text) AND (receipt_id IS NOT NULL) AND (effect = 'APPLIED'::text)) OR ((outcome = 'FAILED_CONFIRMED'::text) AND (receipt_id IS NOT NULL) AND (effect = 'NOT_APPLIED'::text)) OR ((outcome = 'ABSENT_UNCERTAIN'::text) AND (receipt_id IS NULL) AND (effect IS NULL)))"},
	}
	for _, check := range checks {
		var expression string
		err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
			FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND c.conname=$1 AND c.contype='c'
			  AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred
		`, check.name).Scan(&expression)
		if err != nil {
			return fmt.Errorf("%w: v18 provider observation check %s missing or invalid: %v", ErrSchemaDrift, check.name, err)
		}
		if check.expression != "" && expression != check.expression {
			return fmt.Errorf("%w: v18 provider observation check %s expression drift: got %q", ErrSchemaDrift, check.name, expression)
		}
	}

	var terminalIndex bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_index i
			JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid
			WHERE i.indrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND idx.oid=pg_catalog.to_regclass('guard_provider_observation_one_terminal_uq')
			  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
			  AND i.indimmediate AND i.indpred IS NOT NULL
			  AND i.indexprs IS NULL AND i.indnkeyatts=2 AND i.indnatts=2
			  AND (SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			       FROM pg_catalog.unnest(i.indkey) WITH ORDINALITY k(attnum,ord)
			       JOIN pg_catalog.pg_attribute a
			         ON a.attrelid=i.indrelid AND a.attnum=k.attnum)
			      ='tenant_id,attempt_id'
			  AND pg_catalog.pg_get_expr(i.indpred,i.indrelid)
			      = '(outcome = ANY (ARRAY[''FOUND''::text, ''FAILED_CONFIRMED''::text]))'
		)
	`).Scan(&terminalIndex); err != nil || !terminalIndex {
		return fmt.Errorf("%w: v18 one-terminal provider observation index drift: %v", ErrSchemaDrift, err)
	}

	const prefix = "CREATE FUNCTION guard_provider_observation_unknown_only_v18() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(providerObservationSchema, prefix) != 1 {
		return fmt.Errorf("%w: invalid v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	body := strings.SplitN(providerObservationSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	var actualBody string
	var functionSafe bool
	if err := tx.QueryRowContext(ctx, `
		SELECT p.prosrc,
		       NOT p.prosecdef AND NOT p.proleakproof
		       AND p.provolatile='v' AND NOT p.proisstrict
		       AND p.proparallel='u' AND p.proconfig IS NULL
		       AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
		       AND p.pronamespace=pg_catalog.current_schema()::regnamespace
		       AND p.prorettype='pg_catalog.trigger'::regtype AND p.pronargs=0
		FROM pg_catalog.pg_proc p
		WHERE p.oid=pg_catalog.to_regprocedure(
			pg_catalog.format('%I.%I()', pg_catalog.current_schema(), 'guard_provider_observation_unknown_only_v18'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_provider_observation_unknown_only_v18()')
	`).Scan(&actualBody, &functionSafe); err != nil || !functionSafe || actualBody != body[:end] {
		return fmt.Errorf("%w: v18 UNKNOWN-only trigger function drift: %v", ErrSchemaDrift, err)
	}

	for _, trigger := range []struct {
		name, function string
		kind           int
	}{
		{"guard_provider_observation_unknown_only_v18", "guard_provider_observation_unknown_only_v18()", 7},
		{"guard_provider_observation_immutable_row", "guard_reject_snapshot_mutation()", 27},
		{"guard_provider_observation_immutable_truncate", "guard_reject_snapshot_mutation()", 34},
	} {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger t
				WHERE t.tgrelid=pg_catalog.to_regclass('guard_provider_observations')
				  AND t.tgname=$1 AND t.tgtype=$2
				  AND t.tgenabled='A' AND NOT t.tgisinternal
				  AND t.tgqual IS NULL AND t.tgattr::text=''
				  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
				  AND NOT t.tgdeferrable AND NOT t.tginitdeferred
				  AND t.tgfoid=pg_catalog.to_regprocedure($3)
			)
		`, trigger.name, trigger.kind, trigger.function).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v18 provider observation trigger %s drift: %v", ErrSchemaDrift, trigger.name, err)
		}
	}

	var dataConsistent bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1
			FROM guard_provider_observations o
			LEFT JOIN guard_operation_intents i
			  ON i.tenant_id=o.tenant_id AND i.operation_id=o.operation_id
			 AND i.permit_id=o.permit_id AND i.attempt_id=o.attempt_id
			 AND i.action_hash=o.action_hash
			LEFT JOIN guard_permits p
			  ON p.tenant_id=i.tenant_id AND p.operation_id=i.operation_id
			 AND p.permit_id=i.permit_id AND p.action_hash=i.action_hash
			LEFT JOIN guard_operation_unknown_events u
			  ON u.tenant_id=i.tenant_id AND u.operation_id=i.operation_id
			 AND u.permit_id=i.permit_id AND u.attempt_id=i.attempt_id
			 AND u.action_hash=i.action_hash
			LEFT JOIN guard_execution_audit a
			  ON a.tenant_id=i.tenant_id AND a.operation_id=i.operation_id
			 AND a.permit_id=i.permit_id AND a.attempt_id=i.attempt_id
			 AND a.action_hash=i.action_hash
			 AND a.event_type='guard.operation.dispatching.v1'
			WHERE i.attempt_id IS NULL OR i.state <> 'UNKNOWN'
			   OR p.state <> 'CLAIMED' OR u.attempt_id IS NULL OR a.attempt_id IS NULL
		)
	`).Scan(&dataConsistent); err != nil || !dataConsistent {
		return fmt.Errorf("%w: v18 provider observation rows are not bound to durable UNKNOWN attempts: %v", ErrSchemaDrift, err)
	}
	return nil
}
::text))"},
		{"guard_provider_observations_observed_at_check", ""},
		{"guard_provider_observation_receipt_id_check", ""},
		{"guard_provider_observation_outcome_shape_check", "(((outcome = 'FOUND'::text) AND (receipt_id IS NOT NULL) AND (effect = 'APPLIED'::text)) OR ((outcome = 'FAILED_CONFIRMED'::text) AND (receipt_id IS NOT NULL) AND (effect = 'NOT_APPLIED'::text)) OR ((outcome = 'ABSENT_UNCERTAIN'::text) AND (receipt_id IS NULL) AND (effect IS NULL)))"},
	}
	for _, check := range checks {
		var expression string
		err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
			FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND c.conname=$1 AND c.contype='c'
			  AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred
		`, check.name).Scan(&expression)
		if err != nil {
			return fmt.Errorf("%w: v18 provider observation check %s missing or invalid: %v", ErrSchemaDrift, check.name, err)
		}
		if check.expression != "" && expression != check.expression {
			return fmt.Errorf("%w: v18 provider observation check %s expression drift: got %q", ErrSchemaDrift, check.name, expression)
		}
	}

	var terminalIndex bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_index i
			JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid
			WHERE i.indrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND idx.oid=pg_catalog.to_regclass('guard_provider_observation_one_terminal_uq')
			  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
			  AND i.indimmediate AND i.indpred IS NOT NULL
			  AND i.indexprs IS NULL AND i.indnkeyatts=2 AND i.indnatts=2
			  AND (SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			       FROM pg_catalog.unnest(i.indkey) WITH ORDINALITY k(attnum,ord)
			       JOIN pg_catalog.pg_attribute a
			         ON a.attrelid=i.indrelid AND a.attnum=k.attnum)
			      ='tenant_id,attempt_id'
			  AND pg_catalog.pg_get_expr(i.indpred,i.indrelid)
			      = '(outcome = ANY (ARRAY[''FOUND''::text, ''FAILED_CONFIRMED''::text]))'
		)
	`).Scan(&terminalIndex); err != nil || !terminalIndex {
		return fmt.Errorf("%w: v18 one-terminal provider observation index drift: %v", ErrSchemaDrift, err)
	}

	const prefix = "CREATE FUNCTION guard_provider_observation_unknown_only_v18() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(providerObservationSchema, prefix) != 1 {
		return fmt.Errorf("%w: invalid v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	body := strings.SplitN(providerObservationSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	var actualBody string
	var functionSafe bool
	if err := tx.QueryRowContext(ctx, `
		SELECT p.prosrc,
		       NOT p.prosecdef AND NOT p.proleakproof
		       AND p.provolatile='v' AND NOT p.proisstrict
		       AND p.proparallel='u' AND p.proconfig IS NULL
		       AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
		       AND p.pronamespace=pg_catalog.current_schema()::regnamespace
		       AND p.prorettype='pg_catalog.trigger'::regtype AND p.pronargs=0
		FROM pg_catalog.pg_proc p
		WHERE p.oid=pg_catalog.to_regprocedure(
			pg_catalog.format('%I.%I()', pg_catalog.current_schema(), 'guard_provider_observation_unknown_only_v18'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_provider_observation_unknown_only_v18()')
	`).Scan(&actualBody, &functionSafe); err != nil || !functionSafe || actualBody != body[:end] {
		return fmt.Errorf("%w: v18 UNKNOWN-only trigger function drift: %v", ErrSchemaDrift, err)
	}

	for _, trigger := range []struct {
		name, function string
		kind           int
	}{
		{"guard_provider_observation_unknown_only_v18", "guard_provider_observation_unknown_only_v18()", 7},
		{"guard_provider_observation_immutable_row", "guard_reject_snapshot_mutation()", 27},
		{"guard_provider_observation_immutable_truncate", "guard_reject_snapshot_mutation()", 34},
	} {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger t
				WHERE t.tgrelid=pg_catalog.to_regclass('guard_provider_observations')
				  AND t.tgname=$1 AND t.tgtype=$2
				  AND t.tgenabled='A' AND NOT t.tgisinternal
				  AND t.tgqual IS NULL AND t.tgattr::text=''
				  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
				  AND NOT t.tgdeferrable AND NOT t.tginitdeferred
				  AND t.tgfoid=pg_catalog.to_regprocedure($3)
			)
		`, trigger.name, trigger.kind, trigger.function).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v18 provider observation trigger %s drift: %v", ErrSchemaDrift, trigger.name, err)
		}
	}

	var dataConsistent bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1
			FROM guard_provider_observations o
			LEFT JOIN guard_operation_intents i
			  ON i.tenant_id=o.tenant_id AND i.operation_id=o.operation_id
			 AND i.permit_id=o.permit_id AND i.attempt_id=o.attempt_id
			 AND i.action_hash=o.action_hash
			LEFT JOIN guard_permits p
			  ON p.tenant_id=i.tenant_id AND p.operation_id=i.operation_id
			 AND p.permit_id=i.permit_id AND p.action_hash=i.action_hash
			LEFT JOIN guard_operation_unknown_events u
			  ON u.tenant_id=i.tenant_id AND u.operation_id=i.operation_id
			 AND u.permit_id=i.permit_id AND u.attempt_id=i.attempt_id
			 AND u.action_hash=i.action_hash
			LEFT JOIN guard_execution_audit a
			  ON a.tenant_id=i.tenant_id AND a.operation_id=i.operation_id
			 AND a.permit_id=i.permit_id AND a.attempt_id=i.attempt_id
			 AND a.action_hash=i.action_hash
			 AND a.event_type='guard.operation.dispatching.v1'
			WHERE i.attempt_id IS NULL OR i.state <> 'UNKNOWN'
			   OR p.state <> 'CLAIMED' OR u.attempt_id IS NULL OR a.attempt_id IS NULL
		)
	`).Scan(&dataConsistent); err != nil || !dataConsistent {
		return fmt.Errorf("%w: v18 provider observation rows are not bound to durable UNKNOWN attempts: %v", ErrSchemaDrift, err)
	}
	return nil
}
::text))"},
		{"guard_provider_observations_idempotency_key_check", ""},
		{"guard_provider_observations_action_hash_check", "(action_hash ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_outcome_check", "(outcome = ANY (ARRAY['FOUND'::text, 'ABSENT_UNCERTAIN'::text, 'FAILED_CONFIRMED'::text]))"},
		{"guard_provider_observations_evidence_digest_check", "(evidence_digest ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_evidence_bytes_check", "((octet_length(evidence_bytes) >= 1) AND (octet_length(evidence_bytes) <= 262144))"},
		{"guard_provider_observations_verifier_id_check", ""},
		{"guard_provider_observations_observed_at_check", ""},
		{"guard_provider_observation_receipt_id_check", ""},
		{"guard_provider_observation_outcome_shape_check", "(((outcome = 'FOUND'::text) AND (receipt_id IS NOT NULL) AND (effect = 'APPLIED'::text)) OR ((outcome = 'FAILED_CONFIRMED'::text) AND (receipt_id IS NOT NULL) AND (effect = 'NOT_APPLIED'::text)) OR ((outcome = 'ABSENT_UNCERTAIN'::text) AND (receipt_id IS NULL) AND (effect IS NULL)))"},
	}
	for _, check := range checks {
		var expression string
		err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
			FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND c.conname=$1 AND c.contype='c'
			  AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred
		`, check.name).Scan(&expression)
		if err != nil {
			return fmt.Errorf("%w: v18 provider observation check %s missing or invalid: %v", ErrSchemaDrift, check.name, err)
		}
		if check.expression != "" && expression != check.expression {
			return fmt.Errorf("%w: v18 provider observation check %s expression drift: got %q", ErrSchemaDrift, check.name, expression)
		}
	}

	var terminalIndex bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_index i
			JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid
			WHERE i.indrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND idx.oid=pg_catalog.to_regclass('guard_provider_observation_one_terminal_uq')
			  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
			  AND i.indimmediate AND i.indpred IS NOT NULL
			  AND i.indexprs IS NULL AND i.indnkeyatts=2 AND i.indnatts=2
			  AND (SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			       FROM pg_catalog.unnest(i.indkey) WITH ORDINALITY k(attnum,ord)
			       JOIN pg_catalog.pg_attribute a
			         ON a.attrelid=i.indrelid AND a.attnum=k.attnum)
			      ='tenant_id,attempt_id'
			  AND pg_catalog.pg_get_expr(i.indpred,i.indrelid)
			      = '(outcome = ANY (ARRAY[''FOUND''::text, ''FAILED_CONFIRMED''::text]))'
		)
	`).Scan(&terminalIndex); err != nil || !terminalIndex {
		return fmt.Errorf("%w: v18 one-terminal provider observation index drift: %v", ErrSchemaDrift, err)
	}

	const prefix = "CREATE FUNCTION guard_provider_observation_unknown_only_v18() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(providerObservationSchema, prefix) != 1 {
		return fmt.Errorf("%w: invalid v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	body := strings.SplitN(providerObservationSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	var actualBody string
	var functionSafe bool
	if err := tx.QueryRowContext(ctx, `
		SELECT p.prosrc,
		       NOT p.prosecdef AND NOT p.proleakproof
		       AND p.provolatile='v' AND NOT p.proisstrict
		       AND p.proparallel='u' AND p.proconfig IS NULL
		       AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
		       AND p.pronamespace=pg_catalog.current_schema()::regnamespace
		       AND p.prorettype='pg_catalog.trigger'::regtype AND p.pronargs=0
		FROM pg_catalog.pg_proc p
		WHERE p.oid=pg_catalog.to_regprocedure(
			pg_catalog.format('%I.%I()', pg_catalog.current_schema(), 'guard_provider_observation_unknown_only_v18'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_provider_observation_unknown_only_v18()')
	`).Scan(&actualBody, &functionSafe); err != nil || !functionSafe || actualBody != body[:end] {
		return fmt.Errorf("%w: v18 UNKNOWN-only trigger function drift: %v", ErrSchemaDrift, err)
	}

	for _, trigger := range []struct {
		name, function string
		kind           int
	}{
		{"guard_provider_observation_unknown_only_v18", "guard_provider_observation_unknown_only_v18()", 7},
		{"guard_provider_observation_immutable_row", "guard_reject_snapshot_mutation()", 27},
		{"guard_provider_observation_immutable_truncate", "guard_reject_snapshot_mutation()", 34},
	} {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger t
				WHERE t.tgrelid=pg_catalog.to_regclass('guard_provider_observations')
				  AND t.tgname=$1 AND t.tgtype=$2
				  AND t.tgenabled='A' AND NOT t.tgisinternal
				  AND t.tgqual IS NULL AND t.tgattr::text=''
				  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
				  AND NOT t.tgdeferrable AND NOT t.tginitdeferred
				  AND t.tgfoid=pg_catalog.to_regprocedure($3)
			)
		`, trigger.name, trigger.kind, trigger.function).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v18 provider observation trigger %s drift: %v", ErrSchemaDrift, trigger.name, err)
		}
	}

	var dataConsistent bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1
			FROM guard_provider_observations o
			LEFT JOIN guard_operation_intents i
			  ON i.tenant_id=o.tenant_id AND i.operation_id=o.operation_id
			 AND i.permit_id=o.permit_id AND i.attempt_id=o.attempt_id
			 AND i.action_hash=o.action_hash
			LEFT JOIN guard_permits p
			  ON p.tenant_id=i.tenant_id AND p.operation_id=i.operation_id
			 AND p.permit_id=i.permit_id AND p.action_hash=i.action_hash
			LEFT JOIN guard_operation_unknown_events u
			  ON u.tenant_id=i.tenant_id AND u.operation_id=i.operation_id
			 AND u.permit_id=i.permit_id AND u.attempt_id=i.attempt_id
			 AND u.action_hash=i.action_hash
			LEFT JOIN guard_execution_audit a
			  ON a.tenant_id=i.tenant_id AND a.operation_id=i.operation_id
			 AND a.permit_id=i.permit_id AND a.attempt_id=i.attempt_id
			 AND a.action_hash=i.action_hash
			 AND a.event_type='guard.operation.dispatching.v1'
			WHERE i.attempt_id IS NULL OR i.state <> 'UNKNOWN'
			   OR p.state <> 'CLAIMED' OR u.attempt_id IS NULL OR a.attempt_id IS NULL
		)
	`).Scan(&dataConsistent); err != nil || !dataConsistent {
		return fmt.Errorf("%w: v18 provider observation rows are not bound to durable UNKNOWN attempts: %v", ErrSchemaDrift, err)
	}
	return nil
}
::text))"},
		{"guard_provider_observations_action_hash_check", "(action_hash ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_outcome_check", "(outcome = ANY (ARRAY['FOUND'::text, 'ABSENT_UNCERTAIN'::text, 'FAILED_CONFIRMED'::text]))"},
		{"guard_provider_observations_evidence_digest_check", "(evidence_digest ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_evidence_bytes_check", "((octet_length(evidence_bytes) >= 1) AND (octet_length(evidence_bytes) <= 262144))"},
		{"guard_provider_observations_verifier_id_check", ""},
		{"guard_provider_observations_observed_at_check", ""},
		{"guard_provider_observation_receipt_id_check", ""},
		{"guard_provider_observation_outcome_shape_check", "(((outcome = 'FOUND'::text) AND (receipt_id IS NOT NULL) AND (effect = 'APPLIED'::text)) OR ((outcome = 'FAILED_CONFIRMED'::text) AND (receipt_id IS NOT NULL) AND (effect = 'NOT_APPLIED'::text)) OR ((outcome = 'ABSENT_UNCERTAIN'::text) AND (receipt_id IS NULL) AND (effect IS NULL)))"},
	}
	for _, check := range checks {
		var expression string
		err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
			FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND c.conname=$1 AND c.contype='c'
			  AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred
		`, check.name).Scan(&expression)
		if err != nil {
			return fmt.Errorf("%w: v18 provider observation check %s missing or invalid: %v", ErrSchemaDrift, check.name, err)
		}
		if check.expression != "" && expression != check.expression {
			return fmt.Errorf("%w: v18 provider observation check %s expression drift: got %q", ErrSchemaDrift, check.name, expression)
		}
	}

	var terminalIndex bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_index i
			JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid
			WHERE i.indrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND idx.oid=pg_catalog.to_regclass('guard_provider_observation_one_terminal_uq')
			  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
			  AND i.indimmediate AND i.indpred IS NOT NULL
			  AND i.indexprs IS NULL AND i.indnkeyatts=2 AND i.indnatts=2
			  AND (SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			       FROM pg_catalog.unnest(i.indkey) WITH ORDINALITY k(attnum,ord)
			       JOIN pg_catalog.pg_attribute a
			         ON a.attrelid=i.indrelid AND a.attnum=k.attnum)
			      ='tenant_id,attempt_id'
			  AND pg_catalog.pg_get_expr(i.indpred,i.indrelid)
			      = '(outcome = ANY (ARRAY[''FOUND''::text, ''FAILED_CONFIRMED''::text]))'
		)
	`).Scan(&terminalIndex); err != nil || !terminalIndex {
		return fmt.Errorf("%w: v18 one-terminal provider observation index drift: %v", ErrSchemaDrift, err)
	}

	const prefix = "CREATE FUNCTION guard_provider_observation_unknown_only_v18() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(providerObservationSchema, prefix) != 1 {
		return fmt.Errorf("%w: invalid v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	body := strings.SplitN(providerObservationSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	var actualBody string
	var functionSafe bool
	if err := tx.QueryRowContext(ctx, `
		SELECT p.prosrc,
		       NOT p.prosecdef AND NOT p.proleakproof
		       AND p.provolatile='v' AND NOT p.proisstrict
		       AND p.proparallel='u' AND p.proconfig IS NULL
		       AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
		       AND p.pronamespace=pg_catalog.current_schema()::regnamespace
		       AND p.prorettype='pg_catalog.trigger'::regtype AND p.pronargs=0
		FROM pg_catalog.pg_proc p
		WHERE p.oid=pg_catalog.to_regprocedure(
			pg_catalog.format('%I.%I()', pg_catalog.current_schema(), 'guard_provider_observation_unknown_only_v18'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_provider_observation_unknown_only_v18()')
	`).Scan(&actualBody, &functionSafe); err != nil || !functionSafe || actualBody != body[:end] {
		return fmt.Errorf("%w: v18 UNKNOWN-only trigger function drift: %v", ErrSchemaDrift, err)
	}

	for _, trigger := range []struct {
		name, function string
		kind           int
	}{
		{"guard_provider_observation_unknown_only_v18", "guard_provider_observation_unknown_only_v18()", 7},
		{"guard_provider_observation_immutable_row", "guard_reject_snapshot_mutation()", 27},
		{"guard_provider_observation_immutable_truncate", "guard_reject_snapshot_mutation()", 34},
	} {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger t
				WHERE t.tgrelid=pg_catalog.to_regclass('guard_provider_observations')
				  AND t.tgname=$1 AND t.tgtype=$2
				  AND t.tgenabled='A' AND NOT t.tgisinternal
				  AND t.tgqual IS NULL AND t.tgattr::text=''
				  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
				  AND NOT t.tgdeferrable AND NOT t.tginitdeferred
				  AND t.tgfoid=pg_catalog.to_regprocedure($3)
			)
		`, trigger.name, trigger.kind, trigger.function).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v18 provider observation trigger %s drift: %v", ErrSchemaDrift, trigger.name, err)
		}
	}

	var dataConsistent bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1
			FROM guard_provider_observations o
			LEFT JOIN guard_operation_intents i
			  ON i.tenant_id=o.tenant_id AND i.operation_id=o.operation_id
			 AND i.permit_id=o.permit_id AND i.attempt_id=o.attempt_id
			 AND i.action_hash=o.action_hash
			LEFT JOIN guard_permits p
			  ON p.tenant_id=i.tenant_id AND p.operation_id=i.operation_id
			 AND p.permit_id=i.permit_id AND p.action_hash=i.action_hash
			LEFT JOIN guard_operation_unknown_events u
			  ON u.tenant_id=i.tenant_id AND u.operation_id=i.operation_id
			 AND u.permit_id=i.permit_id AND u.attempt_id=i.attempt_id
			 AND u.action_hash=i.action_hash
			LEFT JOIN guard_execution_audit a
			  ON a.tenant_id=i.tenant_id AND a.operation_id=i.operation_id
			 AND a.permit_id=i.permit_id AND a.attempt_id=i.attempt_id
			 AND a.action_hash=i.action_hash
			 AND a.event_type='guard.operation.dispatching.v1'
			WHERE i.attempt_id IS NULL OR i.state <> 'UNKNOWN'
			   OR p.state <> 'CLAIMED' OR u.attempt_id IS NULL OR a.attempt_id IS NULL
		)
	`).Scan(&dataConsistent); err != nil || !dataConsistent {
		return fmt.Errorf("%w: v18 provider observation rows are not bound to durable UNKNOWN attempts: %v", ErrSchemaDrift, err)
	}
	return nil
}
::text))"},
		{"guard_provider_observations_idempotency_key_check", ""},
		{"guard_provider_observations_action_hash_check", "(action_hash ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_outcome_check", "(outcome = ANY (ARRAY['FOUND'::text, 'ABSENT_UNCERTAIN'::text, 'FAILED_CONFIRMED'::text]))"},
		{"guard_provider_observations_evidence_digest_check", "(evidence_digest ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_evidence_bytes_check", "((octet_length(evidence_bytes) >= 1) AND (octet_length(evidence_bytes) <= 262144))"},
		{"guard_provider_observations_verifier_id_check", ""},
		{"guard_provider_observations_observed_at_check", ""},
		{"guard_provider_observation_receipt_id_check", ""},
		{"guard_provider_observation_outcome_shape_check", "(((outcome = 'FOUND'::text) AND (receipt_id IS NOT NULL) AND (effect = 'APPLIED'::text)) OR ((outcome = 'FAILED_CONFIRMED'::text) AND (receipt_id IS NOT NULL) AND (effect = 'NOT_APPLIED'::text)) OR ((outcome = 'ABSENT_UNCERTAIN'::text) AND (receipt_id IS NULL) AND (effect IS NULL)))"},
	}
	for _, check := range checks {
		var expression string
		err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
			FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND c.conname=$1 AND c.contype='c'
			  AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred
		`, check.name).Scan(&expression)
		if err != nil {
			return fmt.Errorf("%w: v18 provider observation check %s missing or invalid: %v", ErrSchemaDrift, check.name, err)
		}
		if check.expression != "" && expression != check.expression {
			return fmt.Errorf("%w: v18 provider observation check %s expression drift: got %q", ErrSchemaDrift, check.name, expression)
		}
	}

	var terminalIndex bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_index i
			JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid
			WHERE i.indrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND idx.oid=pg_catalog.to_regclass('guard_provider_observation_one_terminal_uq')
			  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
			  AND i.indimmediate AND i.indpred IS NOT NULL
			  AND i.indexprs IS NULL AND i.indnkeyatts=2 AND i.indnatts=2
			  AND (SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			       FROM pg_catalog.unnest(i.indkey) WITH ORDINALITY k(attnum,ord)
			       JOIN pg_catalog.pg_attribute a
			         ON a.attrelid=i.indrelid AND a.attnum=k.attnum)
			      ='tenant_id,attempt_id'
			  AND pg_catalog.pg_get_expr(i.indpred,i.indrelid)
			      = '(outcome = ANY (ARRAY[''FOUND''::text, ''FAILED_CONFIRMED''::text]))'
		)
	`).Scan(&terminalIndex); err != nil || !terminalIndex {
		return fmt.Errorf("%w: v18 one-terminal provider observation index drift: %v", ErrSchemaDrift, err)
	}

	const prefix = "CREATE FUNCTION guard_provider_observation_unknown_only_v18() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(providerObservationSchema, prefix) != 1 {
		return fmt.Errorf("%w: invalid v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	body := strings.SplitN(providerObservationSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	var actualBody string
	var functionSafe bool
	if err := tx.QueryRowContext(ctx, `
		SELECT p.prosrc,
		       NOT p.prosecdef AND NOT p.proleakproof
		       AND p.provolatile='v' AND NOT p.proisstrict
		       AND p.proparallel='u' AND p.proconfig IS NULL
		       AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
		       AND p.pronamespace=pg_catalog.current_schema()::regnamespace
		       AND p.prorettype='pg_catalog.trigger'::regtype AND p.pronargs=0
		FROM pg_catalog.pg_proc p
		WHERE p.oid=pg_catalog.to_regprocedure(
			pg_catalog.format('%I.%I()', pg_catalog.current_schema(), 'guard_provider_observation_unknown_only_v18'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_provider_observation_unknown_only_v18()')
	`).Scan(&actualBody, &functionSafe); err != nil || !functionSafe || actualBody != body[:end] {
		return fmt.Errorf("%w: v18 UNKNOWN-only trigger function drift: %v", ErrSchemaDrift, err)
	}

	for _, trigger := range []struct {
		name, function string
		kind           int
	}{
		{"guard_provider_observation_unknown_only_v18", "guard_provider_observation_unknown_only_v18()", 7},
		{"guard_provider_observation_immutable_row", "guard_reject_snapshot_mutation()", 27},
		{"guard_provider_observation_immutable_truncate", "guard_reject_snapshot_mutation()", 34},
	} {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger t
				WHERE t.tgrelid=pg_catalog.to_regclass('guard_provider_observations')
				  AND t.tgname=$1 AND t.tgtype=$2
				  AND t.tgenabled='A' AND NOT t.tgisinternal
				  AND t.tgqual IS NULL AND t.tgattr::text=''
				  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
				  AND NOT t.tgdeferrable AND NOT t.tginitdeferred
				  AND t.tgfoid=pg_catalog.to_regprocedure($3)
			)
		`, trigger.name, trigger.kind, trigger.function).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v18 provider observation trigger %s drift: %v", ErrSchemaDrift, trigger.name, err)
		}
	}

	var dataConsistent bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1
			FROM guard_provider_observations o
			LEFT JOIN guard_operation_intents i
			  ON i.tenant_id=o.tenant_id AND i.operation_id=o.operation_id
			 AND i.permit_id=o.permit_id AND i.attempt_id=o.attempt_id
			 AND i.action_hash=o.action_hash
			LEFT JOIN guard_permits p
			  ON p.tenant_id=i.tenant_id AND p.operation_id=i.operation_id
			 AND p.permit_id=i.permit_id AND p.action_hash=i.action_hash
			LEFT JOIN guard_operation_unknown_events u
			  ON u.tenant_id=i.tenant_id AND u.operation_id=i.operation_id
			 AND u.permit_id=i.permit_id AND u.attempt_id=i.attempt_id
			 AND u.action_hash=i.action_hash
			LEFT JOIN guard_execution_audit a
			  ON a.tenant_id=i.tenant_id AND a.operation_id=i.operation_id
			 AND a.permit_id=i.permit_id AND a.attempt_id=i.attempt_id
			 AND a.action_hash=i.action_hash
			 AND a.event_type='guard.operation.dispatching.v1'
			WHERE i.attempt_id IS NULL OR i.state <> 'UNKNOWN'
			   OR p.state <> 'CLAIMED' OR u.attempt_id IS NULL OR a.attempt_id IS NULL
		)
	`).Scan(&dataConsistent); err != nil || !dataConsistent {
		return fmt.Errorf("%w: v18 provider observation rows are not bound to durable UNKNOWN attempts: %v", ErrSchemaDrift, err)
	}
	return nil
}
::text)))"},
		{"guard_provider_observation_outcome_shape_check", "(((outcome = 'FOUND'::text) AND (receipt_id IS NOT NULL) AND (effect = 'APPLIED'::text)) OR ((outcome = 'FAILED_CONFIRMED'::text) AND (receipt_id IS NOT NULL) AND (effect = 'NOT_APPLIED'::text)) OR ((outcome = 'ABSENT_UNCERTAIN'::text) AND (receipt_id IS NULL) AND (effect IS NULL)))"},
	}
	for _, check := range checks {
		var expression string
		err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
			FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND c.conname=$1 AND c.contype='c'
			  AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred
		`, check.name).Scan(&expression)
		if err != nil {
			return fmt.Errorf("%w: v18 provider observation check %s missing or invalid: %v", ErrSchemaDrift, check.name, err)
		}
		if check.expression != "" && expression != check.expression {
			return fmt.Errorf("%w: v18 provider observation check %s expression drift: got %q", ErrSchemaDrift, check.name, expression)
		}
	}

	var terminalIndex bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_index i
			JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid
			WHERE i.indrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND idx.oid=pg_catalog.to_regclass('guard_provider_observation_one_terminal_uq')
			  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
			  AND i.indimmediate AND i.indpred IS NOT NULL
			  AND i.indexprs IS NULL AND i.indnkeyatts=2 AND i.indnatts=2
			  AND (SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			       FROM pg_catalog.unnest(i.indkey) WITH ORDINALITY k(attnum,ord)
			       JOIN pg_catalog.pg_attribute a
			         ON a.attrelid=i.indrelid AND a.attnum=k.attnum)
			      ='tenant_id,attempt_id'
			  AND pg_catalog.pg_get_expr(i.indpred,i.indrelid)
			      = '(outcome = ANY (ARRAY[''FOUND''::text, ''FAILED_CONFIRMED''::text]))'
		)
	`).Scan(&terminalIndex); err != nil || !terminalIndex {
		return fmt.Errorf("%w: v18 one-terminal provider observation index drift: %v", ErrSchemaDrift, err)
	}

	const prefix = "CREATE FUNCTION guard_provider_observation_unknown_only_v18() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(providerObservationSchema, prefix) != 1 {
		return fmt.Errorf("%w: invalid v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	body := strings.SplitN(providerObservationSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	var actualBody string
	var functionSafe bool
	if err := tx.QueryRowContext(ctx, `
		SELECT p.prosrc,
		       NOT p.prosecdef AND NOT p.proleakproof
		       AND p.provolatile='v' AND NOT p.proisstrict
		       AND p.proparallel='u' AND p.proconfig IS NULL
		       AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
		       AND p.pronamespace=pg_catalog.current_schema()::regnamespace
		       AND p.prorettype='pg_catalog.trigger'::regtype AND p.pronargs=0
		FROM pg_catalog.pg_proc p
		WHERE p.oid=pg_catalog.to_regprocedure(
			pg_catalog.format('%I.%I()', pg_catalog.current_schema(), 'guard_provider_observation_unknown_only_v18'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_provider_observation_unknown_only_v18()')
	`).Scan(&actualBody, &functionSafe); err != nil || !functionSafe || actualBody != body[:end] {
		return fmt.Errorf("%w: v18 UNKNOWN-only trigger function drift: %v", ErrSchemaDrift, err)
	}

	for _, trigger := range []struct {
		name, function string
		kind           int
	}{
		{"guard_provider_observation_unknown_only_v18", "guard_provider_observation_unknown_only_v18()", 7},
		{"guard_provider_observation_immutable_row", "guard_reject_snapshot_mutation()", 27},
		{"guard_provider_observation_immutable_truncate", "guard_reject_snapshot_mutation()", 34},
	} {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger t
				WHERE t.tgrelid=pg_catalog.to_regclass('guard_provider_observations')
				  AND t.tgname=$1 AND t.tgtype=$2
				  AND t.tgenabled='A' AND NOT t.tgisinternal
				  AND t.tgqual IS NULL AND t.tgattr::text=''
				  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
				  AND NOT t.tgdeferrable AND NOT t.tginitdeferred
				  AND t.tgfoid=pg_catalog.to_regprocedure($3)
			)
		`, trigger.name, trigger.kind, trigger.function).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v18 provider observation trigger %s drift: %v", ErrSchemaDrift, trigger.name, err)
		}
	}

	var dataConsistent bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1
			FROM guard_provider_observations o
			LEFT JOIN guard_operation_intents i
			  ON i.tenant_id=o.tenant_id AND i.operation_id=o.operation_id
			 AND i.permit_id=o.permit_id AND i.attempt_id=o.attempt_id
			 AND i.action_hash=o.action_hash
			LEFT JOIN guard_permits p
			  ON p.tenant_id=i.tenant_id AND p.operation_id=i.operation_id
			 AND p.permit_id=i.permit_id AND p.action_hash=i.action_hash
			LEFT JOIN guard_operation_unknown_events u
			  ON u.tenant_id=i.tenant_id AND u.operation_id=i.operation_id
			 AND u.permit_id=i.permit_id AND u.attempt_id=i.attempt_id
			 AND u.action_hash=i.action_hash
			LEFT JOIN guard_execution_audit a
			  ON a.tenant_id=i.tenant_id AND a.operation_id=i.operation_id
			 AND a.permit_id=i.permit_id AND a.attempt_id=i.attempt_id
			 AND a.action_hash=i.action_hash
			 AND a.event_type='guard.operation.dispatching.v1'
			WHERE i.attempt_id IS NULL OR i.state <> 'UNKNOWN'
			   OR p.state <> 'CLAIMED' OR u.attempt_id IS NULL OR a.attempt_id IS NULL
		)
	`).Scan(&dataConsistent); err != nil || !dataConsistent {
		return fmt.Errorf("%w: v18 provider observation rows are not bound to durable UNKNOWN attempts: %v", ErrSchemaDrift, err)
	}
	return nil
}
::text))"},
		{"guard_provider_observations_idempotency_key_check", ""},
		{"guard_provider_observations_action_hash_check", "(action_hash ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_outcome_check", "(outcome = ANY (ARRAY['FOUND'::text, 'ABSENT_UNCERTAIN'::text, 'FAILED_CONFIRMED'::text]))"},
		{"guard_provider_observations_evidence_digest_check", "(evidence_digest ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_evidence_bytes_check", "((octet_length(evidence_bytes) >= 1) AND (octet_length(evidence_bytes) <= 262144))"},
		{"guard_provider_observations_verifier_id_check", ""},
		{"guard_provider_observations_observed_at_check", ""},
		{"guard_provider_observation_receipt_id_check", ""},
		{"guard_provider_observation_outcome_shape_check", "(((outcome = 'FOUND'::text) AND (receipt_id IS NOT NULL) AND (effect = 'APPLIED'::text)) OR ((outcome = 'FAILED_CONFIRMED'::text) AND (receipt_id IS NOT NULL) AND (effect = 'NOT_APPLIED'::text)) OR ((outcome = 'ABSENT_UNCERTAIN'::text) AND (receipt_id IS NULL) AND (effect IS NULL)))"},
	}
	for _, check := range checks {
		var expression string
		err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
			FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND c.conname=$1 AND c.contype='c'
			  AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred
		`, check.name).Scan(&expression)
		if err != nil {
			return fmt.Errorf("%w: v18 provider observation check %s missing or invalid: %v", ErrSchemaDrift, check.name, err)
		}
		if check.expression != "" && expression != check.expression {
			return fmt.Errorf("%w: v18 provider observation check %s expression drift: got %q", ErrSchemaDrift, check.name, expression)
		}
	}

	var terminalIndex bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_index i
			JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid
			WHERE i.indrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND idx.oid=pg_catalog.to_regclass('guard_provider_observation_one_terminal_uq')
			  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
			  AND i.indimmediate AND i.indpred IS NOT NULL
			  AND i.indexprs IS NULL AND i.indnkeyatts=2 AND i.indnatts=2
			  AND (SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			       FROM pg_catalog.unnest(i.indkey) WITH ORDINALITY k(attnum,ord)
			       JOIN pg_catalog.pg_attribute a
			         ON a.attrelid=i.indrelid AND a.attnum=k.attnum)
			      ='tenant_id,attempt_id'
			  AND pg_catalog.pg_get_expr(i.indpred,i.indrelid)
			      = '(outcome = ANY (ARRAY[''FOUND''::text, ''FAILED_CONFIRMED''::text]))'
		)
	`).Scan(&terminalIndex); err != nil || !terminalIndex {
		return fmt.Errorf("%w: v18 one-terminal provider observation index drift: %v", ErrSchemaDrift, err)
	}

	const prefix = "CREATE FUNCTION guard_provider_observation_unknown_only_v18() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(providerObservationSchema, prefix) != 1 {
		return fmt.Errorf("%w: invalid v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	body := strings.SplitN(providerObservationSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	var actualBody string
	var functionSafe bool
	if err := tx.QueryRowContext(ctx, `
		SELECT p.prosrc,
		       NOT p.prosecdef AND NOT p.proleakproof
		       AND p.provolatile='v' AND NOT p.proisstrict
		       AND p.proparallel='u' AND p.proconfig IS NULL
		       AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
		       AND p.pronamespace=pg_catalog.current_schema()::regnamespace
		       AND p.prorettype='pg_catalog.trigger'::regtype AND p.pronargs=0
		FROM pg_catalog.pg_proc p
		WHERE p.oid=pg_catalog.to_regprocedure(
			pg_catalog.format('%I.%I()', pg_catalog.current_schema(), 'guard_provider_observation_unknown_only_v18'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_provider_observation_unknown_only_v18()')
	`).Scan(&actualBody, &functionSafe); err != nil || !functionSafe || actualBody != body[:end] {
		return fmt.Errorf("%w: v18 UNKNOWN-only trigger function drift: %v", ErrSchemaDrift, err)
	}

	for _, trigger := range []struct {
		name, function string
		kind           int
	}{
		{"guard_provider_observation_unknown_only_v18", "guard_provider_observation_unknown_only_v18()", 7},
		{"guard_provider_observation_immutable_row", "guard_reject_snapshot_mutation()", 27},
		{"guard_provider_observation_immutable_truncate", "guard_reject_snapshot_mutation()", 34},
	} {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger t
				WHERE t.tgrelid=pg_catalog.to_regclass('guard_provider_observations')
				  AND t.tgname=$1 AND t.tgtype=$2
				  AND t.tgenabled='A' AND NOT t.tgisinternal
				  AND t.tgqual IS NULL AND t.tgattr::text=''
				  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
				  AND NOT t.tgdeferrable AND NOT t.tginitdeferred
				  AND t.tgfoid=pg_catalog.to_regprocedure($3)
			)
		`, trigger.name, trigger.kind, trigger.function).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v18 provider observation trigger %s drift: %v", ErrSchemaDrift, trigger.name, err)
		}
	}

	var dataConsistent bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1
			FROM guard_provider_observations o
			LEFT JOIN guard_operation_intents i
			  ON i.tenant_id=o.tenant_id AND i.operation_id=o.operation_id
			 AND i.permit_id=o.permit_id AND i.attempt_id=o.attempt_id
			 AND i.action_hash=o.action_hash
			LEFT JOIN guard_permits p
			  ON p.tenant_id=i.tenant_id AND p.operation_id=i.operation_id
			 AND p.permit_id=i.permit_id AND p.action_hash=i.action_hash
			LEFT JOIN guard_operation_unknown_events u
			  ON u.tenant_id=i.tenant_id AND u.operation_id=i.operation_id
			 AND u.permit_id=i.permit_id AND u.attempt_id=i.attempt_id
			 AND u.action_hash=i.action_hash
			LEFT JOIN guard_execution_audit a
			  ON a.tenant_id=i.tenant_id AND a.operation_id=i.operation_id
			 AND a.permit_id=i.permit_id AND a.attempt_id=i.attempt_id
			 AND a.action_hash=i.action_hash
			 AND a.event_type='guard.operation.dispatching.v1'
			WHERE i.attempt_id IS NULL OR i.state <> 'UNKNOWN'
			   OR p.state <> 'CLAIMED' OR u.attempt_id IS NULL OR a.attempt_id IS NULL
		)
	`).Scan(&dataConsistent); err != nil || !dataConsistent {
		return fmt.Errorf("%w: v18 provider observation rows are not bound to durable UNKNOWN attempts: %v", ErrSchemaDrift, err)
	}
	return nil
}
::text))"},
		{"guard_provider_observations_action_hash_check", "(action_hash ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_outcome_check", "(outcome = ANY (ARRAY['FOUND'::text, 'ABSENT_UNCERTAIN'::text, 'FAILED_CONFIRMED'::text]))"},
		{"guard_provider_observations_evidence_digest_check", "(evidence_digest ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_evidence_bytes_check", "((octet_length(evidence_bytes) >= 1) AND (octet_length(evidence_bytes) <= 262144))"},
		{"guard_provider_observations_verifier_id_check", ""},
		{"guard_provider_observations_observed_at_check", ""},
		{"guard_provider_observation_receipt_id_check", ""},
		{"guard_provider_observation_outcome_shape_check", "(((outcome = 'FOUND'::text) AND (receipt_id IS NOT NULL) AND (effect = 'APPLIED'::text)) OR ((outcome = 'FAILED_CONFIRMED'::text) AND (receipt_id IS NOT NULL) AND (effect = 'NOT_APPLIED'::text)) OR ((outcome = 'ABSENT_UNCERTAIN'::text) AND (receipt_id IS NULL) AND (effect IS NULL)))"},
	}
	for _, check := range checks {
		var expression string
		err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
			FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND c.conname=$1 AND c.contype='c'
			  AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred
		`, check.name).Scan(&expression)
		if err != nil {
			return fmt.Errorf("%w: v18 provider observation check %s missing or invalid: %v", ErrSchemaDrift, check.name, err)
		}
		if check.expression != "" && expression != check.expression {
			return fmt.Errorf("%w: v18 provider observation check %s expression drift: got %q", ErrSchemaDrift, check.name, expression)
		}
	}

	var terminalIndex bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_index i
			JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid
			WHERE i.indrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND idx.oid=pg_catalog.to_regclass('guard_provider_observation_one_terminal_uq')
			  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
			  AND i.indimmediate AND i.indpred IS NOT NULL
			  AND i.indexprs IS NULL AND i.indnkeyatts=2 AND i.indnatts=2
			  AND (SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			       FROM pg_catalog.unnest(i.indkey) WITH ORDINALITY k(attnum,ord)
			       JOIN pg_catalog.pg_attribute a
			         ON a.attrelid=i.indrelid AND a.attnum=k.attnum)
			      ='tenant_id,attempt_id'
			  AND pg_catalog.pg_get_expr(i.indpred,i.indrelid)
			      = '(outcome = ANY (ARRAY[''FOUND''::text, ''FAILED_CONFIRMED''::text]))'
		)
	`).Scan(&terminalIndex); err != nil || !terminalIndex {
		return fmt.Errorf("%w: v18 one-terminal provider observation index drift: %v", ErrSchemaDrift, err)
	}

	const prefix = "CREATE FUNCTION guard_provider_observation_unknown_only_v18() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(providerObservationSchema, prefix) != 1 {
		return fmt.Errorf("%w: invalid v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	body := strings.SplitN(providerObservationSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	var actualBody string
	var functionSafe bool
	if err := tx.QueryRowContext(ctx, `
		SELECT p.prosrc,
		       NOT p.prosecdef AND NOT p.proleakproof
		       AND p.provolatile='v' AND NOT p.proisstrict
		       AND p.proparallel='u' AND p.proconfig IS NULL
		       AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
		       AND p.pronamespace=pg_catalog.current_schema()::regnamespace
		       AND p.prorettype='pg_catalog.trigger'::regtype AND p.pronargs=0
		FROM pg_catalog.pg_proc p
		WHERE p.oid=pg_catalog.to_regprocedure(
			pg_catalog.format('%I.%I()', pg_catalog.current_schema(), 'guard_provider_observation_unknown_only_v18'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_provider_observation_unknown_only_v18()')
	`).Scan(&actualBody, &functionSafe); err != nil || !functionSafe || actualBody != body[:end] {
		return fmt.Errorf("%w: v18 UNKNOWN-only trigger function drift: %v", ErrSchemaDrift, err)
	}

	for _, trigger := range []struct {
		name, function string
		kind           int
	}{
		{"guard_provider_observation_unknown_only_v18", "guard_provider_observation_unknown_only_v18()", 7},
		{"guard_provider_observation_immutable_row", "guard_reject_snapshot_mutation()", 27},
		{"guard_provider_observation_immutable_truncate", "guard_reject_snapshot_mutation()", 34},
	} {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger t
				WHERE t.tgrelid=pg_catalog.to_regclass('guard_provider_observations')
				  AND t.tgname=$1 AND t.tgtype=$2
				  AND t.tgenabled='A' AND NOT t.tgisinternal
				  AND t.tgqual IS NULL AND t.tgattr::text=''
				  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
				  AND NOT t.tgdeferrable AND NOT t.tginitdeferred
				  AND t.tgfoid=pg_catalog.to_regprocedure($3)
			)
		`, trigger.name, trigger.kind, trigger.function).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v18 provider observation trigger %s drift: %v", ErrSchemaDrift, trigger.name, err)
		}
	}

	var dataConsistent bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1
			FROM guard_provider_observations o
			LEFT JOIN guard_operation_intents i
			  ON i.tenant_id=o.tenant_id AND i.operation_id=o.operation_id
			 AND i.permit_id=o.permit_id AND i.attempt_id=o.attempt_id
			 AND i.action_hash=o.action_hash
			LEFT JOIN guard_permits p
			  ON p.tenant_id=i.tenant_id AND p.operation_id=i.operation_id
			 AND p.permit_id=i.permit_id AND p.action_hash=i.action_hash
			LEFT JOIN guard_operation_unknown_events u
			  ON u.tenant_id=i.tenant_id AND u.operation_id=i.operation_id
			 AND u.permit_id=i.permit_id AND u.attempt_id=i.attempt_id
			 AND u.action_hash=i.action_hash
			LEFT JOIN guard_execution_audit a
			  ON a.tenant_id=i.tenant_id AND a.operation_id=i.operation_id
			 AND a.permit_id=i.permit_id AND a.attempt_id=i.attempt_id
			 AND a.action_hash=i.action_hash
			 AND a.event_type='guard.operation.dispatching.v1'
			WHERE i.attempt_id IS NULL OR i.state <> 'UNKNOWN'
			   OR p.state <> 'CLAIMED' OR u.attempt_id IS NULL OR a.attempt_id IS NULL
		)
	`).Scan(&dataConsistent); err != nil || !dataConsistent {
		return fmt.Errorf("%w: v18 provider observation rows are not bound to durable UNKNOWN attempts: %v", ErrSchemaDrift, err)
	}
	return nil
}
::text))"},
		{"guard_provider_observations_idempotency_key_check", ""},
		{"guard_provider_observations_action_hash_check", "(action_hash ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_outcome_check", "(outcome = ANY (ARRAY['FOUND'::text, 'ABSENT_UNCERTAIN'::text, 'FAILED_CONFIRMED'::text]))"},
		{"guard_provider_observations_evidence_digest_check", "(evidence_digest ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_evidence_bytes_check", "((octet_length(evidence_bytes) >= 1) AND (octet_length(evidence_bytes) <= 262144))"},
		{"guard_provider_observations_verifier_id_check", ""},
		{"guard_provider_observations_observed_at_check", ""},
		{"guard_provider_observation_receipt_id_check", ""},
		{"guard_provider_observation_outcome_shape_check", "(((outcome = 'FOUND'::text) AND (receipt_id IS NOT NULL) AND (effect = 'APPLIED'::text)) OR ((outcome = 'FAILED_CONFIRMED'::text) AND (receipt_id IS NOT NULL) AND (effect = 'NOT_APPLIED'::text)) OR ((outcome = 'ABSENT_UNCERTAIN'::text) AND (receipt_id IS NULL) AND (effect IS NULL)))"},
	}
	for _, check := range checks {
		var expression string
		err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
			FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND c.conname=$1 AND c.contype='c'
			  AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred
		`, check.name).Scan(&expression)
		if err != nil {
			return fmt.Errorf("%w: v18 provider observation check %s missing or invalid: %v", ErrSchemaDrift, check.name, err)
		}
		if check.expression != "" && expression != check.expression {
			return fmt.Errorf("%w: v18 provider observation check %s expression drift: got %q", ErrSchemaDrift, check.name, expression)
		}
	}

	var terminalIndex bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_index i
			JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid
			WHERE i.indrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND idx.oid=pg_catalog.to_regclass('guard_provider_observation_one_terminal_uq')
			  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
			  AND i.indimmediate AND i.indpred IS NOT NULL
			  AND i.indexprs IS NULL AND i.indnkeyatts=2 AND i.indnatts=2
			  AND (SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			       FROM pg_catalog.unnest(i.indkey) WITH ORDINALITY k(attnum,ord)
			       JOIN pg_catalog.pg_attribute a
			         ON a.attrelid=i.indrelid AND a.attnum=k.attnum)
			      ='tenant_id,attempt_id'
			  AND pg_catalog.pg_get_expr(i.indpred,i.indrelid)
			      = '(outcome = ANY (ARRAY[''FOUND''::text, ''FAILED_CONFIRMED''::text]))'
		)
	`).Scan(&terminalIndex); err != nil || !terminalIndex {
		return fmt.Errorf("%w: v18 one-terminal provider observation index drift: %v", ErrSchemaDrift, err)
	}

	const prefix = "CREATE FUNCTION guard_provider_observation_unknown_only_v18() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(providerObservationSchema, prefix) != 1 {
		return fmt.Errorf("%w: invalid v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	body := strings.SplitN(providerObservationSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	var actualBody string
	var functionSafe bool
	if err := tx.QueryRowContext(ctx, `
		SELECT p.prosrc,
		       NOT p.prosecdef AND NOT p.proleakproof
		       AND p.provolatile='v' AND NOT p.proisstrict
		       AND p.proparallel='u' AND p.proconfig IS NULL
		       AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
		       AND p.pronamespace=pg_catalog.current_schema()::regnamespace
		       AND p.prorettype='pg_catalog.trigger'::regtype AND p.pronargs=0
		FROM pg_catalog.pg_proc p
		WHERE p.oid=pg_catalog.to_regprocedure(
			pg_catalog.format('%I.%I()', pg_catalog.current_schema(), 'guard_provider_observation_unknown_only_v18'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_provider_observation_unknown_only_v18()')
	`).Scan(&actualBody, &functionSafe); err != nil || !functionSafe || actualBody != body[:end] {
		return fmt.Errorf("%w: v18 UNKNOWN-only trigger function drift: %v", ErrSchemaDrift, err)
	}

	for _, trigger := range []struct {
		name, function string
		kind           int
	}{
		{"guard_provider_observation_unknown_only_v18", "guard_provider_observation_unknown_only_v18()", 7},
		{"guard_provider_observation_immutable_row", "guard_reject_snapshot_mutation()", 27},
		{"guard_provider_observation_immutable_truncate", "guard_reject_snapshot_mutation()", 34},
	} {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger t
				WHERE t.tgrelid=pg_catalog.to_regclass('guard_provider_observations')
				  AND t.tgname=$1 AND t.tgtype=$2
				  AND t.tgenabled='A' AND NOT t.tgisinternal
				  AND t.tgqual IS NULL AND t.tgattr::text=''
				  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
				  AND NOT t.tgdeferrable AND NOT t.tginitdeferred
				  AND t.tgfoid=pg_catalog.to_regprocedure($3)
			)
		`, trigger.name, trigger.kind, trigger.function).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v18 provider observation trigger %s drift: %v", ErrSchemaDrift, trigger.name, err)
		}
	}

	var dataConsistent bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1
			FROM guard_provider_observations o
			LEFT JOIN guard_operation_intents i
			  ON i.tenant_id=o.tenant_id AND i.operation_id=o.operation_id
			 AND i.permit_id=o.permit_id AND i.attempt_id=o.attempt_id
			 AND i.action_hash=o.action_hash
			LEFT JOIN guard_permits p
			  ON p.tenant_id=i.tenant_id AND p.operation_id=i.operation_id
			 AND p.permit_id=i.permit_id AND p.action_hash=i.action_hash
			LEFT JOIN guard_operation_unknown_events u
			  ON u.tenant_id=i.tenant_id AND u.operation_id=i.operation_id
			 AND u.permit_id=i.permit_id AND u.attempt_id=i.attempt_id
			 AND u.action_hash=i.action_hash
			LEFT JOIN guard_execution_audit a
			  ON a.tenant_id=i.tenant_id AND a.operation_id=i.operation_id
			 AND a.permit_id=i.permit_id AND a.attempt_id=i.attempt_id
			 AND a.action_hash=i.action_hash
			 AND a.event_type='guard.operation.dispatching.v1'
			WHERE i.attempt_id IS NULL OR i.state <> 'UNKNOWN'
			   OR p.state <> 'CLAIMED' OR u.attempt_id IS NULL OR a.attempt_id IS NULL
		)
	`).Scan(&dataConsistent); err != nil || !dataConsistent {
		return fmt.Errorf("%w: v18 provider observation rows are not bound to durable UNKNOWN attempts: %v", ErrSchemaDrift, err)
	}
	return nil
}
::text))"},
		{"guard_provider_observations_observed_at_check", ""},
		{"guard_provider_observation_receipt_id_check", ""},
		{"guard_provider_observation_outcome_shape_check", "(((outcome = 'FOUND'::text) AND (receipt_id IS NOT NULL) AND (effect = 'APPLIED'::text)) OR ((outcome = 'FAILED_CONFIRMED'::text) AND (receipt_id IS NOT NULL) AND (effect = 'NOT_APPLIED'::text)) OR ((outcome = 'ABSENT_UNCERTAIN'::text) AND (receipt_id IS NULL) AND (effect IS NULL)))"},
	}
	for _, check := range checks {
		var expression string
		err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
			FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND c.conname=$1 AND c.contype='c'
			  AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred
		`, check.name).Scan(&expression)
		if err != nil {
			return fmt.Errorf("%w: v18 provider observation check %s missing or invalid: %v", ErrSchemaDrift, check.name, err)
		}
		if check.expression != "" && expression != check.expression {
			return fmt.Errorf("%w: v18 provider observation check %s expression drift: got %q", ErrSchemaDrift, check.name, expression)
		}
	}

	var terminalIndex bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_index i
			JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid
			WHERE i.indrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND idx.oid=pg_catalog.to_regclass('guard_provider_observation_one_terminal_uq')
			  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
			  AND i.indimmediate AND i.indpred IS NOT NULL
			  AND i.indexprs IS NULL AND i.indnkeyatts=2 AND i.indnatts=2
			  AND (SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			       FROM pg_catalog.unnest(i.indkey) WITH ORDINALITY k(attnum,ord)
			       JOIN pg_catalog.pg_attribute a
			         ON a.attrelid=i.indrelid AND a.attnum=k.attnum)
			      ='tenant_id,attempt_id'
			  AND pg_catalog.pg_get_expr(i.indpred,i.indrelid)
			      = '(outcome = ANY (ARRAY[''FOUND''::text, ''FAILED_CONFIRMED''::text]))'
		)
	`).Scan(&terminalIndex); err != nil || !terminalIndex {
		return fmt.Errorf("%w: v18 one-terminal provider observation index drift: %v", ErrSchemaDrift, err)
	}

	const prefix = "CREATE FUNCTION guard_provider_observation_unknown_only_v18() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(providerObservationSchema, prefix) != 1 {
		return fmt.Errorf("%w: invalid v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	body := strings.SplitN(providerObservationSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	var actualBody string
	var functionSafe bool
	if err := tx.QueryRowContext(ctx, `
		SELECT p.prosrc,
		       NOT p.prosecdef AND NOT p.proleakproof
		       AND p.provolatile='v' AND NOT p.proisstrict
		       AND p.proparallel='u' AND p.proconfig IS NULL
		       AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
		       AND p.pronamespace=pg_catalog.current_schema()::regnamespace
		       AND p.prorettype='pg_catalog.trigger'::regtype AND p.pronargs=0
		FROM pg_catalog.pg_proc p
		WHERE p.oid=pg_catalog.to_regprocedure(
			pg_catalog.format('%I.%I()', pg_catalog.current_schema(), 'guard_provider_observation_unknown_only_v18'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_provider_observation_unknown_only_v18()')
	`).Scan(&actualBody, &functionSafe); err != nil || !functionSafe || actualBody != body[:end] {
		return fmt.Errorf("%w: v18 UNKNOWN-only trigger function drift: %v", ErrSchemaDrift, err)
	}

	for _, trigger := range []struct {
		name, function string
		kind           int
	}{
		{"guard_provider_observation_unknown_only_v18", "guard_provider_observation_unknown_only_v18()", 7},
		{"guard_provider_observation_immutable_row", "guard_reject_snapshot_mutation()", 27},
		{"guard_provider_observation_immutable_truncate", "guard_reject_snapshot_mutation()", 34},
	} {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger t
				WHERE t.tgrelid=pg_catalog.to_regclass('guard_provider_observations')
				  AND t.tgname=$1 AND t.tgtype=$2
				  AND t.tgenabled='A' AND NOT t.tgisinternal
				  AND t.tgqual IS NULL AND t.tgattr::text=''
				  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
				  AND NOT t.tgdeferrable AND NOT t.tginitdeferred
				  AND t.tgfoid=pg_catalog.to_regprocedure($3)
			)
		`, trigger.name, trigger.kind, trigger.function).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v18 provider observation trigger %s drift: %v", ErrSchemaDrift, trigger.name, err)
		}
	}

	var dataConsistent bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1
			FROM guard_provider_observations o
			LEFT JOIN guard_operation_intents i
			  ON i.tenant_id=o.tenant_id AND i.operation_id=o.operation_id
			 AND i.permit_id=o.permit_id AND i.attempt_id=o.attempt_id
			 AND i.action_hash=o.action_hash
			LEFT JOIN guard_permits p
			  ON p.tenant_id=i.tenant_id AND p.operation_id=i.operation_id
			 AND p.permit_id=i.permit_id AND p.action_hash=i.action_hash
			LEFT JOIN guard_operation_unknown_events u
			  ON u.tenant_id=i.tenant_id AND u.operation_id=i.operation_id
			 AND u.permit_id=i.permit_id AND u.attempt_id=i.attempt_id
			 AND u.action_hash=i.action_hash
			LEFT JOIN guard_execution_audit a
			  ON a.tenant_id=i.tenant_id AND a.operation_id=i.operation_id
			 AND a.permit_id=i.permit_id AND a.attempt_id=i.attempt_id
			 AND a.action_hash=i.action_hash
			 AND a.event_type='guard.operation.dispatching.v1'
			WHERE i.attempt_id IS NULL OR i.state <> 'UNKNOWN'
			   OR p.state <> 'CLAIMED' OR u.attempt_id IS NULL OR a.attempt_id IS NULL
		)
	`).Scan(&dataConsistent); err != nil || !dataConsistent {
		return fmt.Errorf("%w: v18 provider observation rows are not bound to durable UNKNOWN attempts: %v", ErrSchemaDrift, err)
	}
	return nil
}
::text))"},
		{"guard_provider_observations_idempotency_key_check", ""},
		{"guard_provider_observations_action_hash_check", "(action_hash ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_outcome_check", "(outcome = ANY (ARRAY['FOUND'::text, 'ABSENT_UNCERTAIN'::text, 'FAILED_CONFIRMED'::text]))"},
		{"guard_provider_observations_evidence_digest_check", "(evidence_digest ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_evidence_bytes_check", "((octet_length(evidence_bytes) >= 1) AND (octet_length(evidence_bytes) <= 262144))"},
		{"guard_provider_observations_verifier_id_check", ""},
		{"guard_provider_observations_observed_at_check", ""},
		{"guard_provider_observation_receipt_id_check", ""},
		{"guard_provider_observation_outcome_shape_check", "(((outcome = 'FOUND'::text) AND (receipt_id IS NOT NULL) AND (effect = 'APPLIED'::text)) OR ((outcome = 'FAILED_CONFIRMED'::text) AND (receipt_id IS NOT NULL) AND (effect = 'NOT_APPLIED'::text)) OR ((outcome = 'ABSENT_UNCERTAIN'::text) AND (receipt_id IS NULL) AND (effect IS NULL)))"},
	}
	for _, check := range checks {
		var expression string
		err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
			FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND c.conname=$1 AND c.contype='c'
			  AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred
		`, check.name).Scan(&expression)
		if err != nil {
			return fmt.Errorf("%w: v18 provider observation check %s missing or invalid: %v", ErrSchemaDrift, check.name, err)
		}
		if check.expression != "" && expression != check.expression {
			return fmt.Errorf("%w: v18 provider observation check %s expression drift: got %q", ErrSchemaDrift, check.name, expression)
		}
	}

	var terminalIndex bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_index i
			JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid
			WHERE i.indrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND idx.oid=pg_catalog.to_regclass('guard_provider_observation_one_terminal_uq')
			  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
			  AND i.indimmediate AND i.indpred IS NOT NULL
			  AND i.indexprs IS NULL AND i.indnkeyatts=2 AND i.indnatts=2
			  AND (SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			       FROM pg_catalog.unnest(i.indkey) WITH ORDINALITY k(attnum,ord)
			       JOIN pg_catalog.pg_attribute a
			         ON a.attrelid=i.indrelid AND a.attnum=k.attnum)
			      ='tenant_id,attempt_id'
			  AND pg_catalog.pg_get_expr(i.indpred,i.indrelid)
			      = '(outcome = ANY (ARRAY[''FOUND''::text, ''FAILED_CONFIRMED''::text]))'
		)
	`).Scan(&terminalIndex); err != nil || !terminalIndex {
		return fmt.Errorf("%w: v18 one-terminal provider observation index drift: %v", ErrSchemaDrift, err)
	}

	const prefix = "CREATE FUNCTION guard_provider_observation_unknown_only_v18() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(providerObservationSchema, prefix) != 1 {
		return fmt.Errorf("%w: invalid v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	body := strings.SplitN(providerObservationSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	var actualBody string
	var functionSafe bool
	if err := tx.QueryRowContext(ctx, `
		SELECT p.prosrc,
		       NOT p.prosecdef AND NOT p.proleakproof
		       AND p.provolatile='v' AND NOT p.proisstrict
		       AND p.proparallel='u' AND p.proconfig IS NULL
		       AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
		       AND p.pronamespace=pg_catalog.current_schema()::regnamespace
		       AND p.prorettype='pg_catalog.trigger'::regtype AND p.pronargs=0
		FROM pg_catalog.pg_proc p
		WHERE p.oid=pg_catalog.to_regprocedure(
			pg_catalog.format('%I.%I()', pg_catalog.current_schema(), 'guard_provider_observation_unknown_only_v18'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_provider_observation_unknown_only_v18()')
	`).Scan(&actualBody, &functionSafe); err != nil || !functionSafe || actualBody != body[:end] {
		return fmt.Errorf("%w: v18 UNKNOWN-only trigger function drift: %v", ErrSchemaDrift, err)
	}

	for _, trigger := range []struct {
		name, function string
		kind           int
	}{
		{"guard_provider_observation_unknown_only_v18", "guard_provider_observation_unknown_only_v18()", 7},
		{"guard_provider_observation_immutable_row", "guard_reject_snapshot_mutation()", 27},
		{"guard_provider_observation_immutable_truncate", "guard_reject_snapshot_mutation()", 34},
	} {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger t
				WHERE t.tgrelid=pg_catalog.to_regclass('guard_provider_observations')
				  AND t.tgname=$1 AND t.tgtype=$2
				  AND t.tgenabled='A' AND NOT t.tgisinternal
				  AND t.tgqual IS NULL AND t.tgattr::text=''
				  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
				  AND NOT t.tgdeferrable AND NOT t.tginitdeferred
				  AND t.tgfoid=pg_catalog.to_regprocedure($3)
			)
		`, trigger.name, trigger.kind, trigger.function).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v18 provider observation trigger %s drift: %v", ErrSchemaDrift, trigger.name, err)
		}
	}

	var dataConsistent bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1
			FROM guard_provider_observations o
			LEFT JOIN guard_operation_intents i
			  ON i.tenant_id=o.tenant_id AND i.operation_id=o.operation_id
			 AND i.permit_id=o.permit_id AND i.attempt_id=o.attempt_id
			 AND i.action_hash=o.action_hash
			LEFT JOIN guard_permits p
			  ON p.tenant_id=i.tenant_id AND p.operation_id=i.operation_id
			 AND p.permit_id=i.permit_id AND p.action_hash=i.action_hash
			LEFT JOIN guard_operation_unknown_events u
			  ON u.tenant_id=i.tenant_id AND u.operation_id=i.operation_id
			 AND u.permit_id=i.permit_id AND u.attempt_id=i.attempt_id
			 AND u.action_hash=i.action_hash
			LEFT JOIN guard_execution_audit a
			  ON a.tenant_id=i.tenant_id AND a.operation_id=i.operation_id
			 AND a.permit_id=i.permit_id AND a.attempt_id=i.attempt_id
			 AND a.action_hash=i.action_hash
			 AND a.event_type='guard.operation.dispatching.v1'
			WHERE i.attempt_id IS NULL OR i.state <> 'UNKNOWN'
			   OR p.state <> 'CLAIMED' OR u.attempt_id IS NULL OR a.attempt_id IS NULL
		)
	`).Scan(&dataConsistent); err != nil || !dataConsistent {
		return fmt.Errorf("%w: v18 provider observation rows are not bound to durable UNKNOWN attempts: %v", ErrSchemaDrift, err)
	}
	return nil
}
::text))"},
		{"guard_provider_observations_action_hash_check", "(action_hash ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_outcome_check", "(outcome = ANY (ARRAY['FOUND'::text, 'ABSENT_UNCERTAIN'::text, 'FAILED_CONFIRMED'::text]))"},
		{"guard_provider_observations_evidence_digest_check", "(evidence_digest ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_evidence_bytes_check", "((octet_length(evidence_bytes) >= 1) AND (octet_length(evidence_bytes) <= 262144))"},
		{"guard_provider_observations_verifier_id_check", ""},
		{"guard_provider_observations_observed_at_check", ""},
		{"guard_provider_observation_receipt_id_check", ""},
		{"guard_provider_observation_outcome_shape_check", "(((outcome = 'FOUND'::text) AND (receipt_id IS NOT NULL) AND (effect = 'APPLIED'::text)) OR ((outcome = 'FAILED_CONFIRMED'::text) AND (receipt_id IS NOT NULL) AND (effect = 'NOT_APPLIED'::text)) OR ((outcome = 'ABSENT_UNCERTAIN'::text) AND (receipt_id IS NULL) AND (effect IS NULL)))"},
	}
	for _, check := range checks {
		var expression string
		err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
			FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND c.conname=$1 AND c.contype='c'
			  AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred
		`, check.name).Scan(&expression)
		if err != nil {
			return fmt.Errorf("%w: v18 provider observation check %s missing or invalid: %v", ErrSchemaDrift, check.name, err)
		}
		if check.expression != "" && expression != check.expression {
			return fmt.Errorf("%w: v18 provider observation check %s expression drift: got %q", ErrSchemaDrift, check.name, expression)
		}
	}

	var terminalIndex bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_index i
			JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid
			WHERE i.indrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND idx.oid=pg_catalog.to_regclass('guard_provider_observation_one_terminal_uq')
			  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
			  AND i.indimmediate AND i.indpred IS NOT NULL
			  AND i.indexprs IS NULL AND i.indnkeyatts=2 AND i.indnatts=2
			  AND (SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			       FROM pg_catalog.unnest(i.indkey) WITH ORDINALITY k(attnum,ord)
			       JOIN pg_catalog.pg_attribute a
			         ON a.attrelid=i.indrelid AND a.attnum=k.attnum)
			      ='tenant_id,attempt_id'
			  AND pg_catalog.pg_get_expr(i.indpred,i.indrelid)
			      = '(outcome = ANY (ARRAY[''FOUND''::text, ''FAILED_CONFIRMED''::text]))'
		)
	`).Scan(&terminalIndex); err != nil || !terminalIndex {
		return fmt.Errorf("%w: v18 one-terminal provider observation index drift: %v", ErrSchemaDrift, err)
	}

	const prefix = "CREATE FUNCTION guard_provider_observation_unknown_only_v18() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(providerObservationSchema, prefix) != 1 {
		return fmt.Errorf("%w: invalid v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	body := strings.SplitN(providerObservationSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	var actualBody string
	var functionSafe bool
	if err := tx.QueryRowContext(ctx, `
		SELECT p.prosrc,
		       NOT p.prosecdef AND NOT p.proleakproof
		       AND p.provolatile='v' AND NOT p.proisstrict
		       AND p.proparallel='u' AND p.proconfig IS NULL
		       AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
		       AND p.pronamespace=pg_catalog.current_schema()::regnamespace
		       AND p.prorettype='pg_catalog.trigger'::regtype AND p.pronargs=0
		FROM pg_catalog.pg_proc p
		WHERE p.oid=pg_catalog.to_regprocedure(
			pg_catalog.format('%I.%I()', pg_catalog.current_schema(), 'guard_provider_observation_unknown_only_v18'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_provider_observation_unknown_only_v18()')
	`).Scan(&actualBody, &functionSafe); err != nil || !functionSafe || actualBody != body[:end] {
		return fmt.Errorf("%w: v18 UNKNOWN-only trigger function drift: %v", ErrSchemaDrift, err)
	}

	for _, trigger := range []struct {
		name, function string
		kind           int
	}{
		{"guard_provider_observation_unknown_only_v18", "guard_provider_observation_unknown_only_v18()", 7},
		{"guard_provider_observation_immutable_row", "guard_reject_snapshot_mutation()", 27},
		{"guard_provider_observation_immutable_truncate", "guard_reject_snapshot_mutation()", 34},
	} {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger t
				WHERE t.tgrelid=pg_catalog.to_regclass('guard_provider_observations')
				  AND t.tgname=$1 AND t.tgtype=$2
				  AND t.tgenabled='A' AND NOT t.tgisinternal
				  AND t.tgqual IS NULL AND t.tgattr::text=''
				  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
				  AND NOT t.tgdeferrable AND NOT t.tginitdeferred
				  AND t.tgfoid=pg_catalog.to_regprocedure($3)
			)
		`, trigger.name, trigger.kind, trigger.function).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v18 provider observation trigger %s drift: %v", ErrSchemaDrift, trigger.name, err)
		}
	}

	var dataConsistent bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1
			FROM guard_provider_observations o
			LEFT JOIN guard_operation_intents i
			  ON i.tenant_id=o.tenant_id AND i.operation_id=o.operation_id
			 AND i.permit_id=o.permit_id AND i.attempt_id=o.attempt_id
			 AND i.action_hash=o.action_hash
			LEFT JOIN guard_permits p
			  ON p.tenant_id=i.tenant_id AND p.operation_id=i.operation_id
			 AND p.permit_id=i.permit_id AND p.action_hash=i.action_hash
			LEFT JOIN guard_operation_unknown_events u
			  ON u.tenant_id=i.tenant_id AND u.operation_id=i.operation_id
			 AND u.permit_id=i.permit_id AND u.attempt_id=i.attempt_id
			 AND u.action_hash=i.action_hash
			LEFT JOIN guard_execution_audit a
			  ON a.tenant_id=i.tenant_id AND a.operation_id=i.operation_id
			 AND a.permit_id=i.permit_id AND a.attempt_id=i.attempt_id
			 AND a.action_hash=i.action_hash
			 AND a.event_type='guard.operation.dispatching.v1'
			WHERE i.attempt_id IS NULL OR i.state <> 'UNKNOWN'
			   OR p.state <> 'CLAIMED' OR u.attempt_id IS NULL OR a.attempt_id IS NULL
		)
	`).Scan(&dataConsistent); err != nil || !dataConsistent {
		return fmt.Errorf("%w: v18 provider observation rows are not bound to durable UNKNOWN attempts: %v", ErrSchemaDrift, err)
	}
	return nil
}
::text))"},
		{"guard_provider_observations_idempotency_key_check", ""},
		{"guard_provider_observations_action_hash_check", "(action_hash ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_outcome_check", "(outcome = ANY (ARRAY['FOUND'::text, 'ABSENT_UNCERTAIN'::text, 'FAILED_CONFIRMED'::text]))"},
		{"guard_provider_observations_evidence_digest_check", "(evidence_digest ~ '^[0-9a-f]{64}$'::text)"},
		{"guard_provider_observations_evidence_bytes_check", "((octet_length(evidence_bytes) >= 1) AND (octet_length(evidence_bytes) <= 262144))"},
		{"guard_provider_observations_verifier_id_check", ""},
		{"guard_provider_observations_observed_at_check", ""},
		{"guard_provider_observation_receipt_id_check", ""},
		{"guard_provider_observation_outcome_shape_check", "(((outcome = 'FOUND'::text) AND (receipt_id IS NOT NULL) AND (effect = 'APPLIED'::text)) OR ((outcome = 'FAILED_CONFIRMED'::text) AND (receipt_id IS NOT NULL) AND (effect = 'NOT_APPLIED'::text)) OR ((outcome = 'ABSENT_UNCERTAIN'::text) AND (receipt_id IS NULL) AND (effect IS NULL)))"},
	}
	for _, check := range checks {
		var expression string
		err := tx.QueryRowContext(ctx, `
			SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)
			FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND c.conname=$1 AND c.contype='c'
			  AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred
		`, check.name).Scan(&expression)
		if err != nil {
			return fmt.Errorf("%w: v18 provider observation check %s missing or invalid: %v", ErrSchemaDrift, check.name, err)
		}
		if check.expression != "" && expression != check.expression {
			return fmt.Errorf("%w: v18 provider observation check %s expression drift: got %q", ErrSchemaDrift, check.name, expression)
		}
	}

	var terminalIndex bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_index i
			JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid
			WHERE i.indrelid=pg_catalog.to_regclass('guard_provider_observations')
			  AND idx.oid=pg_catalog.to_regclass('guard_provider_observation_one_terminal_uq')
			  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
			  AND i.indimmediate AND i.indpred IS NOT NULL
			  AND i.indexprs IS NULL AND i.indnkeyatts=2 AND i.indnatts=2
			  AND (SELECT pg_catalog.string_agg(a.attname,',' ORDER BY k.ord)
			       FROM pg_catalog.unnest(i.indkey) WITH ORDINALITY k(attnum,ord)
			       JOIN pg_catalog.pg_attribute a
			         ON a.attrelid=i.indrelid AND a.attnum=k.attnum)
			      ='tenant_id,attempt_id'
			  AND pg_catalog.pg_get_expr(i.indpred,i.indrelid)
			      = '(outcome = ANY (ARRAY[''FOUND''::text, ''FAILED_CONFIRMED''::text]))'
		)
	`).Scan(&terminalIndex); err != nil || !terminalIndex {
		return fmt.Errorf("%w: v18 one-terminal provider observation index drift: %v", ErrSchemaDrift, err)
	}

	const prefix = "CREATE FUNCTION guard_provider_observation_unknown_only_v18() RETURNS trigger\nLANGUAGE plpgsql AS $guard$"
	if strings.Count(providerObservationSchema, prefix) != 1 {
		return fmt.Errorf("%w: invalid v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	body := strings.SplitN(providerObservationSchema, prefix, 2)[1]
	end := strings.Index(body, "$guard$;")
	if end < 0 {
		return fmt.Errorf("%w: unterminated v18 UNKNOWN-only trigger source", ErrSchemaDrift)
	}
	var actualBody string
	var functionSafe bool
	if err := tx.QueryRowContext(ctx, `
		SELECT p.prosrc,
		       NOT p.prosecdef AND NOT p.proleakproof
		       AND p.provolatile='v' AND NOT p.proisstrict
		       AND p.proparallel='u' AND p.proconfig IS NULL
		       AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
		       AND p.pronamespace=pg_catalog.current_schema()::regnamespace
		       AND p.prorettype='pg_catalog.trigger'::regtype AND p.pronargs=0
		FROM pg_catalog.pg_proc p
		WHERE p.oid=pg_catalog.to_regprocedure(
			pg_catalog.format('%I.%I()', pg_catalog.current_schema(), 'guard_provider_observation_unknown_only_v18'))
		  AND p.oid=pg_catalog.to_regprocedure('guard_provider_observation_unknown_only_v18()')
	`).Scan(&actualBody, &functionSafe); err != nil || !functionSafe || actualBody != body[:end] {
		return fmt.Errorf("%w: v18 UNKNOWN-only trigger function drift: %v", ErrSchemaDrift, err)
	}

	for _, trigger := range []struct {
		name, function string
		kind           int
	}{
		{"guard_provider_observation_unknown_only_v18", "guard_provider_observation_unknown_only_v18()", 7},
		{"guard_provider_observation_immutable_row", "guard_reject_snapshot_mutation()", 27},
		{"guard_provider_observation_immutable_truncate", "guard_reject_snapshot_mutation()", 34},
	} {
		var intact bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger t
				WHERE t.tgrelid=pg_catalog.to_regclass('guard_provider_observations')
				  AND t.tgname=$1 AND t.tgtype=$2
				  AND t.tgenabled='A' AND NOT t.tgisinternal
				  AND t.tgqual IS NULL AND t.tgattr::text=''
				  AND t.tgnargs=0 AND pg_catalog.octet_length(t.tgargs)=0
				  AND NOT t.tgdeferrable AND NOT t.tginitdeferred
				  AND t.tgfoid=pg_catalog.to_regprocedure($3)
			)
		`, trigger.name, trigger.kind, trigger.function).Scan(&intact); err != nil || !intact {
			return fmt.Errorf("%w: v18 provider observation trigger %s drift: %v", ErrSchemaDrift, trigger.name, err)
		}
	}

	var dataConsistent bool
	if err := tx.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
			SELECT 1
			FROM guard_provider_observations o
			LEFT JOIN guard_operation_intents i
			  ON i.tenant_id=o.tenant_id AND i.operation_id=o.operation_id
			 AND i.permit_id=o.permit_id AND i.attempt_id=o.attempt_id
			 AND i.action_hash=o.action_hash
			LEFT JOIN guard_permits p
			  ON p.tenant_id=i.tenant_id AND p.operation_id=i.operation_id
			 AND p.permit_id=i.permit_id AND p.action_hash=i.action_hash
			LEFT JOIN guard_operation_unknown_events u
			  ON u.tenant_id=i.tenant_id AND u.operation_id=i.operation_id
			 AND u.permit_id=i.permit_id AND u.attempt_id=i.attempt_id
			 AND u.action_hash=i.action_hash
			LEFT JOIN guard_execution_audit a
			  ON a.tenant_id=i.tenant_id AND a.operation_id=i.operation_id
			 AND a.permit_id=i.permit_id AND a.attempt_id=i.attempt_id
			 AND a.action_hash=i.action_hash
			 AND a.event_type='guard.operation.dispatching.v1'
			WHERE i.attempt_id IS NULL OR i.state <> 'UNKNOWN'
			   OR p.state <> 'CLAIMED' OR u.attempt_id IS NULL OR a.attempt_id IS NULL
		)
	`).Scan(&dataConsistent); err != nil || !dataConsistent {
		return fmt.Errorf("%w: v18 provider observation rows are not bound to durable UNKNOWN attempts: %v", ErrSchemaDrift, err)
	}
	return nil
}
