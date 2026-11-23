-- v13: harden the already installed v10 deferred causal trigger function.
-- Its v10 function resolves unqualified Intent/Audit/Revocation tables through
-- the invoker's search_path; pg_temp may shadow them in the *same session*.
-- This append-only replacement preserves the trigger OID and historical
-- v1-v12 migration SQL/checksums; never treat pg_temp as durable evidence.
-- No provider execution or trusted Permit issuance is introduced.
CREATE OR REPLACE FUNCTION guard_permit_causal_transition_v10() RETURNS trigger
LANGUAGE plpgsql AS $guard$
DECLARE
    complete boolean;
BEGIN
    IF OLD.state = 'ISSUED' AND NEW.state = 'CLAIMED' THEN
        EXECUTE pg_catalog.format($query$
            SELECT EXISTS (
                SELECT 1
                FROM %I.guard_operation_intents i
                JOIN %I.guard_execution_audit a
                  ON a.tenant_id = i.tenant_id
                 AND a.operation_id = i.operation_id
                 AND a.permit_id = i.permit_id
                 AND a.attempt_id = i.attempt_id
                 AND a.action_hash = i.action_hash
                WHERE i.tenant_id = $1
                  AND i.operation_id = $2
                  AND i.permit_id = $3
                  AND i.action_hash = $4
                  AND i.binding_digest = $5
                  AND a.event_type = 'guard.operation.dispatching.v1'
            )
        $query$, TG_TABLE_SCHEMA, TG_TABLE_SCHEMA)
        INTO complete
        USING NEW.tenant_id, NEW.operation_id, NEW.permit_id,
              NEW.action_hash, NEW.binding_digest;
        IF NOT complete THEN
            RAISE EXCEPTION 'Guard Permit claim lacks exact committed Intent and audit'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
        EXECUTE pg_catalog.format($query$
            SELECT EXISTS (
                SELECT 1 FROM %I.guard_permit_revocations r
                 WHERE r.tenant_id = $1
                   AND r.permit_id = $2
                   AND r.prior_state = $3
            )
        $query$, TG_TABLE_SCHEMA)
        INTO complete
        USING NEW.tenant_id, NEW.permit_id, OLD.state;
        IF NOT complete THEN
            RAISE EXCEPTION 'Guard Permit revocation lacks exact immutable evidence'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$guard$;
