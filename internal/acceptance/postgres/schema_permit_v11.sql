-- v11: bind both v10 causal journal lookups to the actual trigger schema.
-- Preserve all historical v1-v10 migration bytes and trigger identities.
-- This is database integrity only; it does not authorize protected effects.
CREATE OR REPLACE FUNCTION guard_claim_causal_commit_v10() RETURNS trigger
LANGUAGE plpgsql AS $guard$
DECLARE
    intact BOOLEAN;
BEGIN
    IF TG_TABLE_NAME = 'guard_permits' THEN
        IF NEW.state <> 'CLAIMED' THEN
            RETURN NULL;
        END IF;
        EXECUTE pg_catalog.format($query$
        SELECT EXISTS (
            SELECT 1
            FROM %I.guard_operation_intents AS i
            JOIN %I.guard_execution_audit AS a
              ON a.tenant_id = i.tenant_id
             AND a.operation_id = i.operation_id
             AND a.permit_id = i.permit_id
             AND a.attempt_id = i.attempt_id
             AND a.action_hash = i.action_hash
             AND a.event_type = 'guard.operation.dispatching.v1'
            WHERE i.tenant_id = $1
              AND i.operation_id = $2
              AND i.permit_id = $3
              AND i.action_hash = $4
              AND i.binding_digest = $5
        )
        $query$, TG_TABLE_SCHEMA, TG_TABLE_SCHEMA)
        INTO intact
        USING NEW.tenant_id, NEW.operation_id, NEW.permit_id, NEW.action_hash, NEW.binding_digest;
    ELSIF TG_TABLE_NAME = 'guard_operation_intents' THEN
        EXECUTE pg_catalog.format($query$
        SELECT EXISTS (
            SELECT 1
            FROM %I.guard_permits AS p
            JOIN %I.guard_execution_audit AS a
              ON a.tenant_id = $1
             AND a.operation_id = $2
             AND a.permit_id = $3
             AND a.attempt_id = $6
             AND a.action_hash = $4
             AND a.event_type = 'guard.operation.dispatching.v1'
            WHERE p.tenant_id = $1
              AND p.operation_id = $2
              AND p.permit_id = $3
              AND p.action_hash = $4
              AND p.binding_digest = $5
              AND p.state = 'CLAIMED'
        )
        $query$, TG_TABLE_SCHEMA, TG_TABLE_SCHEMA)
        INTO intact
        USING NEW.tenant_id, NEW.operation_id, NEW.permit_id, NEW.action_hash, NEW.binding_digest, NEW.attempt_id;
    ELSE
        RAISE EXCEPTION 'Guard v10 unexpected causal trigger relation'
            USING ERRCODE='23514';
    END IF;
    IF NOT intact THEN
        RAISE EXCEPTION 'Guard v10 requires CLAIMED Permit, exact Intent and immutable Audit'
            USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END;
$guard$;
