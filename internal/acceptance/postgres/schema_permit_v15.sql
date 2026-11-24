-- v15: UNKNOWN is durable uncertainty, never permission to dispatch again.
-- Preserve v1-v14 SQL bytes. State and exact journal must agree at deferred
-- constraint evaluation; existing inconsistencies fail migration attestation.
CREATE FUNCTION guard_unknown_causal_commit_v15() RETURNS trigger
LANGUAGE plpgsql AS $guard$
DECLARE
    intact BOOLEAN;
BEGIN
    EXECUTE pg_catalog.format($query$
        SELECT EXISTS (
            SELECT 1 FROM %I.guard_operation_intents i
            WHERE i.tenant_id=$1 AND i.attempt_id=$2
              AND ((i.state='DISPATCHING' AND NOT EXISTS (
                    SELECT 1 FROM %I.guard_operation_unknown_events e
                    WHERE e.tenant_id=i.tenant_id AND e.attempt_id=i.attempt_id
                )) OR (i.state='UNKNOWN' AND EXISTS (
                    SELECT 1 FROM %I.guard_operation_unknown_events e
                    WHERE e.tenant_id=i.tenant_id AND e.attempt_id=i.attempt_id
                      AND e.operation_id=i.operation_id AND e.permit_id=i.permit_id
                      AND e.action_hash=i.action_hash
                )))
        )
    $query$, TG_TABLE_SCHEMA, TG_TABLE_SCHEMA, TG_TABLE_SCHEMA)
    INTO intact USING NEW.tenant_id, NEW.attempt_id;
    IF NOT intact THEN
        RAISE EXCEPTION 'Guard UNKNOWN state and immutable journal must agree'
            USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END;
$guard$;
-- statement break
CREATE CONSTRAINT TRIGGER guard_intent_unknown_commit_v15
AFTER INSERT OR UPDATE ON guard_operation_intents
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION guard_unknown_causal_commit_v15();
-- statement break
CREATE CONSTRAINT TRIGGER guard_unknown_journal_commit_v15
AFTER INSERT ON guard_operation_unknown_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION guard_unknown_causal_commit_v15();
-- statement break
ALTER TABLE guard_operation_intents ENABLE ALWAYS TRIGGER guard_intent_unknown_commit_v15;
-- statement break
ALTER TABLE guard_operation_unknown_events ENABLE ALWAYS TRIGGER guard_unknown_journal_commit_v15;
