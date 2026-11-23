-- v10 is an additive *internal-only* atomic claim journal fence.
-- Preserve every v1-v9 source checksum. Deferrable, initially-deferred
-- constraint triggers observe the complete transaction at COMMIT, so the
-- legitimate Permit -> Intent -> Audit write order remains valid.
-- These triggers do NOT authenticate Permit issuance or authorize dispatch.
CREATE FUNCTION guard_claim_causal_commit_v10() RETURNS trigger
LANGUAGE plpgsql AS $guard$
DECLARE
    intact BOOLEAN;
BEGIN
    IF TG_TABLE_NAME = 'guard_permits' THEN
        IF NEW.state <> 'CLAIMED' THEN
            RETURN NULL;
        END IF;
        SELECT EXISTS (
            SELECT 1
            FROM guard_operation_intents AS i
            JOIN guard_execution_audit AS a
              ON a.tenant_id = i.tenant_id
             AND a.operation_id = i.operation_id
             AND a.permit_id = i.permit_id
             AND a.attempt_id = i.attempt_id
             AND a.action_hash = i.action_hash
             AND a.event_type = 'guard.operation.dispatching.v1'
            WHERE i.tenant_id = NEW.tenant_id
              AND i.operation_id = NEW.operation_id
              AND i.permit_id = NEW.permit_id
              AND i.action_hash = NEW.action_hash
              AND i.binding_digest = NEW.binding_digest
        ) INTO intact;
    ELSIF TG_TABLE_NAME = 'guard_operation_intents' THEN
        SELECT EXISTS (
            SELECT 1
            FROM guard_permits AS p
            JOIN guard_execution_audit AS a
              ON a.tenant_id = NEW.tenant_id
             AND a.operation_id = NEW.operation_id
             AND a.permit_id = NEW.permit_id
             AND a.attempt_id = NEW.attempt_id
             AND a.action_hash = NEW.action_hash
             AND a.event_type = 'guard.operation.dispatching.v1'
            WHERE p.tenant_id = NEW.tenant_id
              AND p.operation_id = NEW.operation_id
              AND p.permit_id = NEW.permit_id
              AND p.action_hash = NEW.action_hash
              AND p.binding_digest = NEW.binding_digest
              AND p.state = 'CLAIMED'
        ) INTO intact;
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
-- statement break
CREATE CONSTRAINT TRIGGER guard_permit_causal_commit_v10
AFTER INSERT OR UPDATE ON guard_permits
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION guard_claim_causal_commit_v10();
-- statement break
CREATE CONSTRAINT TRIGGER guard_intent_causal_commit_v10
AFTER INSERT OR UPDATE ON guard_operation_intents
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION guard_claim_causal_commit_v10();
-- statement break
ALTER TABLE guard_permits ENABLE ALWAYS TRIGGER guard_permit_causal_commit_v10;
-- statement break
ALTER TABLE guard_operation_intents ENABLE ALWAYS TRIGGER guard_intent_causal_commit_v10;
-- statement break
-- Constraint triggers do not retroactively validate already committed v9
-- rows. Reject any inconsistent historical claim or orphan Intent before
-- stamping v10; migration is atomic and must not repair/fabricate evidence.
DO $guard$
BEGIN
    IF EXISTS (
        SELECT 1 FROM guard_permits AS p
        WHERE p.state = 'CLAIMED'
          AND NOT EXISTS (
              SELECT 1 FROM guard_operation_intents AS i
              JOIN guard_execution_audit AS a
                ON a.tenant_id = i.tenant_id
               AND a.operation_id = i.operation_id
               AND a.permit_id = i.permit_id
               AND a.attempt_id = i.attempt_id
               AND a.action_hash = i.action_hash
               AND a.event_type = 'guard.operation.dispatching.v1'
              WHERE i.tenant_id = p.tenant_id
                AND i.operation_id = p.operation_id
                AND i.permit_id = p.permit_id
                AND i.action_hash = p.action_hash
                AND i.binding_digest = p.binding_digest
          )
    ) OR EXISTS (
        SELECT 1 FROM guard_operation_intents AS i
        WHERE NOT EXISTS (
            SELECT 1 FROM guard_permits AS p
            JOIN guard_execution_audit AS a
              ON a.tenant_id = i.tenant_id
             AND a.operation_id = i.operation_id
             AND a.permit_id = i.permit_id
             AND a.attempt_id = i.attempt_id
             AND a.action_hash = i.action_hash
             AND a.event_type = 'guard.operation.dispatching.v1'
            WHERE p.tenant_id = i.tenant_id
              AND p.operation_id = i.operation_id
              AND p.permit_id = i.permit_id
              AND p.action_hash = i.action_hash
              AND p.binding_digest = i.binding_digest
              AND p.state = 'CLAIMED'
        )
    ) THEN
        RAISE EXCEPTION 'Guard v10 refuses historical orphan Permit/Intent evidence'
            USING ERRCODE='23514';
    END IF;
END;
$guard$;
