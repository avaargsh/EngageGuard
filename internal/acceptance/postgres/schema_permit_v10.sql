-- v10 Permit state transitions require exact causal evidence at COMMIT.
-- This is a database integrity fence only, not an issuer, approval or PEP.
-- Existing migration source v1-v9 and their checksums must not be rewritten.
-- Caller DB roles must lack DDL, TRIGGER and schema-owner privileges.
CREATE FUNCTION guard_permit_causal_transition_v10() RETURNS trigger
LANGUAGE plpgsql AS $guard$
BEGIN
    IF OLD.state = 'ISSUED' AND NEW.state = 'CLAIMED' THEN
        -- The trusted ClaimAuthorizedIntent transaction writes all three
        -- records in one transaction. A direct SQL UPDATE without its
        -- exact Intent and immutable dispatch audit fails on COMMIT.
        IF NOT EXISTS (
            SELECT 1
            FROM guard_operation_intents i
            JOIN guard_execution_audit a
              ON a.tenant_id = i.tenant_id
             AND a.operation_id = i.operation_id
             AND a.permit_id = i.permit_id
             AND a.attempt_id = i.attempt_id
             AND a.action_hash = i.action_hash
            WHERE i.tenant_id = NEW.tenant_id
              AND i.operation_id = NEW.operation_id
              AND i.permit_id = NEW.permit_id
              AND i.action_hash = NEW.action_hash
              AND i.binding_digest = NEW.binding_digest
              AND a.event_type = 'guard.operation.dispatching.v1'
        ) THEN
            RAISE EXCEPTION 'Guard Permit claim lacks exact committed Intent and audit'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
        -- RevokeScopedPermit commits the write and journal atomically.
        -- The timestamp is evidence of a transition, not a Permit outcome.
        IF NOT EXISTS (
            SELECT 1 FROM guard_permit_revocations r
             WHERE r.tenant_id = NEW.tenant_id
               AND r.permit_id = NEW.permit_id
               AND r.prior_state = OLD.state
        ) THEN
            RAISE EXCEPTION 'Guard Permit revocation lacks exact immutable evidence'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$guard$;
-- statement break
CREATE CONSTRAINT TRIGGER guard_permit_causal_transition_v10
AFTER UPDATE ON guard_permits
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION guard_permit_causal_transition_v10();
-- statement break
ALTER TABLE guard_permits ENABLE ALWAYS TRIGGER guard_permit_causal_transition_v10;
