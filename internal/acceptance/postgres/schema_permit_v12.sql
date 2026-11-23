-- v12: an INSERT-only Permit issuer must not mint already-CLAIMED or
-- pre-revoked Permits without the deferred UPDATE journal and causal history.
-- Preserve prior migrations v1-v11 byte-for-byte and audit preexisting rows.
-- This is an integrity fence, NOT an authenticated issuer or provider PEP.
CREATE FUNCTION guard_permit_initial_state_v12() RETURNS trigger
LANGUAGE plpgsql AS $guard$
BEGIN
    IF NEW.state IS DISTINCT FROM 'ISSUED'
       OR NEW.claimed_at IS NOT NULL
       OR NEW.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'Guard Permit INSERT must start ISSUED and unclaimed/unrevoked'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$guard$;
-- statement break
CREATE TRIGGER guard_permit_initial_state_v12
BEFORE INSERT ON guard_permits
FOR EACH ROW EXECUTE FUNCTION guard_permit_initial_state_v12();
-- statement break
ALTER TABLE guard_permits ENABLE ALWAYS TRIGGER guard_permit_initial_state_v12;
-- statement break
-- CREATE TRIGGER holds a conflicting table lock through this migration
-- transaction. Refuse to stamp v12 over already-forged pre-claim/revocation
-- rows, rather than silently treating historical damage as authoritative.
DO $guard$
BEGIN
    IF EXISTS (
        SELECT 1 FROM guard_permits p
        WHERE (
            p.state = 'CLAIMED'
            AND NOT EXISTS (
                SELECT 1 FROM guard_operation_intents i
                JOIN guard_execution_audit a
                  ON a.tenant_id = i.tenant_id
                 AND a.operation_id = i.operation_id
                 AND a.permit_id = i.permit_id
                 AND a.attempt_id = i.attempt_id
                 AND a.action_hash = i.action_hash
                WHERE i.tenant_id = p.tenant_id
                  AND i.operation_id = p.operation_id
                  AND i.permit_id = p.permit_id
                  AND i.action_hash = p.action_hash
                  AND i.binding_digest = p.binding_digest
                  AND a.event_type = 'guard.operation.dispatching.v1'
            )
        ) OR (
            p.revoked_at IS NOT NULL
            AND NOT EXISTS (
                SELECT 1 FROM guard_permit_revocations r
                WHERE r.tenant_id = p.tenant_id
                  AND r.permit_id = p.permit_id
            )
        )
    ) THEN
        RAISE EXCEPTION 'Guard existing Permit claim/revocation lacks causal evidence'
            USING ERRCODE = '23514';
    END IF;
END;
$guard$;
