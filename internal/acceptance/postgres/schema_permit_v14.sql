-- Canonical v14: revocation state and immutable journal must agree at
-- deferred constraint evaluation. Preserve all v1-v13 migration bytes.
-- This is internal integrity, not proof of trusted revocation authority.
CREATE FUNCTION guard_revocation_causal_commit_v14() RETURNS trigger
LANGUAGE plpgsql AS $guard$
DECLARE
    intact BOOLEAN;
BEGIN
    EXECUTE pg_catalog.format($query$
        SELECT EXISTS (
            SELECT 1 FROM %I.guard_permits p
            WHERE p.tenant_id = $1 AND p.permit_id = $2
              AND (
                (p.revoked_at IS NULL AND NOT EXISTS (
                    SELECT 1 FROM %I.guard_permit_revocations r
                    WHERE r.tenant_id = p.tenant_id AND r.permit_id = p.permit_id
                )) OR
                (p.revoked_at IS NOT NULL AND EXISTS (
                    SELECT 1 FROM %I.guard_permit_revocations r
                    WHERE r.tenant_id = p.tenant_id AND r.permit_id = p.permit_id
                      AND r.prior_state = p.state
                ))
              )
        )
    $query$, TG_TABLE_SCHEMA, TG_TABLE_SCHEMA, TG_TABLE_SCHEMA)
    INTO intact USING NEW.tenant_id, NEW.permit_id;
    IF NOT intact THEN
        RAISE EXCEPTION 'Guard revocation flag and journal must agree'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$guard$;
-- statement break
CREATE CONSTRAINT TRIGGER guard_permit_revocation_commit_v14
AFTER UPDATE ON guard_permits
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION guard_revocation_causal_commit_v14();
-- statement break
CREATE CONSTRAINT TRIGGER guard_revocation_journal_commit_v14
AFTER INSERT ON guard_permit_revocations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION guard_revocation_causal_commit_v14();
-- statement break
ALTER TABLE guard_permits ENABLE ALWAYS TRIGGER guard_permit_revocation_commit_v14;
-- statement break
ALTER TABLE guard_permit_revocations ENABLE ALWAYS TRIGGER guard_revocation_journal_commit_v14;
