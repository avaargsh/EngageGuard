-- v8: Permit identity and revocation evidence are write-once at the SQL boundary.
-- Ordinary application roles must not have DDL, TRIGGER or superuser rights.
-- ALWAYS triggers also fire under session_replication_role=replica.
CREATE FUNCTION guard_permit_immutable_row_v8() RETURNS trigger
LANGUAGE plpgsql AS $guard$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Guard issued Permits cannot be deleted' USING ERRCODE='23514';
    END IF;
    IF ROW(NEW.permit_id, NEW.tenant_id, NEW.operation_id, NEW.action_hash,
           NEW.binding_digest, NEW.audience, NEW.policy_version, NEW.issued_by,
           NEW.issued_at, NEW.expires_at)
       IS DISTINCT FROM
       ROW(OLD.permit_id, OLD.tenant_id, OLD.operation_id, OLD.action_hash,
           OLD.binding_digest, OLD.audience, OLD.policy_version, OLD.issued_by,
           OLD.issued_at, OLD.expires_at)
       OR (OLD.state = 'CLAIMED' AND NEW.state IS DISTINCT FROM OLD.state)
       OR (OLD.claimed_at IS NOT NULL AND NEW.claimed_at IS DISTINCT FROM OLD.claimed_at)
       OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at)
    THEN
        RAISE EXCEPTION 'Guard Permit identity or terminal state is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$guard$;
-- statement break
CREATE FUNCTION guard_forbid_permit_evidence_mutation_v8() RETURNS trigger
LANGUAGE plpgsql AS $guard$
BEGIN
    RAISE EXCEPTION 'Guard Permit and revocation evidence cannot be removed or changed' USING ERRCODE='23514';
END;
$guard$;
-- statement break
CREATE TRIGGER guard_permit_immutable_row_v8
BEFORE UPDATE OR DELETE ON guard_permits
FOR EACH ROW EXECUTE FUNCTION guard_permit_immutable_row_v8();
-- statement break
CREATE TRIGGER guard_permit_immutable_truncate_v8
BEFORE TRUNCATE ON guard_permits
FOR EACH STATEMENT EXECUTE FUNCTION guard_forbid_permit_evidence_mutation_v8();
-- statement break
CREATE TRIGGER guard_revocation_immutable_row_v8
BEFORE UPDATE OR DELETE ON guard_permit_revocations
FOR EACH ROW EXECUTE FUNCTION guard_forbid_permit_evidence_mutation_v8();
-- statement break
CREATE TRIGGER guard_revocation_immutable_truncate_v8
BEFORE TRUNCATE ON guard_permit_revocations
FOR EACH STATEMENT EXECUTE FUNCTION guard_forbid_permit_evidence_mutation_v8();
-- statement break
ALTER TABLE guard_permits ENABLE ALWAYS TRIGGER guard_permit_immutable_row_v8;
-- statement break
ALTER TABLE guard_permits ENABLE ALWAYS TRIGGER guard_permit_immutable_truncate_v8;
-- statement break
ALTER TABLE guard_permit_revocations ENABLE ALWAYS TRIGGER guard_revocation_immutable_row_v8;
-- statement break
ALTER TABLE guard_permit_revocations ENABLE ALWAYS TRIGGER guard_revocation_immutable_truncate_v8;
