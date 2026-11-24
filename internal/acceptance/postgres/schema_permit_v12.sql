-- v12: necessary database-side expiry fence for ISSUED -> CLAIMED.
-- This runs as a deferred constraint trigger when PostgreSQL resolves
-- transaction-end deferred events. It cannot prove an external effect or
-- eliminate every real-time interval between trigger evaluation and WAL COMMIT.
-- Previous versioned migrations v1-v11 remain byte-for-byte unchanged.
-- Ordinary Guard application roles must not own schema/DDL/TRIGGER privileges.
CREATE FUNCTION guard_permit_claim_expiry_v12() RETURNS trigger
LANGUAGE plpgsql AS $guard$
BEGIN
    IF OLD.state = 'ISSUED' AND NEW.state = 'CLAIMED' THEN
        IF NEW.revoked_at IS NOT NULL
           OR NEW.claimed_at IS NULL
           OR NEW.claimed_at < NEW.issued_at
           OR NEW.claimed_at >= NEW.expires_at
           OR clock_timestamp() >= NEW.expires_at THEN
            RAISE EXCEPTION 'Guard Permit expired or invalid at deferred claim check'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$guard$;
-- statement break
CREATE CONSTRAINT TRIGGER guard_permit_claim_expiry_v12
AFTER UPDATE ON guard_permits
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION guard_permit_claim_expiry_v12();
-- statement break
ALTER TABLE guard_permits ENABLE ALWAYS TRIGGER guard_permit_claim_expiry_v12;
