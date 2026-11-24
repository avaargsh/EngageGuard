-- Canonical v13: an inserted Permit must start ISSUED, unclaimed, unrevoked.
-- Preserve v1-v12 bytes. This is a necessary-only integrity fence.
CREATE FUNCTION guard_permit_initial_state_v13() RETURNS trigger
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
CREATE TRIGGER guard_permit_initial_state_v13
BEFORE INSERT ON guard_permits
FOR EACH ROW EXECUTE FUNCTION guard_permit_initial_state_v13();
-- statement break
ALTER TABLE guard_permits ENABLE ALWAYS TRIGGER guard_permit_initial_state_v13;
