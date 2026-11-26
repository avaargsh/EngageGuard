-- v18: append-only, provider-authenticated observations for an already UNKNOWN attempt.
-- This stores evidence only. It does not resolve the Intent, grant a retry, or dispatch.
CREATE TABLE guard_provider_observations (
    observation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    operation_id UUID NOT NULL,
    permit_id UUID NOT NULL,
    attempt_id UUID NOT NULL,
    provider_id TEXT NOT NULL CHECK (
        length(provider_id) BETWEEN 1 AND 256 AND provider_id COLLATE "C" ~ '^[!-~]+$'
    ),
    idempotency_key TEXT NOT NULL CHECK (
        length(idempotency_key) BETWEEN 1 AND 256 AND idempotency_key COLLATE "C" ~ '^[!-~]+$'
    ),
    action_hash TEXT NOT NULL CHECK (action_hash ~ '^[0-9a-f]{64}$'),
    outcome TEXT NOT NULL CHECK (outcome IN ('FOUND', 'ABSENT_UNCERTAIN', 'FAILED_CONFIRMED')),
    receipt_id TEXT,
    effect TEXT,
    evidence_digest TEXT NOT NULL CHECK (evidence_digest ~ '^[0-9a-f]{64}$'),
    evidence_bytes BYTEA NOT NULL CHECK (octet_length(evidence_bytes) BETWEEN 1 AND 262144),
    verifier_id TEXT NOT NULL CHECK (
        length(verifier_id) BETWEEN 1 AND 512 AND verifier_id COLLATE "C" ~ '^[!-~]+$'
    ),
    observed_at TIMESTAMPTZ NOT NULL CHECK (
        observed_at > '-infinity'::timestamptz AND observed_at < 'infinity'::timestamptz
    ),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT guard_provider_observation_attempt_digest_uq
        UNIQUE (tenant_id, attempt_id, evidence_digest),
    CONSTRAINT guard_provider_observation_exact_intent_fk
        FOREIGN KEY (tenant_id, operation_id, permit_id, attempt_id, action_hash)
        REFERENCES guard_operation_intents
            (tenant_id, operation_id, permit_id, attempt_id, action_hash)
        ON DELETE RESTRICT,
    CONSTRAINT guard_provider_observation_receipt_id_check CHECK (
        receipt_id IS NULL OR (
            length(receipt_id) BETWEEN 1 AND 256 AND receipt_id COLLATE "C" ~ '^[!-~]+$'
        )
    ),
    CONSTRAINT guard_provider_observation_outcome_shape_check CHECK (
        (outcome = 'FOUND' AND receipt_id IS NOT NULL AND effect = 'APPLIED')
        OR (outcome = 'FAILED_CONFIRMED' AND receipt_id IS NOT NULL AND effect = 'NOT_APPLIED')
        OR (outcome = 'ABSENT_UNCERTAIN' AND receipt_id IS NULL AND effect IS NULL)
    )
);

-- Only one terminal provider outcome may ever be recorded for an Attempt.
-- Multiple ABSENT_UNCERTAIN observations are allowed until a terminal receipt exists.
-- statement break
CREATE UNIQUE INDEX guard_provider_observation_one_terminal_uq
    ON guard_provider_observations (tenant_id, attempt_id)
    WHERE outcome IN ('FOUND', 'FAILED_CONFIRMED');

-- Serialize inserts on the immutable parent Attempt, require the exact
-- committed UNKNOWN journal, and prevent evidence after a terminal result.
-- statement break
CREATE FUNCTION guard_provider_observation_unknown_only_v18() RETURNS trigger
LANGUAGE plpgsql AS $guard$
BEGIN
    PERFORM 1
    FROM guard_operation_intents i
    JOIN guard_permits p
      ON p.tenant_id=i.tenant_id
     AND p.operation_id=i.operation_id
     AND p.permit_id=i.permit_id
     AND p.action_hash=i.action_hash
    JOIN guard_operation_unknown_events u
      ON u.tenant_id=i.tenant_id
     AND u.operation_id=i.operation_id
     AND u.permit_id=i.permit_id
     AND u.attempt_id=i.attempt_id
     AND u.action_hash=i.action_hash
    WHERE i.tenant_id=NEW.tenant_id
      AND i.operation_id=NEW.operation_id
      AND i.permit_id=NEW.permit_id
      AND i.attempt_id=NEW.attempt_id
      AND i.action_hash=NEW.action_hash
      AND i.state='UNKNOWN'
      AND p.state='CLAIMED'
    FOR UPDATE OF i;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'provider observation requires exact committed UNKNOWN Attempt'
            USING ERRCODE='23514';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM guard_provider_observations prior
        WHERE prior.tenant_id=NEW.tenant_id
          AND prior.attempt_id=NEW.attempt_id
          AND prior.outcome IN ('FOUND', 'FAILED_CONFIRMED')
    ) THEN
        RAISE EXCEPTION 'terminal provider observation already recorded for Attempt'
            USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$guard$;
-- statement break
CREATE TRIGGER guard_provider_observation_unknown_only_v18
BEFORE INSERT ON guard_provider_observations
FOR EACH ROW EXECUTE FUNCTION guard_provider_observation_unknown_only_v18();
-- statement break
CREATE TRIGGER guard_provider_observation_immutable_row
BEFORE UPDATE OR DELETE ON guard_provider_observations
FOR EACH ROW EXECUTE FUNCTION guard_reject_snapshot_mutation();
-- statement break
CREATE TRIGGER guard_provider_observation_immutable_truncate
BEFORE TRUNCATE ON guard_provider_observations
FOR EACH STATEMENT EXECUTE FUNCTION guard_reject_snapshot_mutation();
-- statement break
ALTER TABLE guard_provider_observations ENABLE ALWAYS TRIGGER guard_provider_observation_unknown_only_v18;
-- statement break
ALTER TABLE guard_provider_observations ENABLE ALWAYS TRIGGER guard_provider_observation_immutable_row;
-- statement break
ALTER TABLE guard_provider_observations ENABLE ALWAYS TRIGGER guard_provider_observation_immutable_truncate;
