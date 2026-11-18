-- v4: record uncertain dispatch outcome without a fresh dispatch grant.
-- Forward-only: original Permit, Intent, Audit and v3 identity migrations
-- retain their exact source bytes and checksums. This does not authorize
-- execution, claim a final outcome or prove an external effect.
ALTER TABLE guard_operation_intents DROP CONSTRAINT guard_operation_intents_state_check;

ALTER TABLE guard_operation_intents
    ADD CONSTRAINT guard_operation_intents_state_check
    CHECK (state IN ('DISPATCHING', 'UNKNOWN'));

CREATE TABLE guard_operation_unknown_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    operation_id UUID NOT NULL,
    permit_id UUID NOT NULL,
    attempt_id UUID NOT NULL,
    action_hash TEXT NOT NULL CHECK (action_hash ~ '^[0-9a-f]{64}$'),
    reason TEXT NOT NULL CHECK (reason IN (
        'ACK_LOST', 'PROVIDER_TIMEOUT', 'PROVIDER_UNAVAILABLE', 'WORKER_KILLED'
    )),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT guard_unknown_once_per_attempt UNIQUE (tenant_id, attempt_id),
    CONSTRAINT guard_unknown_exact_intent_fk
        FOREIGN KEY (tenant_id, operation_id, permit_id, attempt_id, action_hash)
        REFERENCES guard_operation_intents
            (tenant_id, operation_id, permit_id, attempt_id, action_hash)
        ON DELETE RESTRICT
);
