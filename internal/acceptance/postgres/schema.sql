-- P0 admission-only schema. No executor / Permit / UNKNOWN transition is enabled.
-- The surrounding Store.Accept transaction is the only supported writer.
CREATE TABLE IF NOT EXISTS guard_action_operations (
    operation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
    submission_key TEXT NOT NULL CHECK (length(submission_key) BETWEEN 1 AND 128),
    submission_digest TEXT NOT NULL CHECK (submission_digest ~ '^[0-9a-f]{64}$'),
    status TEXT NOT NULL DEFAULT 'ACCEPTED' CHECK (status = 'ACCEPTED'),
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, submission_key),
    UNIQUE (tenant_id, operation_id)
);

CREATE TABLE IF NOT EXISTS guard_outbox_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    operation_id UUID NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type = 'guard.submission.recorded.v1'),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT guard_outbox_operation_fk
        FOREIGN KEY (tenant_id, operation_id)
        REFERENCES guard_action_operations (tenant_id, operation_id),
    UNIQUE (tenant_id, operation_id, event_type)
);

CREATE INDEX IF NOT EXISTS guard_outbox_unpublished_idx
    ON guard_outbox_events (occurred_at, event_id);
