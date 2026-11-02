-- P0 Guard internal pre-dispatch ledger, NOT an authorization/issuance API.
-- The source of trusted Permit issuance is intentionally absent in this slice.
CREATE TABLE guard_permits (
    permit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    operation_id UUID NOT NULL,
    action_hash TEXT NOT NULL CHECK (action_hash ~ '^[0-9a-f]{64}$'),
    binding_digest TEXT NOT NULL CHECK (binding_digest ~ '^[0-9a-f]{64}$'),
    audience TEXT NOT NULL CHECK (length(audience) BETWEEN 1 AND 512),
    policy_version TEXT NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 512),
    issued_by TEXT NOT NULL CHECK (length(issued_by) BETWEEN 1 AND 512),
    issued_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    state TEXT NOT NULL DEFAULT 'ISSUED' CHECK (state IN ('ISSUED', 'CLAIMED')),
    claimed_at TIMESTAMPTZ,
    CONSTRAINT guard_permit_operation_fk FOREIGN KEY (tenant_id, operation_id)
        REFERENCES guard_action_operations (tenant_id, operation_id) ON DELETE RESTRICT,
    CONSTRAINT guard_permit_operation_unique UNIQUE (tenant_id, operation_id),
    CONSTRAINT guard_permit_tenant_id_unique UNIQUE (tenant_id, permit_id),
    CONSTRAINT guard_permit_claim_state_check CHECK (
        (state = 'ISSUED' AND claimed_at IS NULL)
        OR (state = 'CLAIMED' AND claimed_at IS NOT NULL)
    )
);

CREATE TABLE guard_operation_intents (
    attempt_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    operation_id UUID NOT NULL,
    permit_id UUID NOT NULL,
    action_hash TEXT NOT NULL CHECK (action_hash ~ '^[0-9a-f]{64}$'),
    binding_digest TEXT NOT NULL CHECK (binding_digest ~ '^[0-9a-f]{64}$'),
    state TEXT NOT NULL DEFAULT 'DISPATCHING' CHECK (state = 'DISPATCHING'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT guard_intent_operation_fk FOREIGN KEY (tenant_id, operation_id)
        REFERENCES guard_action_operations (tenant_id, operation_id) ON DELETE RESTRICT,
    CONSTRAINT guard_intent_permit_fk FOREIGN KEY (tenant_id, permit_id)
        REFERENCES guard_permits (tenant_id, permit_id) ON DELETE RESTRICT,
    CONSTRAINT guard_intent_one_per_operation UNIQUE (tenant_id, operation_id),
    CONSTRAINT guard_intent_one_per_permit UNIQUE (tenant_id, permit_id),
    CONSTRAINT guard_intent_tenant_attempt_unique UNIQUE (tenant_id, attempt_id)
);

CREATE TABLE guard_execution_audit (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    operation_id UUID NOT NULL,
    permit_id UUID NOT NULL,
    attempt_id UUID NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type = 'guard.operation.dispatching.v1'),
    action_hash TEXT NOT NULL CHECK (action_hash ~ '^[0-9a-f]{64}$'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT guard_audit_permit_fk FOREIGN KEY (tenant_id, permit_id)
        REFERENCES guard_permits (tenant_id, permit_id) ON DELETE RESTRICT,
    CONSTRAINT guard_audit_attempt_fk FOREIGN KEY (tenant_id, attempt_id)
        REFERENCES guard_operation_intents (tenant_id, attempt_id) ON DELETE RESTRICT,
    CONSTRAINT guard_audit_one_dispatch_event UNIQUE (tenant_id, operation_id, event_type)
);
