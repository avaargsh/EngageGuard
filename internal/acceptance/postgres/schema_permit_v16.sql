-- v16: bind trusted issuance authority evidence to the one-time Permit.
-- Preserve v1-v15 migration bytes. Existing legacy Permit rows are not
-- fabricated into trusted evidence; only the new issuer adapter writes this
-- table atomically with guard_permits.
ALTER TABLE guard_permits
    ADD CONSTRAINT guard_permit_authority_identity_uq
    UNIQUE (
        tenant_id, operation_id, permit_id, action_hash, binding_digest,
        audience, policy_version, issued_by, issued_at, expires_at
    );
-- statement break
CREATE TABLE guard_permit_authority_evidence (
    tenant_id TEXT NOT NULL,
    operation_id UUID NOT NULL,
    permit_id UUID NOT NULL,
    run_id TEXT NOT NULL CHECK (
        length(run_id) BETWEEN 1 AND 512
        AND run_id !~ '[[:cntrl:][:space:]]'
    ),
    runtime_attempt_id TEXT NOT NULL CHECK (
        length(runtime_attempt_id) BETWEEN 1 AND 512
        AND runtime_attempt_id !~ '[[:cntrl:][:space:]]'
    ),
    turn_id TEXT NOT NULL CHECK (
        length(turn_id) BETWEEN 1 AND 512
        AND turn_id !~ '[[:cntrl:][:space:]]'
    ),
    approval_ref TEXT NOT NULL CHECK (
        length(approval_ref) BETWEEN 1 AND 512
        AND approval_ref !~ '[[:cntrl:][:space:]]'
    ),
    risk_revision TEXT NOT NULL CHECK (
        length(risk_revision) BETWEEN 1 AND 512
        AND risk_revision !~ '[[:cntrl:][:space:]]'
    ),
    action_hash TEXT NOT NULL CHECK (action_hash ~ '^[0-9a-f]{64}$'),
    binding_digest TEXT NOT NULL CHECK (binding_digest ~ '^[0-9a-f]{64}$'),
    audience TEXT NOT NULL CHECK (
        length(audience) BETWEEN 1 AND 512
        AND audience !~ '[[:cntrl:][:space:]]'
    ),
    policy_version TEXT NOT NULL CHECK (
        length(policy_version) BETWEEN 1 AND 512
        AND policy_version !~ '[[:cntrl:][:space:]]'
    ),
    issued_by TEXT NOT NULL CHECK (
        length(issued_by) BETWEEN 1 AND 512
        AND issued_by !~ '[[:cntrl:][:space:]]'
    ),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT guard_permit_authority_evidence_pkey PRIMARY KEY (tenant_id, permit_id),
    CONSTRAINT guard_permit_authority_operation_uq UNIQUE (tenant_id, operation_id),
    CONSTRAINT guard_permit_authority_time_check CHECK (expires_at > issued_at),
    CONSTRAINT guard_permit_authority_exact_permit_fk
        FOREIGN KEY (
            tenant_id, operation_id, permit_id, action_hash, binding_digest,
            audience, policy_version, issued_by, issued_at, expires_at
        )
        REFERENCES guard_permits (
            tenant_id, operation_id, permit_id, action_hash, binding_digest,
            audience, policy_version, issued_by, issued_at, expires_at
        )
        ON DELETE RESTRICT
);
-- statement break
CREATE TRIGGER guard_permit_authority_evidence_immutable_row
BEFORE UPDATE OR DELETE ON guard_permit_authority_evidence
FOR EACH ROW EXECUTE FUNCTION guard_reject_snapshot_mutation();
-- statement break
CREATE TRIGGER guard_permit_authority_evidence_immutable_truncate
BEFORE TRUNCATE ON guard_permit_authority_evidence
FOR EACH STATEMENT EXECUTE FUNCTION guard_reject_snapshot_mutation();
-- statement break
ALTER TABLE guard_permit_authority_evidence
    ENABLE ALWAYS TRIGGER guard_permit_authority_evidence_immutable_row;
-- statement break
ALTER TABLE guard_permit_authority_evidence
    ENABLE ALWAYS TRIGGER guard_permit_authority_evidence_immutable_truncate;
