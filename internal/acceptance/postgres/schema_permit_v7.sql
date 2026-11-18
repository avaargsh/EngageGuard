-- v5: immutable one-time tenant- and Permit-bound revocation evidence.
-- A revoke is never an executor receipt, final dispatch outcome or Permit.
CREATE TABLE guard_permit_revocations (
    revocation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    permit_id UUID NOT NULL,
    evidence_ref TEXT NOT NULL CHECK (length(evidence_ref) BETWEEN 1 AND 128),
    reason TEXT NOT NULL CHECK (reason IN ('POLICY_REVOKED','SECURITY_RESPONSE','HUMAN_REVOKED')),
    prior_state TEXT NOT NULL CHECK (prior_state IN ('ISSUED','CLAIMED')),
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT guard_revocation_one_per_permit UNIQUE (tenant_id, permit_id),
    CONSTRAINT guard_revocation_exact_permit_fk
        FOREIGN KEY (tenant_id, permit_id)
        REFERENCES guard_permits (tenant_id, permit_id) ON DELETE RESTRICT
);
