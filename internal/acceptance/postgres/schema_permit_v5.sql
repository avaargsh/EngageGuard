-- Immutable v3 migration: enforce a single authorization identity across
-- Permit -> Intent -> Audit even when a caller can write directly to tables.
-- This migration intentionally validates all existing rows. On inconsistency
-- the transaction fails closed without stamping migration version 3.
ALTER TABLE guard_permits
    ADD CONSTRAINT guard_permit_resolved_identity_uq
    UNIQUE (tenant_id, operation_id, permit_id, action_hash, binding_digest);

ALTER TABLE guard_operation_intents
    ADD CONSTRAINT guard_intent_resolved_permit_fk
    FOREIGN KEY (tenant_id, operation_id, permit_id, action_hash, binding_digest)
    REFERENCES guard_permits
        (tenant_id, operation_id, permit_id, action_hash, binding_digest)
    ON DELETE RESTRICT;

ALTER TABLE guard_operation_intents
    ADD CONSTRAINT guard_intent_audit_identity_uq
    UNIQUE (tenant_id, operation_id, permit_id, attempt_id, action_hash);

ALTER TABLE guard_execution_audit
    ADD CONSTRAINT guard_audit_resolved_intent_fk
    FOREIGN KEY (tenant_id, operation_id, permit_id, attempt_id, action_hash)
    REFERENCES guard_operation_intents
        (tenant_id, operation_id, permit_id, attempt_id, action_hash)
    ON DELETE RESTRICT;
