-- Guard v8 is additive. All v1-v7 source checksums remain unchanged.
-- Reuse the existing unconditional immutable snapshot trigger function.
-- Ordinary runtime SQL roles have no DDL or replication-role privileges.
-- Snapshot, Permit and provider outcome ownership remains separate.
CREATE TRIGGER guard_execution_audit_immutable_row
BEFORE UPDATE OR DELETE ON guard_execution_audit
FOR EACH ROW EXECUTE FUNCTION guard_reject_snapshot_mutation();

CREATE TRIGGER guard_execution_audit_immutable_truncate
BEFORE TRUNCATE ON guard_execution_audit
FOR EACH STATEMENT EXECUTE FUNCTION guard_reject_snapshot_mutation();

CREATE TRIGGER guard_operation_unknown_events_immutable_row
BEFORE UPDATE OR DELETE ON guard_operation_unknown_events
FOR EACH ROW EXECUTE FUNCTION guard_reject_snapshot_mutation();

CREATE TRIGGER guard_operation_unknown_events_immutable_truncate
BEFORE TRUNCATE ON guard_operation_unknown_events
FOR EACH STATEMENT EXECUTE FUNCTION guard_reject_snapshot_mutation();

CREATE TRIGGER guard_permit_revocations_immutable_row
BEFORE UPDATE OR DELETE ON guard_permit_revocations
FOR EACH ROW EXECUTE FUNCTION guard_reject_snapshot_mutation();

CREATE TRIGGER guard_permit_revocations_immutable_truncate
BEFORE TRUNCATE ON guard_permit_revocations
FOR EACH STATEMENT EXECUTE FUNCTION guard_reject_snapshot_mutation();

ALTER TABLE guard_execution_audit ENABLE ALWAYS TRIGGER guard_execution_audit_immutable_row;
ALTER TABLE guard_execution_audit ENABLE ALWAYS TRIGGER guard_execution_audit_immutable_truncate;
ALTER TABLE guard_operation_unknown_events ENABLE ALWAYS TRIGGER guard_operation_unknown_events_immutable_row;
ALTER TABLE guard_operation_unknown_events ENABLE ALWAYS TRIGGER guard_operation_unknown_events_immutable_truncate;
ALTER TABLE guard_permit_revocations ENABLE ALWAYS TRIGGER guard_permit_revocations_immutable_row;
ALTER TABLE guard_permit_revocations ENABLE ALWAYS TRIGGER guard_permit_revocations_immutable_truncate;
