-- Immutable v2: admission intent snapshot only, not an approved ActionRequest.
-- New migrations are appended; the released v1 schema.sql is not edited.
ALTER TABLE guard_action_operations
    ADD CONSTRAINT guard_ops_snapshot_binding_uk
    UNIQUE (tenant_id, submission_key, submission_digest, operation_id);

-- statement break
CREATE TABLE guard_accepted_submission_snapshots (
    tenant_id TEXT NOT NULL,
    operation_id UUID NOT NULL,
    submission_key TEXT NOT NULL,
    submission_digest TEXT NOT NULL,
    submission_bytes BYTEA NOT NULL
        CONSTRAINT guard_snapshot_bytes_length_check
        CHECK (octet_length(submission_bytes) BETWEEN 1 AND 65536),
    persisted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT guard_accepted_submission_snapshots_pkey
        PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT guard_snapshot_operation_binding_fk
        FOREIGN KEY (tenant_id, submission_key, submission_digest, operation_id)
        REFERENCES guard_action_operations (tenant_id, submission_key, submission_digest, operation_id)
);

-- statement break
CREATE FUNCTION guard_reject_snapshot_mutation() RETURNS trigger
LANGUAGE plpgsql AS $guard_snapshot$
BEGIN
    RAISE EXCEPTION 'accepted Guard submission snapshots are immutable';
END;
$guard_snapshot$;

-- statement break
CREATE TRIGGER guard_snapshot_immutable_row
BEFORE UPDATE OR DELETE ON guard_accepted_submission_snapshots
FOR EACH ROW EXECUTE FUNCTION guard_reject_snapshot_mutation();

-- statement break
CREATE TRIGGER guard_snapshot_immutable_truncate
BEFORE TRUNCATE ON guard_accepted_submission_snapshots
FOR EACH STATEMENT EXECUTE FUNCTION guard_reject_snapshot_mutation();

-- statement break
ALTER TABLE guard_accepted_submission_snapshots
    ENABLE ALWAYS TRIGGER guard_snapshot_immutable_row;

-- statement break
ALTER TABLE guard_accepted_submission_snapshots
    ENABLE ALWAYS TRIGGER guard_snapshot_immutable_truncate;
