-- v3: enforce immutable accepted snapshots even under replica-mode SQL.
-- PostgreSQL ENABLE TRIGGER (origin-only) does not fire in replica mode.
-- Forward-only: preserve the exact v1/v2 migration bytes and checksums.
-- Ordinary Guard writers must not hold SET session_replication_role or DDL rights.
-- A privileged superuser/table owner still requires independent operational controls.
ALTER TABLE guard_accepted_submission_snapshots
    ENABLE ALWAYS TRIGGER guard_snapshot_immutable_row;

-- statement break
ALTER TABLE guard_accepted_submission_snapshots
    ENABLE ALWAYS TRIGGER guard_snapshot_immutable_truncate;
