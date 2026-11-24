-- v17: bind Permit authority evidence to the canonical resolved ActionRequest v1.
-- Existing v16 rows remain explicitly legacy (all v17 columns NULL); they are
-- never upgraded by guessing Run/Decision/Plan/Capability facts.
ALTER TABLE guard_permit_authority_evidence
    ADD COLUMN decision_id TEXT,
    ADD COLUMN plan_id TEXT,
    ADD COLUMN plan_hash TEXT,
    ADD COLUMN step_id TEXT,
    ADD COLUMN capability_id TEXT,
    ADD COLUMN capability_version TEXT,
    ADD COLUMN capability_contract_sha256 TEXT,
    ADD COLUMN resource_ref TEXT;
-- statement break
ALTER TABLE guard_permit_authority_evidence
    ADD CONSTRAINT guard_permit_authority_action_request_v17_all_or_none_check
    CHECK (
        (decision_id IS NULL) = (plan_id IS NULL)
        AND (decision_id IS NULL) = (plan_hash IS NULL)
        AND (decision_id IS NULL) = (step_id IS NULL)
        AND (decision_id IS NULL) = (capability_id IS NULL)
        AND (decision_id IS NULL) = (capability_version IS NULL)
        AND (decision_id IS NULL) = (capability_contract_sha256 IS NULL)
        AND (decision_id IS NULL) = (resource_ref IS NULL)
    );
-- statement break
ALTER TABLE guard_permit_authority_evidence
    ADD CONSTRAINT guard_permit_authority_action_request_v17_decision_check
    CHECK (decision_id IS NULL OR (
        length(decision_id) BETWEEN 1 AND 512
        AND decision_id !~ '[[:cntrl:][:space:]]'
    ));
-- statement break
ALTER TABLE guard_permit_authority_evidence
    ADD CONSTRAINT guard_permit_authority_action_request_v17_plan_check
    CHECK (plan_id IS NULL OR (
        length(plan_id) BETWEEN 1 AND 512
        AND plan_id !~ '[[:cntrl:][:space:]]'
    ));
-- statement break
ALTER TABLE guard_permit_authority_evidence
    ADD CONSTRAINT guard_permit_authority_action_request_v17_plan_hash_check
    CHECK (plan_hash IS NULL OR plan_hash ~ '^[0-9a-f]{64}$');
-- statement break
ALTER TABLE guard_permit_authority_evidence
    ADD CONSTRAINT guard_permit_authority_action_request_v17_step_check
    CHECK (step_id IS NULL OR (
        length(step_id) BETWEEN 1 AND 512
        AND step_id !~ '[[:cntrl:][:space:]]'
    ));
-- statement break
ALTER TABLE guard_permit_authority_evidence
    ADD CONSTRAINT guard_permit_authority_action_request_v17_capability_check
    CHECK (capability_id IS NULL OR (
        length(capability_id) BETWEEN 1 AND 512
        AND capability_id !~ '[[:cntrl:][:space:]]'
    ));
-- statement break
ALTER TABLE guard_permit_authority_evidence
    ADD CONSTRAINT guard_permit_authority_action_request_v17_capability_version_check
    CHECK (capability_version IS NULL OR (
        length(capability_version) BETWEEN 1 AND 512
        AND capability_version !~ '[[:cntrl:][:space:]]'
    ));
-- statement break
ALTER TABLE guard_permit_authority_evidence
    ADD CONSTRAINT guard_permit_authority_action_request_v17_capability_contract_check
    CHECK (capability_contract_sha256 IS NULL OR capability_contract_sha256 ~ '^[0-9a-f]{64}$');
-- statement break
ALTER TABLE guard_permit_authority_evidence
    ADD CONSTRAINT guard_permit_authority_action_request_v17_resource_check
    CHECK (resource_ref IS NULL OR (
        length(resource_ref) BETWEEN 1 AND 512
        AND resource_ref !~ '[[:cntrl:][:space:]]'
    ));
-- Existing v16 evidence may predate the printable-ASCII contract. Do not
-- fabricate or rewrite those rows during migration. NOT VALID preserves them,
-- while PostgreSQL enforces this constraint on every new or changed row.
ALTER TABLE guard_permit_authority_evidence
    ADD CONSTRAINT guard_permit_authority_v17_ascii_identifiers_check
    CHECK (
        run_id COLLATE "C" ~ '^[!-~]{1,512}$'
        AND runtime_attempt_id COLLATE "C" ~ '^[!-~]{1,512}$'
        AND turn_id COLLATE "C" ~ '^[!-~]{1,512}$'
        AND approval_ref COLLATE "C" ~ '^[!-~]{1,512}$'
        AND risk_revision COLLATE "C" ~ '^[!-~]{1,512}$'
        AND audience COLLATE "C" ~ '^[!-~]{1,512}$'
        AND policy_version COLLATE "C" ~ '^[!-~]{1,512}$'
        AND issued_by COLLATE "C" ~ '^[!-~]{1,512}$'
        AND (decision_id IS NULL OR decision_id COLLATE "C" ~ '^[!-~]{1,512}$')
        AND (plan_id IS NULL OR plan_id COLLATE "C" ~ '^[!-~]{1,512}$')
        AND (step_id IS NULL OR step_id COLLATE "C" ~ '^[!-~]{1,512}$')
        AND (capability_id IS NULL OR capability_id COLLATE "C" ~ '^[!-~]{1,512}$')
        AND (capability_version IS NULL OR capability_version COLLATE "C" ~ '^[!-~]{1,512}$')
        AND (resource_ref IS NULL OR resource_ref COLLATE "C" ~ '^[!-~]{1,512}$')
    ) NOT VALID;
