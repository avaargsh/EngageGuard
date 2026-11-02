# Action Contract v0.1

ActionEnvelope includes authenticated subject, actor/workload identity, tenant, capability binding/version, operation_id, target resource, canonical arguments, risk context and trace/correlation references. Identity fields supplied by caller are assertions only and must be checked against authenticated context.

CanonicalAction is schema-validated, default-expanded and normalized before hashing. ActionHash binds schema version, subject/delegation, capability id/version, target, canonical arguments, policy/binding digest and audience.

Decision: ALLOW | DENY | REQUIRE_APPROVAL. Approval never overrides DENY. Permit is one-time, short-lived, audience-bound and operation-bound. Executor verifies Permit, ActionHash, binding digest, expiry and claim before effect.

Operation states: PENDING → CLAIMED → RUNNING → SUCCEEDED | FAILED | UNKNOWN. UNKNOWN requires provider inspection/reconciliation before retry. Receipt includes operation_id, attempt_id, action_hash, executor identity, target reference, result digest, timestamps and verification outcome.
