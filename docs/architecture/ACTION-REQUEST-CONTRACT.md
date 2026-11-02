# Guard Submission v1 and Resolved Action — Contract Gate

Status: **Draft / not ratified**. This branch contains pure validation helpers, not a running PEP, PostgreSQL journal, Permit service, or trusted executor.

## Authority split

1. **Runtime** validates the active Run/AgentRelease and sends an *untrusted* `ActionSubmission` (`action-submission.v1`) with a caller-generated, persisted `Idempotency-Key` HTTP header. Runtime **does not supply** `operation_id`.
2. **EngageGuard** authenticates Runtime, verifies Run ownership against the authoritative control-plane/runtime state, resolves tenant/subject/agent/delegation and current Capability/ToolBinding/policy/executor audience; rejects stale, revoked, or mismatched references.
3. **EngageGuard** is the **only authority to allocate `operation_id`** on the first accepted submission. A future PostgreSQL transaction must uniquely bind `(authenticated_tenant, submission_key)` to `(submission_digest, operation_id)`. Same key + exact digest returns the same operation, different digest conflicts; race/concurrent request and restart behavior need integration tests.
4. After allocation and trusted resolution, **EngageGuard** builds its internal `ActionRequest` containing `operation_id` and all trusted binding fields. The existing `action-request.v1.schema.json` and Go `ActionRequest` are **internal resolved-action drafts, NOT the Runtime request wire contract**.
5. Guard performs policy/risk/approval and issues an action-bound Permit only after required checks. Trusted Executor validates and atomically claims it before the side effect. OperationJournal persists Intent **before** dispatch, and owns UNKNOWN reconciliation after uncertain outcomes. Runtime owns Run/Step progress, not Guard's external-effect retry.

## Caller wire contract

- `docs/contracts/action-submission.v1.schema.json` has `additionalProperties: false`; deliberately excludes `operation_id`, tenant, subject, agent identity, policy, ToolBinding digest, audience and executor endpoint.
- `ParseActionSubmission` rejects duplicate JSON keys at any depth, invalid/oversized JSON, unknown fields and invalid typed references. The request body limit is 64 KiB.
- `ValidateSubmissionKey` validates a bounded ASCII idempotency key; enforcement and authenticated tenant binding must happen in the future server handler.
- `SubmissionDigest` hashes **the exact accepted request bytes** with `engageguard/submission-bytes/v1\\0` domain separation. This digest is only an idempotency replay fingerprint. Byte-different submissions using the same key must conflict, even when semantically equal JSON, until a separately reviewed canonical replay format is accepted.
- **Never use SubmissionDigest for approval, Permit or ActionHash.** It has different domain, purpose, and trust assumptions.

## ActionHash conformance blocker

The current general-purpose `ActionRequest.ActionHash` uses Go `json.Marshal` with lexical number preservation. It **does not implement RFC 8785 JCS** for arbitrary JSON numbers/Unicode and **must not be treated as a normative cross-language Permit binding**. The narrower `WorkspaceWrite` helper already uses a versioned all-string JCS subset, but those two hash contracts are not interchangeable.

Before Permit integration or PR #2 promotion, ratify a *single* domain separator and JCS implementation using shared Go/Python/TypeScript golden vectors (IEEE-754 numbers, UTF-16 property order, escaping, Unicode, tampering and mutation), then update the resolved ActionRequest code and schema together. Prefer a vetted RFC 8785 implementation over rolling a general-purpose serializer.

## Acceptance still required

- Authenticated Guard HTTP endpoint, PostgreSQL operation allocation and `(tenant,key,digest)` conflict/replay atomicity
- Cross-tenant conflict isolation, concurrent claims, restart/replay, and lost-ACK operation lookup
- Trust-source resolution and policy, approval, Permit claim, revocation/fencing
- Intent-before-side-effect journal, trusted executor, external UNKNOWN reconciliation
- Cross-repo ACP/Runtime/Decision/Compute consumers, schema generation, Go/Python/TS hash fixtures

Related blockers: [EngageGuard #3](https://github.com/avaargsh/EngageGuard/issues/3) and [agent-control-panel #3](https://github.com/avaargsh/agent-control-panel/issues/3).
