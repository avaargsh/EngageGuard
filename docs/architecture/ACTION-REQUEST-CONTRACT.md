# Guard Submission v1 and Resolved Action — Contract Gate

Status: **Draft / not ratified**. This branch contains pure validation helpers, not a running PEP, PostgreSQL journal, Permit service, or trusted executor.

## Authority split

1. **Runtime** validates the active Run/AgentRelease and sends an *untrusted* `ActionSubmission` (`action-submission.v1`) with a caller-generated, persisted `Idempotency-Key` HTTP header. Runtime **does not supply** `operation_id`.
2. **EngageGuard** authenticates Runtime, verifies Run ownership against authoritative control-plane/runtime state, resolves tenant/subject/actor/workload/agent/delegation and current Capability/ToolBinding/policy/executor audience; rejects stale, revoked, or mismatched references.
3. **EngageGuard** is the **only authority to allocate `operation_id`** on the first accepted submission. A future PostgreSQL transaction must uniquely bind `(authenticated_tenant, submission_key)` to `(submission_digest, operation_id)`. Same key + exact digest returns the same operation, different digest conflicts; race/concurrent request and restart behavior need integration tests.
4. After allocation and trusted resolution, **EngageGuard** builds its internal `ActionRequest` containing `operation_id` and all trusted binding fields. The existing `action-request.v1.schema.json` and Go `ActionRequest` are **internal resolved-action contracts, NOT the Runtime request wire contract**. The resolved record includes actor and workload identity.
5. Guard performs policy/risk/approval and issues an action-bound Permit only after required checks. Trusted Executor validates and atomically claims it before the side effect. OperationJournal persists Intent **before** dispatch, and owns UNKNOWN reconciliation after uncertain outcomes. Runtime owns Run/Step progress, not Guard's external-effect retry.

## Caller wire contract

- `docs/contracts/action-submission.v1.schema.json` has `additionalProperties: false`; deliberately excludes `operation_id`, tenant, subject, agent identity, policy, ToolBinding digest, audience and executor endpoint.
- `ParseActionSubmission` rejects duplicate JSON keys at any depth, invalid/oversized JSON, unknown fields and invalid typed references. The request body limit is 64 KiB; the shared JCS parser also enforces maximum nesting depth 64.
- `ValidateSubmissionKey` validates a bounded ASCII idempotency key; enforcement and authenticated tenant binding must happen in the future server handler.
- `SubmissionDigest` hashes **the exact accepted request bytes** with `engageguard/submission-bytes/v1\\0` domain separation. This digest is only an idempotency replay fingerprint. Byte-different submissions using the same key must conflict, even when semantically equal JSON, until a separately reviewed canonical replay format is accepted.
- **Never use SubmissionDigest for approval, Permit or ActionHash.** It has different domain, purpose, and trust assumptions.

## Replay identity and resolved ActionHash

Two hashes have different purposes and must never be substituted:

- `SubmissionDigest` hashes the exact accepted `ActionSubmission` bytes with `engageguard/submission-bytes/v1\\0`. It is a conservative idempotency fingerprint stored with the tenant-scoped `Idempotency-Key`. Byte-different retries conflict, even when JSON is semantically equivalent. It is **not** an approval or Permit digest.
- `ActionHash` hashes the fully resolved internal `ActionRequest` with `engageguard/action-hash/v1\\0` and RFC 8785 JCS. It is the approval and Permit binding. It includes tenant, subject, actor, workload, Agent/Run/Decision/Plan/Step, Guard-generated operation ID, resolved capability contract digest, resource, canonical arguments, ToolBinding digest, policy version and executor audience.

The standard-library JCS implementation in `internal/action/jcs.go` rejects duplicate object keys, invalid UTF-8 and unpaired surrogate escapes; it bounds nesting and document size; sorts names by UTF-16 code units; and serializes numbers using ECMAScript IEEE-754 rules. Shared numeric vectors live in `docs/contracts/jcs-number-vectors.v1.json`; the resolved ActionRequest golden vector is in `docs/contracts/resolved-action-v1-vectors.json`.

For `workspace.write`, the resolved arguments contain exactly `path` and `content_sha256`. Lexical validation rejects traversal, absolute paths, empty segments, backslashes, NUL and Windows drive-relative/absolute prefixes. This is **not** filesystem confinement. A Trusted Executor must still use root-relative, symlink-safe and TOCTOU-resistant OS operations.

Go verification covers the generic numeric and resolved-action vectors. The separate Go/Python/TypeScript vectors in PR #6 exercise only the fixed all-string `WorkspaceWrite` compatibility shape; they do not prove full generic ActionRequest interoperability. Python and TypeScript parity for the generic resolved-action fixture remains a contract gate.

## Acceptance still required

- Authenticated Guard HTTP endpoint, PostgreSQL operation allocation and `(tenant,key,digest)` conflict/replay atomicity
- Cross-tenant conflict isolation, concurrent claims, restart/replay, and lost-ACK operation lookup
- Trust-source resolution and policy, approval, Permit claim, revocation/fencing
- Intent-before-side-effect journal, trusted executor, external UNKNOWN reconciliation
- Cross-repo ACP/Runtime/Decision/Compute consumers, schema generation, Go/Python/TS hash fixtures

Related blockers: [EngageGuard #3](https://github.com/avaargsh/EngageGuard/issues/3) and [agent-control-panel #3](https://github.com/avaargsh/agent-control-panel/issues/3).
