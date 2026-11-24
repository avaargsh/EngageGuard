# Guard Submission v1 and Resolved Action — Contract Gate

Status: **Draft / not ratified**. This branch contains the generic ActionRequest contract, non-production trusted Issuer and PostgreSQL v16/v17 evidence/claim primitives. It still has no production authority adapters, signed bearer Permit, public issuer endpoint, effect-time PEP or trusted executor.

## Authority split

1. **Runtime** validates the active Run/AgentRelease and sends an *untrusted* `ActionSubmission` (`action-submission.v1`) with a caller-generated, persisted `Idempotency-Key` HTTP header. Runtime **does not supply** `operation_id`.
2. **EngageGuard** authenticates Runtime, verifies Run ownership against authoritative control-plane/runtime state, resolves tenant/subject/actor/workload/agent/delegation and current Capability/ToolBinding/policy/executor audience; rejects stale, revoked, or mismatched references.
3. **EngageGuard** is the **only authority to allocate `operation_id`** on the first accepted submission. A future PostgreSQL transaction must uniquely bind `(authenticated_tenant, submission_key)` to `(submission_digest, operation_id)`. Same key + exact digest returns the same operation, different digest conflicts; race/concurrent request and restart behavior need integration tests.
4. After allocation and trusted resolution, **EngageGuard** builds its internal `ActionRequest` containing `operation_id` and all trusted binding fields. The existing `action-request.v1.schema.json` and Go `ActionRequest` are **internal resolved-action contracts, NOT the Runtime request wire contract**. The resolved record includes actor and workload identity.
5. Guard performs policy/risk/approval and issues an action-bound Permit only after required checks. Trusted Executor validates and atomically claims it before the side effect. OperationJournal persists Intent **before** dispatch, and owns UNKNOWN reconciliation after uncertain outcomes. Runtime owns Run/Step progress, not Guard's external-effect retry.

## Current issuer/claim implementation boundary (non-production)

The current branch implements a generic `action.ActionRequest` v1 issuer contract, not the legacy fixed-shape `WorkspaceWrite` v0.1 contract:

- `issuer.Service.Issue` computes the normative RFC 8785 `ActionHash` over the complete resolved ActionRequest and requires the fresh authority result to match tenant, Run, Decision, Plan ID/hash, Step, Capability ID/version/contract digest, ToolBinding, policy, audience and expiry.
- The opaque `PermitDraft` carries the resolved identity plus current Runtime Attempt, Decision Turn, Approval reference and Risk revision.
- PostgreSQL v16 stores immutable source-bound Permit evidence. v17 adds Decision/Plan/Step/Capability/Resource fields. Existing v16 rows retain NULL v17 fields; no missing source evidence is fabricated.
- `ClaimResolvedActionIntent` re-hashes the supplied ActionRequest, compares it to the Permit and all immutable v17 evidence, and atomically creates one DispatchIntent/Attempt/Audit. The legacy WorkspaceWrite claim path cannot claim an ActionRequest v1 Permit.
- The returned ScopedPermit is an internal database result, not a signed bearer token. A committed DispatchIntent is not permission to call a provider.

This slice has no live Run/Decision/ACP/Policy/Approval/Risk adapters. Fake authorities exist only in tests. No provider side effect is enabled.

## Caller wire contract

- `docs/contracts/action-submission.v1.schema.json` has `additionalProperties: false`; capability is only an untrusted `id/version` selector. It deliberately excludes capability contract digests, `operation_id`, tenant, subject, actor, workload, policy, ToolBinding digest, audience, executor endpoint and supplied ActionHash.
- `ParseActionSubmission` rejects duplicate JSON keys at any depth, invalid/oversized JSON, unknown fields and invalid typed references. The request body limit is 64 KiB; the shared JCS parser also enforces maximum nesting depth 64. Capability `contract_sha256` is rejected at this boundary and resolved by Guard from the authoritative capability registry.
- `ValidateSubmissionKey` validates a bounded ASCII idempotency key; enforcement and authenticated tenant binding must happen in the future server handler.
- `SubmissionDigest` hashes **the exact accepted request bytes** with `engageguard/submission-bytes/v1\\0` domain separation. This digest is only an idempotency replay fingerprint. Byte-different submissions using the same key must conflict, even when semantically equal JSON, until a separately reviewed canonical replay format is accepted.
- **Never use SubmissionDigest for approval, Permit or ActionHash.** It has different domain, purpose, and trust assumptions.

## Replay identity and resolved ActionHash

Two hashes have different purposes and must never be substituted:

- `SubmissionDigest` hashes the exact accepted `ActionSubmission` bytes with `engageguard/submission-bytes/v1\\0`. It is a conservative idempotency fingerprint stored with the tenant-scoped `Idempotency-Key`. Byte-different retries conflict, even when JSON is semantically equivalent. It is **not** an approval or Permit digest.
- `ActionHash` hashes the fully resolved internal `ActionRequest` with `engageguard/action-hash/v1\\0` and RFC 8785 JCS. It is the approval and Permit binding. It includes tenant, subject, actor, workload, Agent/Run/Decision/Plan/Step, Guard-generated operation ID, resolved capability contract digest, resource, canonical arguments, ToolBinding digest, policy version and executor audience.

The standard-library JCS implementation in `internal/action/jcs.go` rejects duplicate object keys, invalid UTF-8 and unpaired surrogate escapes; it bounds nesting and document size; sorts names by UTF-16 code units; and serializes numbers using ECMAScript IEEE-754 rules. Shared numeric vectors live in `docs/contracts/jcs-number-vectors.v1.json`; the resolved ActionRequest golden vector is in `docs/contracts/resolved-action-v1-vectors.json`.

For `workspace.write`, the resolved arguments contain exactly `path` and `content_sha256`. Lexical validation rejects traversal, absolute paths, empty segments, backslashes, NUL and Windows drive-relative/absolute prefixes. This is **not** filesystem confinement. A Trusted Executor must still use root-relative, symlink-safe and TOCTOU-resistant OS operations.

CI verifies the shared generic resolved-ActionRequest hash and numeric vectors in Go, Python and TypeScript. A separate compatibility check covers the historical fixed all-string `WorkspaceWrite` v0.1 subset; that compatibility fixture is not a substitute for the generic ActionRequest vector.

## Acceptance still required

- Authenticated Guard HTTP endpoint, PostgreSQL operation allocation and `(tenant,key,digest)` conflict/replay atomicity
- Cross-tenant conflict isolation, concurrent claims, restart/replay, and lost-ACK operation lookup
- Production mTLS adapters for current Runtime Run/Attempt, Decision Plan/Step, ACP Capability/ToolBinding, Policy, Approval and Risk sources
- Signed bearer Permit/JTI issuance, revocation and policy revalidation at claim and effect time
- ActionRequest v1-aware pre-effect ledger and independently deployed Trusted Executor PEP
- Intent-before-side-effect journal, provider idempotency/receipt inspection, external UNKNOWN reconciliation and crash recovery
- Cross-repo ACP/Runtime/Decision/Compute consumers, schema generation, Go/Python/TS hash fixtures

Related blockers: [EngageGuard #3](https://github.com/avaargsh/EngageGuard/issues/3) and [agent-control-panel #3](https://github.com/avaargsh/agent-control-panel/issues/3).
