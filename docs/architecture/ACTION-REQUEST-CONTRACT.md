# ActionRequest v1 — Guard-owned authorization contract

Status: contract and canonical ActionHash reference implementation; no Permit issuance or Trusted Executor implementation is claimed.

## Ownership

- Decision emits an immutable PlanCandidate and PlanHash. It does not construct an executable request or authorize a side effect.
- Runtime validates the plan against the active Run and AgentRelease, resolves one PlanStep and its inputs, and persists a stable `Idempotency-Key` before submission. Runtime **does not** create an EngageGuard `operation_id`.
- EngageGuard validates the authenticated, strictly decoded submission and transactionally claims the tenant-scoped `Idempotency-Key` and canonical request digest before assigning a stable server-issued `operation_id`. It re-resolves the Capability/ToolBinding, evaluates policy and approval, and issues or denies a Permit. This is a **proposed** lifecycle; no durable handler is implemented in this branch.
- Trusted Executor revalidates and consumes a one-time, action-bound Permit immediately before the side effect. OperationJournal owns operation state and UNKNOWN reconciliation.

## Required binding

ActionRequest v1 submission binds tenant, subject, agent, Run, Decision, Plan, PlanHash, Step, exact Capability ID/version/contract digest, resource target, arguments, trusted ToolBinding digest, policy version and executor audience. It **must not** contain `operation_id`; only Guard-owned resolved action/Permit/receipt records may bind the server-generated ID. The `Idempotency-Key` is a separate HTTP header, not an action field.

No endpoint, provider secret, bearer token or executable code is accepted in the ActionRequest contract. The tenant and identity fields are assertions to compare against the authenticated caller and authoritative Run; they are not trusted merely because they appear in JSON.

## Canonicalization

- Arguments must be a JSON object, no larger than 64 KiB.
- Duplicate object keys are rejected at every nesting depth.
- The current generic `ActionRequest` hashing uses Go JSON re-encoding, **not** full RFC 8785/JCS (notably JSON numbers and Unicode property order). It must not be used as an approved cross-language authorization hash until shared JCS fixtures pass.
- The hash covers all identity and authorization binding fields plus the canonical arguments.
- A change to any bound field produces a different ActionHash. A Permit must reference the exact hash, audience, tenant, subject, expiry and nonce.

## Required execution order

1. Runtime persists a stable Guard submission key and sends `Idempotency-Key` with one ActionRequest for one PlanStep; the body contains no `operation_id`.
2. Guard rejects unknown/duplicate JSON keys, authenticates Runtime and verifies tenant/Agent/Run/Release ownership; it atomically claims (tenant, key, digest), assigning `operation_id` once. Same-key/different-digest conflicts; unresolved in-flight requests are not redispatched.
3. Guard re-resolves capability version, schema digest, tool binding and current policy; stale or revoked references fail closed.
4. Guard computes ActionHash over the normalized action and obtains any required human approval bound to that hash.
5. Guard issues a short-lived, audience-bound, single-use Permit only after approval and policy checks.
6. Trusted Executor validates signature, audience, expiry, action hash, subject, tenant and nonce; atomically claims the nonce before executing.
7. OperationJournal persists STARTED/COMPLETED/FAILED/UNKNOWN. Lost ACK or uncertain provider result becomes UNKNOWN and is reconciled against the external resource; never blind-retried.
8. Runtime receives a signed/verified outcome reference and updates its own Step/Run state.

## Current implementation boundary

This branch implements ActionRequest validation, strict canonical argument parsing and deterministic SHA-256 ActionHash with mutation tests. The earlier WorkspaceWrite-specific hash helper remains as a narrower example. Permit signing, one-time nonce storage, policy evaluation, filesystem/provider execution and UNKNOWN journal are not implemented by this PR and must not be represented as complete.

## P0 status and incompatibility

The ingress parser and submission schema are implemented here but the transactional idempotency claim, Guard-issued operation identity, authoritative JCS ActionHash, one-time Permit and UNKNOWN recovery are **not** implemented. The fixed-string `WorkspaceWrite` internal hash binds a **Guard-issued** operation ID after admission; it is not the caller's ActionRequest and must not be used to justify accepting a client-generated ID. ACP G03 remains blocked until shared golden vectors, real PostgreSQL concurrency/ACK-loss tests and cross-language consumers pass.
