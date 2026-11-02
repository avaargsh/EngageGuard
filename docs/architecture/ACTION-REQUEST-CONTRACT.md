# ActionRequest v1 and Operation identity

Status: protocol implementation candidate, 2026-11-03. Protected effects remain disabled until durable idempotency, Permit claim, trusted execution and UNKNOWN recovery are integration-tested.

## Ownership

Runtime creates and durably retains one stable `Idempotency-Key` per logical submission before the first HTTP request. Retries reuse the same key. The request body contains only untrusted intent: Agent/Run/Decision/Plan/Step references, capability selector, resource reference and arguments.

EngageGuard derives tenant, subject, actor and workload from authenticated context. It verifies the references, resolves the capability contract and ToolBinding, evaluates current policy, generates `operation_id`, and owns the Action Operation, approval, Permit, executor attempt and Receipt. Runtime only projects resulting state into its Run/Step.

## ActionRequest body

`docs/contracts/action-request.v1.schema.json` is the wire schema. Unknown fields are rejected. Accepted fields are `schema_version`, `agent_id`, `run_id`, `decision_id`, `plan_id`, `plan_hash`, `step_id`, `capability.id`, `capability.version`, `resource_ref`, and `arguments`.

The body must not contain `tenant_id`, `subject_id`, `actor_id`, `workload_id`, `operation_id`, `tool_binding_digest`, `policy_version`, `audience`, `attempt_id`, or `action_hash`. These are Guard-derived or Guard-owned values.

`Idempotency-Key` is a required HTTP header, not a body property. It must be 1–128 visible ASCII bytes without whitespace or control characters and is scoped by authenticated tenant.

## RequestHash and replay contract

```text
"engageguard/request-hash/v1\\0" || JCS({
  "authenticated_context": { tenant_id, subject_id, actor_id, workload_id },
  "request": ActionRequest
})
```

RequestHash binds the normalized request to authenticated identity. It excludes the idempotency key (the index key) and server-generated `operation_id`. The persistent store must enforce uniqueness on `(tenant_id, idempotency_key)`; a read-then-write check is unsafe. Persist RequestHash, generated operation ID, initial state and durable intent before any external effect.

| Condition | Required behavior |
|---|---|
| New tenant + key | Atomically create one Operation; return 202 with server-generated operation ID |
| Same tenant + key + same RequestHash | Return the existing operation ID and current state; never dispatch again |
| Same tenant + key + different RequestHash | Return 409 `IDEMPOTENCY_KEY_REUSED`; create no second Operation |
| Existing Operation is UNKNOWN/RECONCILING | Return current state; never redispatch while the result is ambiguous |

A lost acknowledgement is recovered by resubmitting the exact body with the exact same key. Distinct intended effects require distinct keys. Key/tombstone retention must outlive all retry and dead-letter replay paths.

## CanonicalAction and ActionHash

After authentication and trusted resolution, Guard creates CanonicalAction with authenticated tenant/subject/actor/workload, validated Agent/Run/Decision/Plan/Step references, server-generated operation ID, resolved capability ID/version/contract digest, exact target, canonical arguments, ToolBinding digest, current policy version and executor audience.

```text
"engageguard/action-hash/v1\\0" || JCS(CanonicalAction)
```

ActionHash binds approval and Permit to the exact resolved action. Any change to identity, delegation, workload, Run/Plan/Step, operation, capability contract, target, arguments, ToolBinding, policy or audience changes the digest. Agent/plugin-supplied hashes are never trusted. Approval cannot override DENY; revocation, expiry and one-time Permit claim remain independent checks.

RequestHash and ActionHash are distinct: the first detects replay/conflicting key reuse; the second binds execution authority to the final trusted action.

## Canonicalization and workspace.write

JCS requirements: UTF-16 property ordering; ECMAScript IEEE-754 binary64 number formatting; duplicate-key rejection at all depths; valid UTF-8; rejection of unpaired surrogate escapes; maximum nesting depth 64; maximum arguments size 64 KiB. Strings are not Unicode-normalized, and HTML-specific escaping is not applied.

Shared fixtures: `docs/contracts/jcs-number-vectors.v1.json` and `docs/contracts/action-hash-vectors.v1.json`. Go tests load these files; Python and TypeScript parity checks are still required before cross-language ratification.

The resolved `workspace.write` v1 arguments contain exactly `path` and `content_sha256`. The path check rejects absolute, noncanonical, traversal, empty-segment, backslash, NUL and Windows drive-prefixed paths. This is lexical validation only; it does not provide filesystem confinement or prevent symlink/TOCTOU races. A Trusted Executor must use root-relative race-resistant OS operations after Permit verification and durable intent.

## Operation lifecycle and explicit non-goals

`PENDING → CLAIMED → DISPATCHING → SUCCEEDED | FAILED_CONFIRMED | UNKNOWN`

`UNKNOWN → RECONCILING → SUCCEEDED | FAILED_CONFIRMED | MANUAL_REVIEW`

FAILED_CONFIRMED requires authoritative evidence. Lost acknowledgement is UNKNOWN, never implicit failure or permission to retry.

This branch implements strict ActionRequest decoding, RequestHash, trusted CanonicalAction ActionHash, JCS and shared vectors. It does not yet implement PostgreSQL idempotency, policy evaluation, human approval, signed Permit, atomic nonce claim, Trusted Executor, persistent Operation Journal, UNKNOWN reconciliation or an end-to-end HTTP endpoint. Do not enable protected execution until those gates pass.
