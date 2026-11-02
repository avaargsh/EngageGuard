# EngageGuard Implementation Plan

## Stage A — Protocol primitives (current PR #2)

1. Freeze caller-only ActionRequest v1 and the HTTP Idempotency-Key contract.
2. Separate RequestHash (submission identity) from ActionHash (trusted resolved action).
3. Publish RFC 8785 JCS and shared cross-language golden vectors.
4. Keep all protected execution disabled while persistence and enforcement remain absent.

Exit evidence: strict request decoding, identity binding, canonical vectors, mutation tests and Go CI.

## Stage B — PEP and durable idempotency

1. Authenticate Runtime workload identity and derive tenant/subject/actor/workload context.
2. Verify Run/Plan/Step ownership and resolve capability, target, ToolBinding and policy from trusted sources.
3. Persist unique (tenant_id, idempotency_key), RequestHash and server-generated operation_id atomically.
4. Return the existing Operation on same-key/same-hash replay; return 409 on same-key/different-hash.
5. Persist operation intent and outbox before any external request.

Exit evidence: real HTTP replay/conflict tests, lost-ACK tests and process-restart recovery.

## Stage C — Authorization and Permit

1. Implement deny-by-default policy and explicit risk assessment.
2. Bind human approval to the exact ActionHash.
3. Issue short-lived audience-bound signed Permit only after ALLOW and required approval.
4. Atomically claim the Permit nonce and reject replay, expiry, revocation or audience mismatch.

Exit evidence: concurrent claim tests and tamper/revocation/expiry coverage.

## Stage D — Trusted execution and recovery

1. Implement Workspace Executor with root-relative, symlink-safe and TOCTOU-resistant filesystem operations.
2. Persist operation/attempt/receipt state and enforce the operation state machine.
3. Move ambiguous outcomes to UNKNOWN and reconcile against authoritative resource state; never blindly replay.
4. Add crash-window, restart, concurrent submission and adversarial integration tests.

Exit gate: no authorization/no execution; one Permit cannot be consumed twice; modified approved action is denied; ambiguous side effects never blindly replay.
