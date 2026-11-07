# EngageGuard Implementation Plan

## Stage A — Caller and resolved-action protocol (parent PR #5)

1. Freeze caller-only ActionSubmission v1 and the HTTP Idempotency-Key contract.
2. Freeze Guard-internal ActionRequest with Guard-generated operation_id and authenticated identity / capability / ToolBinding / policy / audience bindings.
3. Keep SubmissionDigest (exact submission bytes) exclusively for tenant-scoped idempotency replay; never use it as approval or Permit authority.
4. Use RFC 8785 JCS + engageguard/action-hash/v1\0 over the fully resolved ActionRequest for approval and Permit binding.
5. Publish Go golden vectors and keep protected execution disabled until persistence and enforcement are complete.

Exit evidence: strict request decoding, duplicate-key/Unicode/depth tests, complete identity/action mutation tests, shared JCS number and resolved-action vectors, Go 1.26 CI.

## Stage B — Authenticated PEP and durable idempotency

1. Authenticate Runtime workload identity and derive tenant/subject/actor/workload from trusted principal resolution.
2. Verify Run/Plan/Step ownership and resolve capability, target, ToolBinding and policy from trusted authorities.
3. Persist unique (tenant_id, idempotency_key), exact-byte SubmissionDigest and server-generated operation_id atomically.
4. Return the existing Operation on same-key/same-digest replay; return 409 on same-key/different-digest.
5. Persist operation intent and outbox in the acceptance transaction before any external request.

Exit evidence: real HTTP replay/conflict tests, tenant isolation, lost-ACK lookup and process-restart recovery against PostgreSQL.

## Stage C — Authorization and Permit

1. Implement deny-by-default policy and explicit risk assessment.
2. Bind human approval to the exact resolved ActionHash.
3. Issue a short-lived, audience-bound signed Permit only after ALLOW and required approval.
4. Atomically claim the Permit nonce and reject replay, expiry, revocation, action mismatch or audience mismatch.

Exit evidence: concurrent claim tests, permit tampering, revocation/expiry, cross-operation ledger constraints and trusted issuer validation.

## Stage D — Trusted execution and recovery

1. Implement Workspace Executor with root-relative, symlink-safe and TOCTOU-resistant filesystem operations.
2. Persist operation/attempt/receipt state and enforce the operation state machine.
3. Move ambiguous outcomes to UNKNOWN and reconcile against authoritative resource state; never blindly replay.
4. Add crash-window, restart, concurrent submission and adversarial integration tests.

Exit gate: no authorization/no execution; one Permit cannot be consumed twice; modified approved action is denied; ambiguous side effects never blindly replay.
