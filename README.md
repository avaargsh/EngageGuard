# EngageGuard

Go-based Action Authorization and Trusted Execution Guard for Agent systems.

## Product boundary

EngageGuard is intended to own canonical action resolution, authorization decisions, risk evaluation, approval requests, one-time permits, protected Action Operations, operation receipts and audit evidence. It does not own Agent Run or Task lifecycle.

## Architecture target

- Go API / Policy Enforcement Point (PEP).
- PostgreSQL-backed idempotency, approval, Permit and operation records.
- A separately deployed Trusted Executor for the first `workspace.write` Golden Path.
- RequestHash binds a caller submission to its authenticated context and supports safe idempotent replay.
- ActionHash binds approval and Permit to the exact trusted, resolved CanonicalAction.
- UNKNOWN outcomes are reconciled before any retry.
- Raw credentials never enter Agent Framework plugin payloads.

## Implementation status

The current implementation branch provides:

- Caller-only ActionRequest v1 schema and strict JSON decoding.
- Idempotency-Key syntax validation and deterministic RequestHash.
- Trusted CanonicalAction validation and ActionHash.
- RFC 8785 JCS canonicalization with shared Go golden vectors.
- Negative tests for identity tampering, duplicate keys, invalid Unicode, parser depth, hash binding and lexical workspace path constraints.

The following are **not implemented yet**: the HTTP PEP, authenticated Runtime identity verification, authoritative Run/Plan and ToolBinding resolution, PostgreSQL idempotency index, atomic same-key replay/conflict handling, policy evaluation, approval workflow, signed Permit, one-time Permit claim, Trusted Executor, persistent Operation Journal, outbox delivery and UNKNOWN reconciliation.

**Protected side effects must remain disabled** until these enforcement and recovery mechanisms are implemented and integration-tested. A hash or approval match by itself is not authorization.
