# EngageGuard

Go-based Action Authorization and Trusted Execution Guard for Agent systems.

## Product boundary

EngageGuard owns canonical action resolution, authorization decisions, risk evaluation, approval requests, one-time permits, protected Action Operations, operation receipts and audit evidence. It does not own Agent Run or Task lifecycle.

## Authority split

- Runtime sends an untrusted `ActionSubmission` with a persisted `Idempotency-Key`; `capability` is only an id/version selector.
- EngageGuard derives authenticated identity, validates authoritative Run/Plan state, resolves the current capability contract digest and ToolBinding from trusted registries, and generates `operation_id`. Caller-supplied `contract_sha256` is rejected.
- `SubmissionDigest` is an exact-byte replay fingerprint for tenant-scoped idempotency. It is not an approval hash.
- Internal resolved `ActionRequest` is canonicalized with RFC 8785 JCS and hashed using `engageguard/action-hash/v1\0`. Approval and Permit bind this digest.
- A separately deployed Trusted Executor must validate a one-time Permit and durable intent before any protected side effect.

## Implemented primitives in this PR stack

- Caller-only ActionSubmission schema and strict parser.
- Stable Idempotency-Key syntax validation and exact-byte SubmissionDigest.
- Guard-internal ActionRequest with tenant/subject/actor/workload, operation, capability contract, binding, policy and audience.
- RFC 8785 JCS canonicalization, shared numeric and resolved-action vectors, duplicate-key/Unicode/depth validation.
- `workspace.write` argument allowlist and lexical path checks.
- Historical fixed-shape WorkspaceWrite v0.1 hash retained as a compatibility vector, not a general executor.

## Still required before protected execution

The HTTP Admission, PostgreSQL acceptance, migration, SPIFFE identity, Permit-claim and ledger-integrity work is being developed as a stacked Draft PR series. These slices are not a production authorization path by themselves. The following remain release gates:

- Consumer ratification and shared generic Go/Python/TypeScript ActionHash fixtures.
- Production mTLS listener, certificate rotation/revocation, and authoritative RunVerifier.
- PostgreSQL unique idempotency index, restart/lost-ACK recovery and tenant isolation.
- Trusted policy/revocation source, approval workflow and signed one-time Permit issuance.
- Trusted Executor with root-constrained filesystem operations.
- Durable Operation Journal, UNKNOWN reconciliation and crash-window recovery.

**Protected side effects must remain disabled** until the full authorization, execution and recovery path is independently verified. A matching hash, an accepted submission, or a claimed Permit intent alone does not authorize execution.
