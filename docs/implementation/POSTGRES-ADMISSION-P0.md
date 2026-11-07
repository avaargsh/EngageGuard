# EngageGuard PostgreSQL admission slice (P0, Draft)

## Authority and meaning

Runtime persists a stable `Idempotency-Key` and submits an **untrusted** `action-submission.v1` body. Tenant identity is supplied to the store only from an authenticated and already-verified service principal. The body cannot supply `tenant_id`, `subject_id`, `operation_id`, policy, executor or ToolBinding. This repository remains the only authority that creates `operation_id`.

`Store.Accept` is an **acceptance-only** transaction. An `ACCEPTED` record is not an approval, a Permit, a provider ACK or permission to dispatch an external effect.

## Atomic boundary

1. Strictly validate the trusted tenant selector, caller Idempotency-Key, and complete untrusted JSON body; compute a domain-separated SHA-256 of its **exact bytes**.
2. Start a PostgreSQL READ COMMITTED transaction.
3. Atomically claim `UNIQUE(tenant_id, submission_key)`. PostgreSQL assigns a UUID `operation_id` to the first successful claimant.
4. Exact replay returns the same operation ID with `created=false`. Different digest returns `ErrConflict`; neither duplicates an operation nor emits a second event.
5. New acceptance appends one `guard.submission.recorded.v1` outbox row referencing the durable operation in the **same transaction**.
6. Commit. Any insert error (including Outbox failure) rolls both writes back. No external effects are called from this path.

`guard.submission.recorded.v1` is an **audit/integration signal, not a provider-dispatchable operation or authorization receipt**. A future consumer MUST NOT treat its presence as a Permit.

The submission digest is intentionally byte-exact and distinct from an RFC 8785/JCS `ActionHash`. Whitespace or field-order changes under an already-used key conflict until the protocol is deliberately versioned and cross-language canonicalization is proven.

## Evidence and remaining release blockers

The new CI job uses a real PostgreSQL 16 service and covers 12 concurrent identical claims, tenant isolation, stable replay after Store reconstruction, changed digest conflict, rejected malicious inputs, and a PostgreSQL trigger that forces Outbox insertion failure to prove transaction rollback.

This does **not** yet implement: authenticated HTTP admission and principal resolver; authoritative Run/Plan verification; per-tenant database RLS or reviewed equivalent; versioned checksummed migrations and operational role setup; Outbox publishing/ack; ActionHash RFC 8785/JCS vectors; policy/approval/Permit issuance; external effect operation journal, UNKNOWN reconciliation or signed receipts. There is no privileged dispatch path here. G03/G04/G05 remain blocked. Preserve this PR as Draft until independent latest-HEAD CI and cross-service acceptance.
