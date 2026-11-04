# Guard HTTP admission P0

Status: implementation seam only; not a production authorization service.

## Trust and identity

Runtime submits an untrusted `action-submission.v1` body with one persisted `Idempotency-Key`. Capability is an untrusted `id/version` selector; no caller contract digest is accepted.

The handler requires all three dependencies: `PrincipalResolver`, `RunVerifier` and `AcceptanceStore`. The resolved Principal must contain tenant, subject, actor, workload and service identity. All identity fields must come from an authenticated resolver, never from headers or JSON. Only the registered `agent-runtime` service is eligible.

The RunVerifier must validate Run/AgentRelease/Decision/Plan/Step provenance and capability visibility against authoritative state. A nil or failed verifier never falls back to cache or caller claims.

The AcceptanceStore creates the Guard operation ID and writes acceptance state only. `ACCEPTED` is not authorization, Permit issuance, external dispatch or a successful action receipt.

## HTTP behavior

- `POST /v1/action-submissions` only.
- Exactly one `Idempotency-Key` header; JSON content type; bounded request body.
- 201 for first durable acceptance, 200 for exact replay, 409 for same key with changed submission bytes.
- 400 malformed/unknown/duplicate fields, invalid key or oversized body.
- 401 missing or invalid authenticated Principal.
- 403 non-Runtime caller or authoritative Run/Plan denial.
- 405 / 415 wrong method / media type.
- 503 identity, Run authority or database unavailable.
- Responses are non-cacheable and include only server operation ID + ACCEPTED state.

Every retry is re-authenticated and re-verified before the idempotency store is consulted. No caller-supplied tenant header can override the authenticated Principal.

## Implementation and test boundary

The Go interface now requires `TenantID`, `SubjectID`, `ActorID`, `WorkloadID` and `ServiceID`. These fields support the four-dimensional authenticated context used by the resolved ActionHash contract.

The package intentionally does not ship a production TLS listener, certificate rotation/revocation, a concrete principal resolver, a concrete RunVerifier, or deployment wiring. The separate SPIFFE mTLS work must populate all authenticated identity fields through a pinned workload binding.

PostgreSQL acceptance and versioned migration are separately stacked PRs. This handler does not issue approvals or permits and must not be connected to an executor.

## Release gates

- Production mTLS/OIDC trust configuration and lifecycle.
- Authoritative Run/AgentRelease/Plan/Step verifier.
- Reviewed least-privilege database roles and tenant isolation.
- Action-bound approval, signed single-use Permit and atomic claim.
- Trusted executor, durable operation completion journal, UNKNOWN reconciliation and recovery.
