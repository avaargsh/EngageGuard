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

The SPIFFE mTLS branch supplies a verified identity resolver and an internal `NewMTLSHTTPServer` constructor, but **not** a deployable listener binary, certificate issuance/rotation/revocation operator, or authoritative RunVerifier. All authenticated Principal fields must still come from the configured workload binding. A server constructor and a real CI handshake test do **not** constitute a production deployment.

PostgreSQL acceptance and versioned migration are separately stacked PRs. This handler does not issue approvals or permits and must not be connected to an executor.


## Network mTLS gate (SPIFFE child PR)

`NewMTLSHTTPServer(address, NewHandler(resolver, runVerifier, acceptanceStore), serverCertificate, dedicatedClientCAPool)` configures TLS 1.3, `RequireAndVerifyClientCert`, a copied explicit client trust pool, key/certificate matching, read/write deadlines, and header limits. The server must be started with `ServeTLS(listener, "", "")` or `ListenAndServeTLS("", "")`, **not** a plain `Serve`. Defense in depth: its outer HTTP handler rejects an unverified/missing TLS state even when an operator mistakenly uses plaintext `Serve` or plugs in an overly permissive PrincipalResolver. `X-Forwarded-Proto` or tenant headers are never treated as TLS evidence.

The dedicated CA pool must not be replaced with generic system roots. Trust-domain / SPIFFE workload-to-Principal binding remains the responsibility of `NewSPIFFEMTLSResolver`; Run/Plan/Decision/capability authorization remains the responsibility of the authoritative `RunVerifier`. Do not deploy with the CI fake verifier, an untrusted proxy-header resolver, or an approval/executor adapter hidden inside the acceptance handler.

The real-network Go CI handshake regression exercises trusted Runtime, wrong-but-trusted SPIFFE identity, missing client certificate, untrusted client issuer, TLS 1.2 downgrade and misconfigured plaintext `Serve`. It does **not** exercise live cert rotation/expiry/revocation, production key custody, namespace trust-domain changes, real RunVerifier, loss of ACK, Permit or protected side effects. Keep G03/G05 blocked until those have independently reviewable staging receipts.

## Release gates

- Production mTLS/OIDC trust configuration and lifecycle.
- Authoritative Run/AgentRelease/Plan/Step verifier.
- Reviewed least-privilege database roles and tenant isolation.
- Action-bound approval, signed single-use Permit and atomic claim.
- Trusted executor, durable operation completion journal, UNKNOWN reconciliation and recovery.
