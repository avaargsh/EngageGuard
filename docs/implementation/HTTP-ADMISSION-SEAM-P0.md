# Guard HTTP admission P0 (Draft; NOT a production authorization service)

## Purpose
`internal/admission.NewHandler` is a narrow, non-dispatching HTTP seam for Runtime -> EngageGuard. It accepts only `POST /v1/action-submissions` with `Content-Type: application/json` and one persisted `Idempotency-Key`. The body is an untrusted `action-submission.v1`. **Never** accept caller-controlled tenant, subject, agent, operation ID, policy, ToolBinding, executor, Permit, or approval fields.

## Trust boundaries
1. `PrincipalResolver` is mandatory. It MUST independently authenticate mTLS/OIDC or an explicitly trusted identity gateway and return tenant, subject and service ID. This PR intentionally has **no concrete resolver**, no header token bypass, and no server deployment wiring. The HTTP handler rejects missing trust dependencies.
2. `RunVerifier` is mandatory and MUST check the currently authorized Run, AgentRelease, Decision/Plan/Step provenance, capability visibility and request scope against the resolved principal. The current Go interface is a contract seam only, not such a verifier.
3. Only `ServiceID = agent-runtime` is eligible; `X-Tenant-ID`, `X-Service-ID`, the JSON body and other unverified headers are ignored for identity.
4. Once all gates succeed, `postgres.Store.Accept` transactionally records a stable Guard-assigned `operation_id` and non-dispatchable `guard.submission.recorded.v1` event. This is an intent receipt, **not** an authorization or execution outcome.

## HTTP semantics
- 201: first durable acceptance, response `{"operation_id":"...","status":"ACCEPTED"}`.
- 200: identical key and byte-exact body replay after fresh identity/Run verification; same ID.
- 400: malformed, duplicate, untrusted or oversized body; missing/bad key.
- 401: no authenticated trusted principal.
- 403: non-Runtime service or authoritative Run/Plan denial.
- 405 / 415: wrong method / media type.
- 409: key already bound to different submission bytes.
- 503: identity/verifier/database unavailable or malformed authoritative receipt.
- No permit ID, approval state, execution status, provider address or secret is returned; all responses are non-cacheable.

## Remaining P0 gates
A production-grade `PrincipalResolver`, `RunVerifier`, endpoint wiring and timeouts, independent authentication/authorization review, separate least-privileged DB roles and tenant isolation proof, signed action-bound Permit, RFC 8785/JCS cross-language ActionHash, operation execution journal, revocation, UNKNOWN recovery and real Temporal/provider failure drills. Merely registering this handler to an unauthenticated server does NOT satisfy any of these gates. Do not expose it publicly or connect an executor based solely on `ACCEPTED`.

This PR stacks on #8 (transactional checksummed migrations), #7 (atomic PostgreSQL acceptance), #5 (untrusted submission) and #2 (base ActionHash). The suite includes negative HTTP unit tests; PostgreSQL integration remains an independent part of inherited CI. G03/G05 remain BLOCKED.
