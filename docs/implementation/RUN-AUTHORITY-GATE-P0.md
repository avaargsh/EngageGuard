# Guard Run / Decision / Capability admission authority gate — P0

**Status:** code-level fail-closed composition in stacked Draft PR #20, based on #18; **not** an end-to-end deployed authorization service.

## Authority map and execution order

`ComposedRunVerifier` implements Guard's existing `RunVerifier` admission dependency; it does not own or write any of the authority domains:

1. **Runtime** — `RunSafetyAuthority.GetRunSafetySnapshot(ctx, tenantID, runID)` must be a fresh, authenticated, tenant-scoped read of Runtime's authoritative `GuardRunSafetySnapshot` projection (Runtime #21). Guard passes the tenant ID resolved from the authenticated mTLS Principal, not an untrusted header/body. Guard rejects a mismatched tenant or Run, empty Agent/AgentRelease/Session identities, a Run not in `RUNNING`, any breaker state other than `CLOSED`, and missing epoch/version. Runtime still uniquely owns the Run and breaker.
2. **Agent Decision** — `DecisionPlanAuthority.VerifyDecisionPlanStep` must verify immutable, tenant-bound DecisionRecord provenance plus Run/AgentRelease association, current PlanID/PlanHash/StepID, resource and argument bindings, expiration/revocation and current approved plan revision. A Decision proposal is **not** a Permit. Decision remains the DecisionRecord authority and Runtime owns the selected Turn/plan lifecycle.
3. **ACP** — `CapabilityAuthority.VerifyCapabilityAccess` must validate the immutable capability contract and version, tenant/AgentRelease visibility, policy bindings and current revocation against ACP-owned data. The untrusted ActionSubmission `capability.id/version` is a selector, not authority.

All three dependencies are mandatory (including a typed-nil implementation). An explicit authorization denial maps to `ErrForbidden` → HTTP 403; an unavailable/failed authority maps to `ErrAuthorityUnavailable` → HTTP 503. Neither failure is allowed to call `AcceptanceStore.Accept`. On an exact idempotency-key replay, the HTTP admission handler invokes `RunVerifier` again **before** the store, so a newly open breaker, revoked plan or unavailable policy prevents replay acceptance.

The successful result means **only** that a candidate can be persisted as `ACCEPTED` intent under the current snapshots. It does not imply action approval, Permit issuance, execution, outcome, or recovery.

## Required real adapters

- Runtime must publish an authenticated, read-only, versioned Run safety response. The existing Go PostgreSQL projection in Runtime PR #21 is **not** itself an accessible HTTP/gRPC endpoint for Guard. Pin tenant, canonical Run UUID and `workflow_id` ownership there; expose no Runtime provider secrets to Guard.
- Decision must expose a trusted, tenant-scoped immutable DecisionRecord/Plan/Step resolution contract with a current plan/Turn identifier. Simply trusting submitted PlanHash/StepID or replaying a historical Decision response does not meet this gate.
- ACP must expose a tenant-scoped, authenticated capability/policy snapshot with current revocation. No direct SQL joins across independent service databases; use versioned APIs/read-only adapters.
- The mTLS Principal from Guard #18 is single-tenant-per-workload. Multi-tenant delegation is **not** supported by the certificate alone; an independently authenticated delegation protocol and matching Run/ACP policy are required.

## G03/G05 acceptance and TOCTOU boundary

The three reads are not a distributed transaction. Run breaker state, ACP policy or plan version may change after verification and before/after acceptance. Later Permit issuance, single-use claim and any protected execution must recheck authoritative fences or atomically guard their own side effects. An ACK loss or unknown downstream effect must remain `UNKNOWN` for reconciliation, never silently become `FAILED` and retry.

Before promotion from Draft, capture real TLS + Runtime/Decision/ACP service integration receipts, database/transport restart, cross-tenant mismatch, absent Run, stopped or cancelled Run, OPEN/HALF_OPEN breaker, expiry/revocation, API 5xx/timeouts, repeat request after revocation, concurrent policy/breaker flips around acceptance and downstream UNKNOWN handling. Include exact head SHA, CI and actual staging run identifiers. Unit mocks and PG16 CI in this PR are not those receipts.

Do not merge the earlier legacy Permit/Intent PR #11 directly onto this stack: its contract and migration tree diverged. Reconcile the authoritative ActionHash, operation identity and schema history under a separate, test-first staged integration.
