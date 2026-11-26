# Provider outcome reconciliation contract

Status: read-only provider reconciliation plus an append-only PostgreSQL evidence ledger. This is not a production provider adapter or a production authorization path.

## Ownership and safety boundary

EngageGuard owns the immutable Tenant / Operation / Permit / Attempt / ActionHash identity. A trusted executor selects the provider adapter for the authorized action. The adapter owns provider-specific idempotency and receipt lookup and must authenticate its connection and response independently. The evidence verifier owns provider identity, receipt authenticity, freshness, provider idempotency semantics, and the meaning of a confirmed no-effect result.

The `internal/provider` package has no dispatch method, cannot claim a Permit, and does not mutate the Guard ledger. `Store.ReconcileProvider` is the only application write path in this slice: it checks the committed UNKNOWN Attempt before contacting the provider, verifies the exact raw response, and appends the verified observation. It never transitions the Intent or grants a retry.

## Immutable lookup identity

Every inspection is bound to the complete tuple:

- `ProviderID`
- `TenantID`
- `OperationID`
- `PermitID`
- `AttemptID`
- `IdempotencyKey`
- `ActionHash`

The idempotency key is deterministically derived with the domain `engageguard/provider-idempotency/v1` from Provider, Tenant, Operation, Permit, Attempt and ActionHash. It is stable across retries of this one Attempt and changes when any bound identity changes. A receipt for another provider, tenant, operation, Permit, attempt, key or action hash is rejected before the evidence verifier.

## Provider outcomes

| Outcome | Required evidence | Resolution | Retry implication |
|---|---|---|---|
| `FOUND` | Exact receipt with `Effect=APPLIED`, receipt ID, matching identity tuple, evidence digest and observation time | `EFFECT_OBSERVED` | Never redispatch this Attempt |
| `FAILED_CONFIRMED` | Exact receipt with `Effect=NOT_APPLIED`; verifier must establish provider semantics proving no effect | `NO_EFFECT_CONFIRMED` | Not a retry grant; fresh authorization and a new Attempt are still required |
| `ABSENT_UNCERTAIN` | Authenticated provider query evidence, but no receipt | `REMAIN_UNKNOWN` | Never infer absence of effect; never redispatch |

Inspection outage, verifier outage, invalid evidence, mismatched receipt, or canceled context returns an error and no durable observation. The Guard Intent remains UNKNOWN.

## Durable evidence ledger (migration v18)

`guard_provider_observations` stores the exact provider identity, immutable Attempt tuple, normalized outcome, receipt ID/effect, raw evidence bytes, SHA-256 digest, verifier identity, observation time and database record time.

- The v18 migration is additive; v1-v17 migration sources and checksums remain unchanged.
- A composite foreign key binds each row to the exact Tenant / Operation / Permit / Attempt / ActionHash Intent.
- An insert trigger locks that Intent and requires a committed UNKNOWN journal, a CLAIMED Permit, and the exact dispatch audit.
- Raw evidence is bounded to 256 KiB and its SHA-256 digest is checked before verification and again on read.
- Rows are immutable under UPDATE, DELETE and TRUNCATE; triggers are enabled ALWAYS.
- Exact replay of the same digest and metadata is idempotent. Conflicting evidence for the same digest is rejected.
- Multiple `ABSENT_UNCERTAIN` observations may be appended. At most one terminal `FOUND` or `FAILED_CONFIRMED` observation is allowed for an Attempt; no further observation can replace it.
- `ListProviderObservations` reads the evidence after process/store recreation. Cross-tenant selectors return an empty result.
- Persisting a terminal observation does not change `guard_operation_intents.state`, issue a new Permit, or authorize another provider effect.

The stored `verifier_id` must identify the configured verifier version and pinned trust-set revision. The interface requires an `IdentifiedEvidenceVerifier`; do not use a verifier that trusts caller-populated structs.

## Verification responsibilities

The configured `EvidenceVerifier` must independently verify:

1. Provider identity and authenticated channel.
2. Receipt signature or other provider-authenticated integrity proof.
3. Evidence digest against the exact provider response bytes.
4. Provider-specific idempotency semantics for the derived key.
5. For `FAILED_CONFIRMED`, authoritative proof that no effect was applied.
6. For `ABSENT_UNCERTAIN`, authenticity and scope of the lookup result. A negative lookup is still uncertain and never proves non-execution.

The PostgreSQL ledger validates shape, identity, immutability and digest integrity. It does not authenticate provider signatures; that remains the verifier's responsibility.

## Deliberate non-goals in this slice

This slice does not implement a production provider adapter, a concrete signed receipt verifier/trust-root distribution, a durable state transition out of UNKNOWN, automatic retry, effect-time Executor PEP, two deployed Guard replicas, or provider crash-window recovery. Those remain Issue #34 release gates. Protected side effects remain disabled until the entire path is independently verified.
