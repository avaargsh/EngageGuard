# Provider outcome reconciliation contract

Status: internal read-only contract; not a production provider adapter.

## Ownership and safety boundary

EngageGuard owns the immutable Tenant / Operation / Attempt / ActionHash identity.
A provider adapter owns provider-specific idempotency and receipt lookup. The
provider adapter must authenticate its connection and response independently.
The evidence verifier owns provider-specific receipt authenticity, freshness,
and the meaning of a confirmed no-effect result.

The `internal/provider` package is intentionally read-only. It has no dispatch
method, cannot claim a Permit, and does not mutate the Guard ledger. A caller
must persist a returned resolution through a separately reviewed reconciliation
workflow. This contract alone never authorizes a new provider effect.

## Immutable lookup identity

Every inspection is bound to the complete tuple:

- `ProviderID`
- `TenantID`
- `OperationID`
- `AttemptID`
- `IdempotencyKey` (stable across retries of this logical attempt)
- `ActionHash`

A receipt for another tenant, operation, attempt, key, action hash, or provider
is rejected before it reaches the evidence verifier.

## Provider outcomes

| Outcome | Required evidence | Resolution | Retry implication |
|---|---|---|---|
| `FOUND` | Exact receipt with `Effect=APPLIED`, receipt ID, matching identity tuple, evidence digest and observation time | `EFFECT_OBSERVED` | Never redispatch this attempt |
| `FAILED_CONFIRMED` | Exact receipt with `Effect=NOT_APPLIED`; verifier must establish provider semantics proving no effect | `NO_EFFECT_CONFIRMED` | Not a retry grant; fresh authorization and a new attempt are still required |
| `ABSENT_UNCERTAIN` | Authenticated provider query evidence, but no receipt | `REMAIN_UNKNOWN` | Never infer absence of effect; never redispatch |

Inspection outage, verifier outage, invalid evidence, mismatched receipt, or
canceled context returns an error and no resolution. The durable Guard UNKNOWN
state therefore remains unchanged.

## Verification responsibilities

`Reconcile` performs structural validation and exact tuple binding. It then
calls the configured `EvidenceVerifier`, which must independently verify:

1. The provider identity and authenticated channel.
2. Receipt signature or other provider-authenticated integrity proof.
3. Evidence digest against the exact provider response bytes.
4. Provider-specific idempotency semantics for the supplied key.
5. For `FAILED_CONFIRMED`, authoritative proof that no effect was applied.
6. For `ABSENT_UNCERTAIN`, the authenticity and scope of the lookup result.
   A negative lookup is still uncertain and never proves non-execution.

Do not implement a permissive verifier that trusts caller-populated structs.
Production adapters must pin the provider trust root/identity and reject stale,
ambiguous, partial, or contradictory receipts.

## Deliberate non-goals in this slice

This contract does not implement a provider adapter, provider-side idempotency,
signed receipt verification, durable resolution writes, automatic retry,
effect-time Executor PEP, two deployed Guard replicas, or provider crash-window
recovery. Those remain Issue #34 release gates. Protected side effects remain
disabled until the entire path is independently verified.
