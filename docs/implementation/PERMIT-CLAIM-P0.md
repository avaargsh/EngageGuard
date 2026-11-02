# Guard P0 Permit Claim + Dispatch Intent (Draft)

Status: **internal transaction primitive only; no trusted issuance or executor yet**.
Stack: [#10](https://github.com/avaargsh/EngageGuard/pull/10) on
[#9](https://github.com/avaargsh/EngageGuard/pull/9) on #8/#7/#5/#2.

## Authoritative boundaries

The existing submission admission `ACCEPTED` record is the result of
authenticated Runtime/Run verification and a durable idempotency claim. It
does **not** authorize an action, prove approval or grant execution. This
slice does not change that admission status. Guard's separate execution ledger
holds pre-dispatch intent state. The outbox event
`guard.submission.recorded.v1` is still NOT dispatchable.

Only a future production Guard PEP, after authoritative Run/delegation,
policy, risk, approval and trusted ToolBinding checks, may insert a Permit.
The current PostgreSQL integration tests **seed permits directly** to simulate
that future trusted issuer; anyone who can write them in an uncontrolled DB
environment must be considered a privileged authority. No external API or
automatic executor dispatch is enabled by this PR.

## Atomic pre-dispatch transition

```text
Trusted resolved WorkspaceWrite (fixed-schema v0.1)
    + previously issued, unrevoked, unexpired Permit
    -> Hash(resolved Action) under versioned workspace JCS subset
    -> SELECT Permit FOR UPDATE (tenant + operation + permit)
    -> check ActionHash, ToolBinding digest, audience, policy version
    -> check database-clock expiry + revocation + ISSUED state
    -> BEGIN (already active)
       UPDATE Permit ISSUED -> CLAIMED (database-clock expiry recheck)
       INSERT guard_operation_intents (DISPATCHING, new attempt_id)
       INSERT guard_execution_audit (guard.operation.dispatching.v1)
       COMMIT
    -> return persisted attempt_id for future trusted dispatch path
```

PostgreSQL enforces unique Permit per operation and unique intent/dispatch
audit per tenant/operation, with tenant-bound foreign keys. Concurrent claims
serialize by row locking. After lost ACK or a duplicate request, a second
claim returns `ErrPermitAlreadyClaimed`; that error must **never** be used as
a signal to dispatch again. Future reconciliation must inspect the persisted
attempt and external evidence before choosing a final outcome. Errors or
transaction failures return no dispatch right. A forced audit failure rolls
Permit claim and intent insertion back.

`DISPATCHING` is a **durable intent that the external call may occur**, not
an execution receipt. No external side effect, `UNKNOWN` resolution, executor,
provider query, approval API or general JCS ActionRequest integration exists.

## Schema management and recovery

Schema v1 (admission) retains its original source bytes/checksum. Schema v2
(Permit/Intent/Audit) is an additive, independently checksummed migration under
the same PostgreSQL advisory-locked transaction. Unknown versions, missing
prefixes and checksum mismatches fail closed. Real PostgreSQL tests cover
v1->v2 upgrade, repeated migration, concurrent first install, checksum drift,
and rollback when the new DDL fails after earlier tables were created.

A DB commit ACK may be lost while the transaction succeeds. Claim callers
must reconcile against authoritative Guard rows, not simply resubmit a new
Permit or execute again. This PR intentionally returns an already-claimed
fence on duplicate calls rather than implementing a new dispatch.

## Mandatory security gates before enabling execution

- Production PrincipalResolver, Run ownership verifier, immutable policy
  and approval decision proofs, delegated identity and tenant isolation.
- Reviewed, separately authenticated Permit issuer and revocation authority;
  signed/short-lived Permit trust chain, current policy check, stable JTI,
  executor audience and issuance/claim separation.
- An isolated Trusted Workspace Executor that **independently revalidates**
  canonical action, Permit, expiry, revocation and resource confinement
  before any write, with symlink/TOCTOU and crash-safety fault injection.
- Append-only/independently retained audit evidence, database RLS or reviewed
  equivalent and least-privilege DB roles. This schema by itself is **not** WORM.
- Complete `UNKNOWN -> RECONCILING -> SUCCEEDED/FAILED_CONFIRMED/
  MANUAL_REVIEW` journal, post-effect receipt identity and digest checks,
  lost-ACK, replay, stale-lease and operator recovery tests.
- Cross-language normative general ActionRequest/JCS and ACP/Runtime/Decision
  contract ratification (G03/G05); do not confuse the narrow WorkspaceWrite
  vector with general RFC 8785 compliance.

Do not merge this stacked PR as a production-ready authorization capability.
