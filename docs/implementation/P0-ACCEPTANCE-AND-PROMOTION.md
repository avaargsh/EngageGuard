# P0 acceptance and promotion checklist

Status: development candidate, not production authorization. Tracking: #34, #57.

This document separates a candidate's test evidence from a release decision. It applies to the cumulative main-bound PR #110 and does not grant execution authority.

## Evidence ledger

Each acceptance record must identify repository, exact source SHA, target/base SHA, workflow run and job, source pins, observed result, and applicable scope. Record failures and canceled runs as such. Never carry an older success forward as proof of a different candidate. A passing declaration or unit test is not deployment acceptance.

| Gate | Observed baseline | Remaining acceptance |
| --- | --- | --- |
| Resolved ActionRequest and issuer persistence | Internal Go and PostgreSQL 16 CI on #94 / #108 | Independently review authority bindings, role separation, migration compatibility, and concurrent issuance/claim semantics |
| Runtime / ACP / Decision | #108 source-pinned non-production authority checks | Repeat live checks at cumulative HEAD; independently verify composed authority in deployed topology |
| Executor preflight cancellation | #109 observed RED and GREEN; #110 regression matrix | Independent effect-time PEP deployment acceptance; the library gate is necessary-only |
| Approval and Risk | Not established by this candidate | Independent live adapters and current decision evidence; deny or return unavailable when required evidence is absent |
| Provider outcome and recovery | Typed read-only FOUND / ABSENT_UNCERTAIN / FAILED_CONFIRMED contract in `internal/provider`; no adapter or dispatch API | Authenticated provider adapter and verifier, durable resolution writes, isolated provider fixture, exact attempt inspection, restart and uncertain-outcome acceptance; no automatic redispatch of UNKNOWN |
| Two-replica acceptance | Not established by this candidate | Isolated PostgreSQL and independent service identities; validate durable state consistency across interruption and recovery |
| Main governance | No effective protection or independent approval observed at authoring | Administrator enables and verifies rules; genuine non-author review on the proposed exact HEAD |

## Prior evidence (historical, not current-head proof)

- #94 issuer: [Go / PostgreSQL CI](https://github.com/avaargsh/EngageGuard/actions/runs/45360842066).
- #108 integration: [Go CI retry](https://github.com/avaargsh/EngageGuard/actions/runs/45390849505), [Runtime live](https://github.com/avaargsh/EngageGuard/actions/runs/45384331796), [Decision client live](https://github.com/avaargsh/EngageGuard/actions/runs/45384331759). The last workflow validates the Decision client, not the entire composed execution verifier.
- #109 cancellation: [observed RED](https://github.com/avaargsh/EngageGuard/actions/runs/45390887300), [GREEN](https://github.com/avaargsh/EngageGuard/actions/runs/45390940019).
- #110 cancellation matrix: [original parent-relative CI](https://github.com/avaargsh/EngageGuard/actions/runs/45391238083).
- Decision #75: [functional CI](https://github.com/avaargsh/agent-decision/actions/runs/45384022916), [corrected declaration](https://github.com/avaargsh/agent-decision/actions/runs/45392149289). Not evidence of a main merge or independent review.

## Candidate acceptance

- Verify all main-relative checks applicable to the exact proposed HEAD: Go/Race/PostgreSQL/Vet/JCS/format, Runtime live, Decision live, and declaration.
- Read back effective main branch protection and verify its refusal behavior on a harmless test PR. Require genuine independent approval and refresh stale evidence when HEAD or base changes.
- Keep overlapping component PRs open until reviewed integration is actually merged. Do not treat a retarget or passing declaration as a merge.
- Keep production protected effects disabled until #34 is accepted separately. A successful submission, issuer, claim or preflight check is never sufficient.

## Recovery and rollback

Preserve immutable migration bytes, operation history and audit records. Disable the new path and restore a compatible previous binary/source contract when necessary. Never erase uncertain operations to make a release look successful. Reconcile them through the owning service with independent evidence.
