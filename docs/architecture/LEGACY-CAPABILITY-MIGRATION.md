# Legacy capability migration register — EngageGuard v0.1

Status: design-to-code migration inventory, **not** production acceptance.
Target: `avaargsh/EngageGuard`. The historical `musuntana/EngageGuard` was a
scope-governed reconnaissance/audit prototype. Do not move the old executable,
file-backed state authority, or target scanner into the new Guard process.

## Authority map

- `agent-control-panel`: tenant, AgentBundle/Release, RunIntent and authenticated
  ownership reference; no action Permit.
- `agent-runtime` + Temporal: Run/Task/Attempt, checkpoints, Decision invocation,
  submission-key preservation across lost ACK; no effect-level replay decision.
- `agent-decision`: bounded planning/DecisionRecord; ActionProposal is untrusted.
- **`EngageGuard`**: action resolution/hash, authorization/risk, approval,
  single-use Permit, action Operation Journal, receipt and reconciliation.
- `compute-control-panel`: compute Workload/Allocation/provider reconciliation
  for compute operations; does not issue a Guard action Permit.
- Isolated Trusted Executor: the sole process allowed to reach the protected
  workspace/tool resource after rechecking Permit and canonical action.

## What is carried forward

| Mature legacy invariant / capability | New location / disposition | Evidence and next gate |
| --- | --- | --- |
| Stable operation identity; repeated requests must not multiply effects | Guard-owned `operation_id` and tenant/key/exact submission digest | PR #5 and PostgreSQL PR #7; accepted != authorized |
| Durable intent; fail on uncertain persistence | PostgreSQL atomic operation + outbox; serialized, checksummed schema migration | PR #7 and this PR #8; unversioned schema must be explicitly adopted |
| Explicit UNKNOWN, no blind retry, evidence-based reconciliation | **Guard** Operation Journal + executor attempt; Runtime consumes Guard outcome | NOT IMPLEMENTED in the new repository; require loss-of-ACK, late receipt and lease-expiry tests |
| One action, one execution right; prevent replay | One-time Permit JTI claim + operation intent + audit in ONE PostgreSQL transaction | NOT IMPLEMENTED; no dispatch permitted before this boundary |
| Fingerprint binds concrete action, target, resource, executor audience and policy | Resolved WorkspaceWrite action and fixed-schema versioned JCS subset | PR #2/#6; arbitrary `ActionRequest.ActionHash` still not normative JCS; G03 blocked |
| Evidence validation; immutable audit checkpoints and signed approvals | Guard receipts/audit evidence; external durable checkpoint adapter, if required | Historical Object Lock tests were offline; independent live AWS acceptance never established |
| Atomic file artifacts, no-replace publication and crash cleanup | Future isolated Workspace Executor implementation | Re-evaluate with confined dirfd/openat2 or equivalent, symlink/TOCTOU safety and fsync fault injection |
| Explicit scope rules and expiring authorization | Versioned trusted policy adapter / capability and resource checks | Port deterministic validation ideas, not file-backed policy as a production policy authority |
| Child-process termination and bounded passive discovery | Recon tool plugin / sandbox only | **Do not port** an active scanner into Guard security control plane |

## Implementation ancestry and merge order

1. Architecture proposed in [EngageGuard #5](https://github.com/avaargsh/EngageGuard/pull/5).
2. Resolved action and draft hash [#2](https://github.com/avaargsh/EngageGuard/pull/5).
3. Untrusted submission/Guard-generated ID [#5](https://github.com/avaargsh/EngageGuard/pull/5).
4. Sibling cross-language WorkspaceWrite vectors [#6](https://github.com/avaargsh/EngageGuard/pull/15), to be integrated without overwriting the #5/#7 line.
5. PostgreSQL atomic **acceptance-only** [#7](https://github.com/avaargsh/EngageGuard/pull/14).
6. This stacked PR #8: version/checksum/atomic migration **only**.
7. Next P0 slices: production identity + Run ownership verifier; canonical action
   resolution; authorization/approval; atomic Permit claim+intent+audit; trusted
   Workspace Executor; UNKNOWN/RECONCILING/MANUAL_REVIEW and verified receipt.

Merge must follow ancestry; a green child PR does not independently establish
its parent contracts, RLS, authentication, Permit or cross-service acceptance.
Keep G03 (Guard ActionHash/operation authority), G04 (compute-provider ownership),
G05 (cross-service Golden Path) open until actual integration and negative tests.

## Non-negotiable safety regressions

- No authorization, no execution; acceptance events never trigger external effects.
- No duplicate Permit claim; no replay of an uncertain non-idempotent effect.
- Intent/Permit claim/audit commit before target-affecting operations.
- Client or model fields never supply authenticated identity, credentials, executor
  or final policy digest; unknown capabilities and stale bindings fail closed.
- A checksum matches historical migration source bytes only. It does not prove
  live catalog immutability, multi-tenant isolation, backup/restore or WORM.
