# ActionRequest v1 — Guard-owned authorization contract

Status: contract and canonical ActionHash reference implementation; no Permit issuance or Trusted Executor implementation is claimed.

## Ownership

- Decision emits an immutable PlanCandidate and PlanHash. It does not construct an executable request or authorize a side effect.
- Runtime validates the plan against the active Run and AgentRelease, resolves one PlanStep and its inputs, and creates one ActionRequest with a stable OperationID.
- EngageGuard is the authority for validating the ActionRequest, re-resolving the current Capability and ToolBinding, evaluating policy/risk/approval, computing ActionHash and issuing or denying a Permit.
- Trusted Executor revalidates and consumes a one-time, action-bound Permit immediately before the side effect. OperationJournal owns operation state and UNKNOWN reconciliation.

## Required binding

ActionRequest v1 binds tenant, subject, agent, Run, Decision, Plan, PlanHash, Step, Operation, exact Capability ID/version/contract digest, resource target, canonical arguments, trusted ToolBinding digest, policy version and executor audience.

No endpoint, provider secret, bearer token or executable code is accepted in the ActionRequest contract. The tenant and identity fields are assertions to compare against the authenticated caller and authoritative Run; they are not trusted merely because they appear in JSON.

## Canonicalization

- Arguments must be a JSON object, no larger than 64 KiB.
- Duplicate object keys are rejected at every nesting depth.
- Object keys are sorted by canonical re-encoding; numeric values preserve their JSON number lexeme (no float64 conversion).
- The hash covers all identity and authorization binding fields plus the canonical arguments.
- A change to any bound field produces a different ActionHash. A Permit must reference the exact hash, audience, tenant, subject, expiry and nonce.

## Required execution order

1. Runtime emits one ActionRequest for one PlanStep.
2. Guard authenticates Runtime and verifies tenant/Agent/Run/Release ownership.
3. Guard re-resolves capability version, schema digest, tool binding and current policy; stale or revoked references fail closed.
4. Guard computes ActionHash over the normalized action and obtains any required human approval bound to that hash.
5. Guard issues a short-lived, audience-bound, single-use Permit only after approval and policy checks.
6. Trusted Executor validates signature, audience, expiry, action hash, subject, tenant and nonce; atomically claims the nonce before executing.
7. OperationJournal persists STARTED/COMPLETED/FAILED/UNKNOWN. Lost ACK or uncertain provider result becomes UNKNOWN and is reconciled against the external resource; never blind-retried.
8. Runtime receives a signed/verified outcome reference and updates its own Step/Run state.

## Current implementation boundary

This branch implements ActionRequest validation, strict canonical argument parsing and deterministic SHA-256 ActionHash with mutation tests. The earlier WorkspaceWrite-specific hash helper remains as a narrower example. Permit signing, one-time nonce storage, policy evaluation, filesystem/provider execution and UNKNOWN journal are not implemented by this PR and must not be represented as complete.
