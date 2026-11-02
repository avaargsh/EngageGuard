# EngageGuard Baseline

Status: Proposed v0.1

## Authority
Owns Action, canonicalization, AuthorizationDecision, RiskAssessment, ApprovalRequest, one-time Permit, OperationJournal and AuditEvent. It does not own Agent Run/Task lifecycle.

## Trust boundary
Untrusted Agent Framework emits ActionProposal. Runtime authenticates and submits ActionRequest with a stable Idempotency-Key header. EngageGuard derives actor/tenant from workload identity, resolves trusted ToolBinding, canonicalizes action, creates operation_id and computes ActionHash. Policy/approval produces a decision. Permit is bound to exact canonical action, operation_id, audience, target and expiry. The capability-specific trusted enforcement point independently validates Permit and canonical action before effect.

## Golden Path
Workspace write only. Deny path escape and unknown tool. Require approval for designated high-risk path. Parameter/target/binding change invalidates approval. Persist operation intent and audit before side effect. Lost ACK becomes UNKNOWN and is reconciled; no blind retry. Runtime resubmits the same Idempotency-Key to recover the same server-generated operation_id.

## Persistence
PostgreSQL transaction covers decision/approval/permit claim/operation intent/outbox as appropriate. External effect is never in same ACID transaction; operation journal bridges the gap. Permit claim is one-time and concurrency-safe.

## Security
No raw credentials in Agent plugin or Action payload. Enforce resource-level authorization. Filesystem path confinement must account for symlinks and TOCTOU; string prefix checks are insufficient. Executor is isolated from Agent plugin network. Default deny.

## Stack
Go API and separate trusted executor, PostgreSQL/pgx, policy adapter (start deterministic rules; evaluate OPA/Cedar after contract), OIDC workload identity/mTLS. No general shell or arbitrary network egress in v0.1.


## Cross-service operation ownership

EngageGuard owns the Action Operation, authorization/approval/Permit, action_hash, executor attempt and Receipt. It does not own provider inventory, Kueue admission or Kubernetes resource state.

For a protected compute action, Compute CP is the trusted enforcement point and owns compute_operation_id, provider_request_digest, provider receipts and provider UNKNOWN reconciliation. It validates the Permit for the compute-control-panel audience. Guard and Compute records are linked by operation references only.

Platform-internal Run capacity is not an Agent ActionProposal. Runtime may request Compute capacity using workload identity and Compute policy. For sandboxed execution, Runtime calls SandboxProvider Claim and SandboxProvider is the sole requester of Compute capacity for that claim.
