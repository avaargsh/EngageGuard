# EngageGuard Baseline

Status: Proposed v0.1

## Authority
Owns Action, canonicalization, AuthorizationDecision, RiskAssessment, ApprovalRequest, one-time Permit, OperationJournal and AuditEvent. It does not own Agent Run/Task lifecycle.

## Trust boundary
Untrusted Agent Framework emits ActionProposal. Runtime authenticates and submits ActionEnvelope. EngageGuard derives actor/tenant from workload identity, resolves trusted ToolBinding, canonicalizes action and computes ActionHash. Policy/approval produces a decision. Permit is bound to exact action, operation, audience, target and expiry. Trusted Executor independently validates Permit and canonical action before effect.

## Golden Path
Workspace write only. Deny path escape and unknown tool. Require approval for designated high-risk path. Parameter/target/binding change invalidates approval. Persist operation intent and audit before side effect. Lost ACK becomes UNKNOWN and is reconciled; no blind retry.

## Persistence
PostgreSQL transaction covers decision/approval/permit claim/operation intent/outbox as appropriate. External effect is never in same ACID transaction; operation journal bridges the gap. Permit claim is one-time and concurrency-safe.

## Security
No raw credentials in Agent plugin or Action payload. Enforce resource-level authorization. Filesystem path confinement must account for symlinks and TOCTOU; string prefix checks are insufficient. Executor is isolated from Agent plugin network. Default deny.

## Stack
Go API and separate trusted executor, PostgreSQL/pgx, policy adapter (start deterministic rules; evaluate OPA/Cedar after contract), OIDC workload identity/mTLS. No general shell or arbitrary network egress in v0.1.
