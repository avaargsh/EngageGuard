# EngageGuard

Go-based Action Authorization and Trusted Execution Guard for Agent systems.

## Product boundary

Owns canonical action normalization, authorization decisions, risk evaluation, approval requests, one-time permits, operation journal and audit evidence. It does not own Agent Run or Task lifecycle.

## Initial architecture

- Go API / Policy Enforcement Point.
- PostgreSQL-backed approval, permit and operation records.
- A separately deployed trusted executor for the first Workspace write Golden Path.
- ActionHash binds approval and permit to the exact normalized action and target.
- UNKNOWN outcomes are reconciled before any retry.
- Raw credentials never enter Agent Framework plugin payloads.

All privileged tool side effects must pass through the trusted execution boundary.
