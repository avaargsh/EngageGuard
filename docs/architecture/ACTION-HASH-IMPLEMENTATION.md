# Workspace ActionHash v0.1 — Implementation Evidence

This first production-engineering slice implements a deterministic SHA-256 digest for a **trusted, resolved** WorkspaceWrite action. It binds tenant, subject, agent, operation, capability, trusted ToolBinding digest, policy version, executor audience, workspace, canonical relative path and content digest.

Hashing does **not** provide authorization. A trusted PEP must derive subject and bindings from authenticated context and enforce current policy, approval, revocation, expiry and one-time Permit claims separately.

The file path validation rejects noncanonical relative paths, traversal components, backslashes and NUL. It is not a filesystem confinement primitive. A real Trusted Executor must enforce root-relative open, symlink and TOCTOU protection at the final syscall boundary.

## Local verification

A standard-library-only isolated module with Go 1.23.2 passed `go test -race -count=1 ./...` and `go vet ./...`. This repository targets Go 1.26.0 and uses GitHub Actions for its own CI.

## Pending

- ActionEnvelope AuthN / PEP, authorization policy
- Signed/one-time Permit and durable claim
- PostgreSQL Approval/OperationJournal
- Trusted Executor, root-constrained filesystem
- UNKNOWN recovery and crash-window tests
