# Workspace ActionHash v0.1 — Implementation Evidence

This slice implements a deterministic SHA-256 ActionHash for a **trusted, resolved** WorkspaceWrite action. The canonical representation is RFC 8785 JSON Canonicalization Scheme (JCS), restricted in v0.1 to a fixed all-string object with ASCII property names in UTF-16 lexical order.

The hash preimage is:

```text
"engageguard/action-hash/v1\0" || JCS(WorkspaceWrite)
```

The resulting digest is 64 lowercase hexadecimal characters. The field set and order are explicit in `canonicalJSON`; any new field or changed field meaning requires a versioned contract update and matching Go/Python/TypeScript test vectors. Strings are UTF-8 validated and are not Unicode-normalized. HTML characters and slash are not escaped; quote, backslash and JSON control characters follow JCS escaping.

Hashing does **not** provide authorization. A trusted PEP must derive subject/tenant/workload identity from authenticated context, resolve the current ToolBinding and policy, and enforce approval, revocation, expiry and one-time Permit claims separately. A plugin-supplied ActionHash is never trusted.

The file path validation rejects noncanonical relative paths, traversal components, backslashes and NUL. It is not a filesystem confinement primitive. A real Trusted Executor must enforce root-relative open, symlink and TOCTOU protection at the final syscall boundary.

## Local verification

A standard-library-only isolated module with Go 1.23.2 previously passed `go test -race -count=1 ./...` and `go vet ./...`. This JCS implementation and its new canonicalization regression test require the current PR's Go 1.26 CI run; do not claim it is green until that run is inspected.

## Pending

- ActionEnvelope AuthN / PEP and trusted binding resolution
- Authorization policy and action-bound approval
- Signed/one-time Permit and durable claim
- PostgreSQL Approval/OperationJournal
- Trusted Executor and root-constrained filesystem
- UNKNOWN recovery and crash-window tests
- Shared Go/Python/TypeScript ActionHash vectors against the canonical platform contract
