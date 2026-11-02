# RequestHash and ActionHash v1 — implementation evidence

Status: protocol primitives implemented; authorization and execution are not implemented.

## Distinct hash purposes

RequestHash identifies one logical caller submission:

```text
"engageguard/request-hash/v1\\0" || JCS({
  "authenticated_context": { tenant_id, subject_id, actor_id, workload_id },
  "request": ActionRequest
})
```

It excludes the caller's `Idempotency-Key` (the unique index key) and server-generated `operation_id`.

ActionHash identifies the exact trusted resolved action:

```text
"engageguard/action-hash/v1\\0" || JCS(CanonicalAction)
```

CanonicalAction is built only after authentication, Run/Plan reference validation, capability and ToolBinding resolution, and current-policy evaluation. It binds the generated operation ID and all authorization/effect-relevant values. Approval and Permit must reference this digest.

## JCS implementation

The standard-library implementation in `internal/action/request.go`:

- rejects duplicate object keys at every depth;
- validates UTF-8 and rejects unpaired surrogate escapes;
- limits nesting to 64, total canonical JSON to 128 KiB and arguments to 64 KiB;
- sorts property names by UTF-16 code units;
- serializes IEEE-754 binary64 numbers using ECMAScript/JCS formatting thresholds;
- uses JCS string escaping without HTML-specific escaping or Unicode normalization.

Shared plain-JSON fixtures are in `docs/contracts/jcs-number-vectors.v1.json` and `docs/contracts/action-hash-vectors.v1.json`. Go tests load both fixtures directly. Python and TypeScript parity tests remain required before protocol ratification.

## Workspace write constraints

Resolved `workspace.write` v1 arguments contain exactly `path` and `content_sha256`. Hash validation rejects absolute, noncanonical, traversal, empty-segment, backslash, NUL and Windows drive-prefixed paths. This is lexical validation only, not filesystem isolation.

The historical `WorkspaceWrite` v0.1 helper and fixed all-string golden vector remain as a narrow regression reference. They are not the production CanonicalAction interface and do not authorize a write.

## Local verification

On Go 1.23.2 in a standard-library-only isolated module:

- `go test -race -count=1 ./...` passed;
- `go vet ./...` passed;
- `test -z "$(gofmt -l internal)"` passed;
- the three JSON contract/fixture files parsed successfully with Python's JSON parser.

The repository Actions workflow targets Go 1.26.0. Remote CI for the updated PR commit must be inspected separately; local verification does not establish that remote CI passed.

## Pending

- durable unique `(tenant_id, idempotency_key)` index and atomic replay/conflict semantics;
- Operation Journal, outbox and restart-safe delivery;
- policy evaluation and action-bound human approval;
- signed short-lived audience-bound Permit and atomic one-time claim;
- trusted filesystem executor with symlink/TOCTOU protection;
- UNKNOWN reconciliation and crash-window integration tests;
- Python and TypeScript implementations passing the shared golden fixtures.
