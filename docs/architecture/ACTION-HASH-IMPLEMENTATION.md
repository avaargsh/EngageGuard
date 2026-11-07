# SubmissionDigest and ActionHash v1 — implementation evidence

Status: protocol primitives implemented; authorization and protected execution remain incomplete.

## Distinct digest purposes

### SubmissionDigest — caller replay fingerprint

```text
SHA-256( UTF8("engageguard/submission-bytes/v1") || 0x00 || exact ActionSubmission bytes )
```

This is deliberately byte-exact. The PostgreSQL acceptance store scopes it with the authenticated tenant and caller-persisted `Idempotency-Key`. Repeating the exact bytes returns the same Operation; changing any byte with the same key conflicts. Whitespace or property-order changes therefore conflict by design. SubmissionDigest is not a policy decision, approval digest or Permit binding.

### ActionHash — trusted resolved action binding

```text
SHA-256( UTF8("engageguard/action-hash/v1") || 0x00 || UTF8(JCS(ActionRequest)) )
```

The internal `ActionRequest` is constructed only after Guard authentication, Run/Plan verification, trusted capability/ToolBinding resolution and current policy resolution. It binds tenant, subject, actor, workload, Agent/Run/Decision/Plan/Step, Guard-generated operation ID, immutable capability contract digest, target, canonical arguments, ToolBinding digest, policy version and executor audience.

Approval and Permit must reference this exact digest. A caller-supplied ActionHash is rejected from the Runtime wire schema and never trusted.

## RFC 8785 canonicalization

The standard-library implementation in `internal/action/jcs.go`:

- rejects duplicate keys at every object depth;
- rejects invalid UTF-8 and unpaired UTF-16 surrogate escapes;
- caps canonical JSON at 128 KiB and nesting at 64; ActionSubmission and arguments are each separately capped at 64 KiB;
- sorts object property names by UTF-16 code units;
- serializes numbers using ECMAScript IEEE-754 binary64 shortest representation and exponent thresholds, including negative-zero normalization;
- emits JCS string escaping without HTML escaping or Unicode normalization.

Shared numeric vectors are in `docs/contracts/jcs-number-vectors.v1.json`; the resolved internal action vector is in `docs/contracts/resolved-action-v1-vectors.json`. Go tests consume both fixtures. All 33 numeric fixture cases were also compared independently with ECMAScript `JSON.stringify(Number(input))`.

Full Python/TypeScript parity for the generic resolved ActionRequest fixture remains required. PR #6's existing Python/TypeScript scripts cover only the older fixed-shape, all-string WorkspaceWrite v0.1 compatibility subset and must not be cited as proof of generic RFC 8785 interoperability.

## Workspace write constraints

Resolved `workspace.write` v1 arguments contain exactly `path` and `content_sha256`. Validation rejects absolute, noncanonical, traversal, empty-segment, backslash, NUL and Windows drive-absolute/drive-relative paths.

This is a lexical check only. A Trusted Executor must use root-relative, symlink-safe and TOCTOU-resistant operating-system operations after verifying a valid single-use Permit and durable pre-dispatch intent.

The historical fixed-shape `WorkspaceWrite` v0.1 hash remains as a compatibility vector for the separate P10 internal-only claim tests. It does not replace the generic resolved ActionRequest ActionHash and does not authorize a filesystem write.

## Current code does not provide

- a complete policy engine and authoritative revocation source;
- a human approval lifecycle bound to ActionHash;
- signed short-lived Permit issuance and atomic one-time claim from a trusted issuer;
- deployed mTLS listener configuration, certificate rotation or revocation operations;
- an external Trusted Executor or filesystem sandbox;
- completion/UNKNOWN journal transitions and provider-side reconciliation;
- full generic Go/Python/TypeScript ActionHash parity.

Protected side effects must remain disabled until the whole authorization, dispatch and recovery path is independently verified.
