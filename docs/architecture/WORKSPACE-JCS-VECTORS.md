# WorkspaceWrite v0.1 JCS-subset Interoperability Gate

Status: **Test evidence only, Draft.** This does not approve the generic ActionRequest ActionHash, Permit, or Trusted Executor.

## Exact, bounded hash contract

The `WorkspaceWrite` struct has exactly twelve fixed ASCII property names and string-valued fields. For this **limited shape only**, RFC 8785's UTF-16 property order equals ASCII key sorting, and JSON string serialization has no numeric formatting branch.

```text
SHA-256( UTF8("engageguard/action-hash/v1") || 0x00 || UTF8(JCS(WorkspaceWrite)) )
```

The versioned domain separator includes a **literal NUL byte**, not six printable characters `\\u0000`. No Unicode normalization is applied. The digest is not itself a Permit.

## Frozen vectors and independent checks

- `testdata/workspace-actionhash-v01.json`: canonical UTF-8 JSON, digest and exact action for four scenarios.
- `internal/action/jcs_vectors_test.go`: Go code-under-test, including action approval mutation rejection.
- `scripts/verify_workspace_jcs.py`: independent Python serializer for the fixed ASCII-key/string-only shape.
- `scripts/verify_workspace_jcs.ts`: TypeScript/Node JSON.stringify verifier, executed with Node 22 type-stripping.
- `.github/workflows/go-tests.yml`: requires all three to pass.

Local reproduction:

```sh
go test -race -count=1 ./...
python3 scripts/verify_workspace_jcs.py
node --experimental-strip-types scripts/verify_workspace_jcs.ts
```

## Not yet proven / safety gate

- Parent PR #5 now includes a generic RFC 8785 canonicalizer (`internal/action/jcs.go`) and Go number / resolved-ActionRequest vectors. **These four legacy WorkspaceWrite v0.1 vectors do not establish generic cross-language parity**, authoritative Policy/Approval/Permit issuance, or production-safe protected execution. Review the separate generic test evidence and trust-source gates before using a normative ActionHash for authorization.
- Generic numeric/JCS and resolved-action contract tests are maintained separately under `docs/contracts/` and their own Go/Python/TypeScript verifiers. This compatibility subset cannot be counted as proof for arbitrary JSON arguments, protected effects or closure of EngageGuard #3.
- Before an actual side effect, a Trusted Executor must enforce the action binding, one-time Permit, root-confined filesystem operation, and durable OperationJournal.
- Approval validity also depends on policy and revocation checks, not only a matching hash.

Reference: RFC 8785 Sections 3.2.2, 3.2.3 and Appendix B, https://www.rfc-editor.org/rfc/rfc8785.
