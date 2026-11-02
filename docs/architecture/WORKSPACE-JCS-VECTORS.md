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

- The general `ActionRequest.ActionHash` still uses Go `json.Marshal`, including number lexemes and Unicode property ordering. It is **not JCS-compliant** across arbitrary JSON values and cannot be used as normative Approval/Permit hash.
- RFC 8785 complete numeric and UTF-16 property-name golden vectors remain a P0 requirement; these four WorkspaceWrite vectors do **not** close EngageGuard #3.
- Before an actual side effect, a Trusted Executor must enforce the action binding, one-time Permit, root-confined filesystem operation, and durable OperationJournal.
- Approval validity also depends on policy and revocation checks, not only a matching hash.

Reference: RFC 8785 Sections 3.2.2, 3.2.3 and Appendix B, https://www.rfc-editor.org/rfc/rfc8785.
