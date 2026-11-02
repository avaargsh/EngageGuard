# EngageGuard Tasks

## Implemented protocol slice — parent PR #5 (Draft)

- [x] Define caller-only ActionSubmission v1; reject Guard-owned identity and operation fields.
- [x] Validate stable caller Idempotency-Key syntax.
- [x] Define Guard-internal ActionRequest with generated operation_id and authenticated tenant/subject/actor/workload.
- [x] Separate exact-byte SubmissionDigest (replay fingerprint) from resolved ActionHash (approval/Permit binding).
- [x] Implement RFC 8785 JCS, bounded parser, duplicate-key/Unicode/surrogate handling and UTF-16 property ordering.
- [x] Publish shared numeric vectors and one resolved ActionRequest golden vector.
- [x] Add mutation, malformed input, workspace argument and lexical path tests.
- [ ] Pass full generic ActionHash fixture in Python and TypeScript (existing PR #6 only covers the fixed WorkspaceWrite compatibility shape).
- [ ] Obtain fresh Go 1.26 CI on the consolidated PR #5 head.

## P0 — before protected actions

- [ ] Ratify ActionSubmission, Idempotency-Key, Operation and Receipt contracts with ACP and Runtime.
- [ ] Implement authenticated Runtime verification and authoritative Run/Plan/Capability/ToolBinding resolution.
- [ ] Implement PostgreSQL unique tenant/key index with atomic create, exact replay and changed-digest 409.
- [ ] Verify acceptance/replay behavior after lost ACK and process restart against real PostgreSQL.
- [ ] Implement deny-by-default policy, risk assessment, revocation and approval bound to ActionHash.
- [ ] Implement trusted signed Permit issuance and concurrency-safe one-time claim.
- [ ] Complete Permit → Intent → Audit relational integrity and independent security review.
- [ ] Implement durable operation completion/UNKNOWN journal, outbox delivery and reconciliation.

## P1 — trusted Workspace executor

- [ ] Implement root-relative filesystem operations with symlink and TOCTOU protection.
- [ ] Verify Permit signature, audience, expiry, operation and ActionHash immediately before the write.
- [ ] Add adversarial path, revocation, expiry, concurrency, crash-window and recovery tests.

Protected side effects remain disabled until all P0 gates and Trusted Executor tests pass.
