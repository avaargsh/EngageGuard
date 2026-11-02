# EngageGuard Tasks

## Implemented in PR #2 (remote Go 1.26 CI pending)

- [x] Define ActionRequest v1 as caller intent only; reject Guard-owned fields.
- [x] Validate stable Idempotency-Key syntax.
- [x] Separate authenticated-context RequestHash from trusted CanonicalAction ActionHash.
- [x] Add JCS canonicalization, bounded parsing and shared Go golden vectors.
- [x] Add negative tests for identity tampering, duplicate keys, invalid Unicode, deep nesting and workspace.write path/argument validation.

## P0 — before protected actions

- [ ] Ratify ActionRequest, Idempotency-Key, Operation and Receipt contracts with ACP and Runtime.
- [ ] Pass shared JCS/hash fixtures in Python and TypeScript consumers.
- [ ] Implement PostgreSQL unique tenant/key index with atomic create, same-key replay and changed-digest 409.
- [ ] Implement authenticated Runtime verification and authoritative Run/Plan/Capability/ToolBinding resolution.
- [ ] Implement deny-by-default policy, risk assessment and approval bound to ActionHash.
- [ ] Implement signed short-lived Permit and concurrency-safe one-time claim.
- [ ] Implement durable Operation Journal/outbox and restart-safe dispatch.
- [ ] Implement UNKNOWN reconciliation and crash-window integration tests.

## P1 — trusted Workspace executor

- [ ] Implement root-relative filesystem operations with symlink and TOCTOU protection.
- [ ] Verify Permit, audience, expiry, operation and ActionHash immediately before the write.
- [ ] Add adversarial path, revocation, expiry, concurrency and recovery tests.

Protected side effects remain disabled until the P0 gates and executor tests pass.
