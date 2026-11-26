# EngageGuard

Go-based Action Authorization and Trusted Execution Guard for Agent systems.

## Product boundary

EngageGuard owns canonical action resolution, authorization decisions, risk evaluation, approval requests, one-time permits, protected Action Operations, operation receipts and audit evidence. It does not own Agent Run or Task lifecycle.

## Authority split

- Runtime sends an untrusted `ActionSubmission` with a persisted `Idempotency-Key`; `capability` is only an id/version selector.
- EngageGuard derives authenticated identity, validates authoritative Run/Plan state, resolves the current capability contract digest and ToolBinding from trusted registries, and generates `operation_id`. Caller-supplied `contract_sha256` is rejected.
- `SubmissionDigest` is an exact-byte replay fingerprint for tenant-scoped idempotency. It is not an approval hash.
- Internal resolved `ActionRequest` is canonicalized with RFC 8785 JCS and hashed using `engageguard/action-hash/v1\0`. Approval and Permit bind this digest.
- A separately deployed Trusted Executor must validate a one-time Permit and durable intent before any protected side effect.

## Implemented primitives in this PR stack

- Caller-only ActionSubmission schema and strict parser.
- Stable Idempotency-Key syntax validation and exact-byte SubmissionDigest.
- Guard-internal ActionRequest with tenant/subject/actor/workload, operation, capability contract, binding, policy and audience.
- RFC 8785 JCS canonicalization, shared numeric and resolved-action vectors, duplicate-key/Unicode/depth validation.
- `workspace.write` argument allowlist and lexical path checks.
- Historical fixed-shape WorkspaceWrite v0.1 hash retained as a compatibility vector, not a general executor.
- Non-production trusted Issuer service consumes only the generic resolved ActionRequest v1 and rejects Run/Decision/Plan/Step, capability-version, contract-digest, policy, audience or ActionHash drift.
- PostgreSQL v16/v17 immutable Permit authority evidence and exact replay/conflict fencing; v17 records the resolved ActionRequest metadata while preserving old v16 rows as legacy-only.
- `ClaimResolvedActionIntent` atomically verifies exact v1 authority evidence and claims one Permit with Intent/Audit; it does not dispatch.
- Read-only provider receipt reconciliation plus PostgreSQL v18 append-only evidence ledger: exact Tenant / Operation / Permit / Attempt / ActionHash binding, deterministic idempotency key, raw evidence digest, identified verifier, UNKNOWN-only insert fence, idempotent replay and restart reads. It never dispatches or changes UNKNOWN. See [Provider reconciliation contract](docs/architecture/PROVIDER-RECONCILIATION-CONTRACT.md).

## Run the local admission and Permit demo

Install Git, Bash, Go 1.26 or newer, and PostgreSQL server tools (`initdb` and `pg_ctl`).
Put them on `PATH` or make sure `pg_config --bindir` points to their installation.
Run this command as a regular user from the root of your EngageGuard checkout.

```sh
bash scripts/demo-local-admission.sh
```

The script initializes a temporary PostgreSQL cluster with a private Unix socket
and removes it on exit. The first Go run may download modules. Look for five passing tests on Linux, or four on other supported platforms
with an explicit message that the Linux-only worker termination test was not run.

- HTTP admission persists one Operation and outbox record. Identical replay
  returns the original Operation ID, and changing the body under the same key
  returns HTTP 409.
- Permit issuance interrupted after commit returns no usable Permit. Recovery
  checks current authority before returning the original durable Permit.
- The executor preflight checks real ledger state, including revocation and
  UNKNOWN, before any protected effect could be considered.
- Two independent PostgreSQL connection pools recover the same UNKNOWN attempt
  and retain one durable journal event after the original pool closes. This is
  not a two-process crash or real provider recovery test.
- On Linux, a separate local test process commits the UNKNOWN journal and is
  terminated. The surviving process verifies durable state and idempotent
  recovery. No real provider or deployed service is involved.

The demo uses fixture authorities and exercises the HTTP handler in process.
It starts a temporary database and, on Linux, a local test child process.
It performs zero protected actions.

## Still required before protected execution

The HTTP Admission, PostgreSQL acceptance, migration, SPIFFE identity, Permit-claim and ledger-integrity work is being developed as a stacked Draft PR series. These slices are not a production authorization path by themselves. The following remain release gates:

- Consumer ratification and shared generic Go/Python/TypeScript ActionHash fixtures.
- Production mTLS listener, certificate rotation/revocation, and live authoritative Run/Attempt/Decision/ACP/Policy/Approval/Risk adapters.
- Authenticated Guard HTTP endpoint and PostgreSQL operation allocation, restart/lost-ACK recovery and tenant isolation.
- Signed bearer Permit/JTI issuance and independent revocation/policy checks at claim and effect time.
- Independently deployed Trusted Executor PEP with root-constrained, symlink-safe and TOCTOU-resistant filesystem operations.
- Production provider adapter and signed receipt verifier/trust-root distribution, durable UNKNOWN state transition policy, independent effect-time PEP, and two-replica crash-window recovery. The v18 evidence ledger is necessary but does not authorize execution.

**Protected side effects must remain disabled** until the full authorization, execution and recovery path is independently verified. A matching hash, an accepted submission, or a claimed Permit intent alone does not authorize execution.
