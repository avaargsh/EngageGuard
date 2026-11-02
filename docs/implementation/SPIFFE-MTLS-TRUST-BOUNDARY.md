# EngageGuard SPIFFE mTLS PrincipalResolver — Draft P0

Status: **Candidate, not deployed and not a complete authorization boundary**. Parent: PR #9 HTTP admission seam; parallel Permit PRs #10/#11 remain independent. G03/G05 remain BLOCKED.

## Authenticated caller (one service identity, one tenant mapping)

`NewSPIFFEMTLSResolver("platform.example", operatorBindings)` accepts only a client certificate with:

- A completed TLS 1.3 handshake and a nonempty `VerifiedChains` entry whose leaf matches the presented `PeerCertificates[0]`.
- An in-time, non-CA leaf with explicit client-auth Extended Key Usage; a certificate CommonName or DNS SAN is **not** an identity source.
- Exactly one URI SAN, in canonical `spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>` form, with the configured exact trust domain and no query, fragment, escaped path, or extra URI.
- A preconfigured, copy-on-construction **allowlisted mapping** from that exact SPIFFE URI to a `Principal` containing `TenantID`, `SubjectID`, `ServiceID=agent-runtime`. Unknown or ambiguous workloads fail closed.
- No trust in `X-Tenant-ID`, `X-Service-ID`, forwarded client certificates, request JSON, or runtime-mutated allowlist entries.

Example of an operator-approved binding (illustrative, not a production tenant):

```go
resolver, err := admission.NewSPIFFEMTLSResolver("platform.example", map[string]admission.Principal{
    "spiffe://platform.example/ns/agents/sa/agent-runtime": {
        TenantID: "tenant-a",
        SubjectID: "runtime-workload",
        ServiceID: "agent-runtime",
    },
})
```

The mapping is deliberately **one tenant per configured workload identity**. For a shared multi-tenant Runtime, an independently signed, scoped delegation/act-as proof and ACP authorization checks are required. Do not accept an unsigned tenant header or reinterpret the SPIFFE service account as authority over arbitrary tenants.

## Deployment MUST provide

- A Go HTTPS listener that itself performs the client TLS handshake and sets `ClientAuth=tls.RequireAndVerifyClientCert`, `MinVersion=tls.VersionTLS13`, and a reviewed dedicated `ClientCAs` trust pool. The resolver relies on the TLS stack to populate cryptographically verified chains; it does not cryptographically reverify a certificate against a separate trust pool. **Never copy `r.TLS` from client-controlled metadata or put a proxy-header adapter in front of this resolver.**
- Certificate issuance, rotation, trust-root rollover, expiry and revocation procedures, including how revoked workload identities stop passing ingress.
- A production `RunVerifier` verifying current Run, Decision, Plan, PlanHash, Step, AgentRelease, tenant and capability source state. TLS workload authentication alone does not establish that an individual proposed action is authorized.
- Least-privilege database roles, RLS or reviewed equivalent tenant isolation, rate limits, request timeouts, denial metrics, and operator configuration delivery.
- Full TLS handshake over a real listener, cert rotation/revocation and negative cross-tenant tests. Current tests prove CA-signed x509 chain validation and fail-closed extraction using a constructed TLS connection state. **That is not deployment mTLS verification evidence**.

## Invariants

An authenticated, verified `Principal` is fed into `NewHandler`; every new or repeated submission still passes a fresh authoritative RunVerifier before the admission-only `Store.Accept`. The only success record is `ACCEPTED` plus Guard-issued Operation ID and a non-dispatchable audit event. No Permit, approval, external dispatch or UNKNOWN resolution is implemented by this adapter.

Parent/stack order: #2 → #5 → #7 → #8 → #9 → #12. PR #10/#11 separately implement experimental *internal* Permit/intent claims and do not make #12 a live authorized execution endpoint. Maintain Draft and governance blockers until production transport, authoritative validation, database isolation and cross-repo reliability tests pass.
