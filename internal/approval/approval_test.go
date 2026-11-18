package approval

import (
    "bytes"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "testing"
    "time"
)

func fixtureApproval(t *testing.T, now time.Time) (Scope, Evidence, ed25519.PublicKey, ed25519.PrivateKey) {
    t.Helper()
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatal(err) }
    scope := Scope{
        TenantID: "tenant-1", RunID: "run-001", AttemptID: "attempt-001",
        TurnID: "turn-001", OperationID: "11111111-1111-4111-8111-111111111111",
        AgentID: "agent-001", AgentReleaseID: "release-001",
        SubjectID: "subject-001", DecisionID: "dec_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        PlanHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        StepID: "step-001", ActionHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ToolBindingDigest: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        PolicyVersion: "policy-001", Audience: "trusted-workspace-executor",
        ResourceRef: "workspace-001",
    }
    evidence := Evidence{
        SchemaVersion: "engageguard.approval-evidence.v1",
        ApprovalID: "approval-001", Decision: "APPROVED", Scope: scope,
        IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(2 * time.Minute),
    }
    return scope, evidence, pub, priv
}

func signedApproval(t *testing.T, evidence Evidence, pub ed25519.PublicKey, priv ed25519.PrivateKey) []byte {
    t.Helper()
    payload, err := json.Marshal(evidence)
    if err != nil { t.Fatal(err) }
    fingerprint := sha256.Sum256(pub)
    message := append([]byte("engageguard/approval-proof/v1\x00"), payload...)
    wire, err := json.Marshal(SignedEvidence{KeyID: hex.EncodeToString(fingerprint[:]),
        Payload: payload, Signature: ed25519.Sign(priv, message)})
    if err != nil { t.Fatal(err) }
    return wire
}

func TestVerifySignedApprovalAcceptsOnlyFreshPinnedScopedEvidence(t *testing.T) {
    now := time.Date(2026, 11, 18, 8, 30, 0, 0, time.UTC)
    scope, evidence, pub, priv := fixtureApproval(t, now)
    wire := signedApproval(t, evidence, pub, priv)
    result, err := VerifySignedEvidence(wire, pub, scope, now)
    if err != nil || result.ApprovalID != evidence.ApprovalID || result.Scope != scope {
        t.Fatalf("valid independently signed approval was rejected: %+v %v", result, err)
    }
    for _, tc := range []struct {
        name string
        modify func(*Scope)
    }{
        {"tenant", func(s *Scope) { s.TenantID = "tenant-2" }},
        {"run", func(s *Scope) { s.RunID = "run-002" }},
        {"attempt", func(s *Scope) { s.AttemptID = "attempt-002" }},
        {"turn", func(s *Scope) { s.TurnID = "turn-002" }},
        {"operation", func(s *Scope) { s.OperationID = "22222222-2222-4222-8222-222222222222" }},
        {"agent", func(s *Scope) { s.AgentID = "agent-002" }},
        {"release", func(s *Scope) { s.AgentReleaseID = "release-002" }},
        {"subject", func(s *Scope) { s.SubjectID = "subject-002" }},
        {"decision", func(s *Scope) { s.DecisionID = "dec_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }},
        {"plan", func(s *Scope) { s.PlanHash = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" }},
        {"step", func(s *Scope) { s.StepID = "step-002" }},
        {"action", func(s *Scope) { s.ActionHash = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" }},
        {"binding", func(s *Scope) { s.ToolBindingDigest = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" }},
        {"policy", func(s *Scope) { s.PolicyVersion = "policy-002" }},
        {"audience", func(s *Scope) { s.Audience = "untrusted-executor" }},
        {"resource", func(s *Scope) { s.ResourceRef = "workspace-002" }},
    } {
        t.Run(tc.name, func(t *testing.T) {
            changed := scope
            tc.modify(&changed)
            if _, err := VerifySignedEvidence(wire, pub, changed, now); !errors.Is(err, ErrApprovalRejected) {
                t.Fatalf("signed approval reused across %s: %v", tc.name, err)
            }
        })
    }
    _, otherKey, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatal(err) }
    forged := signedApproval(t, evidence, pub, otherKey)
    if _, err := VerifySignedEvidence(forged, pub, scope, now); !errors.Is(err, ErrApprovalRejected) {
        t.Fatalf("forged approval accepted: %v", err)
    }
    if _, err := VerifySignedEvidence(wire, pub, scope, evidence.ExpiresAt); !errors.Is(err, ErrApprovalRejected) {
        t.Fatalf("expired approval accepted: %v", err)
    }
    if _, err := VerifySignedEvidence(wire, pub, scope, evidence.IssuedAt.Add(-time.Second)); !errors.Is(err, ErrApprovalRejected) {
        t.Fatalf("not-yet-valid approval accepted: %v", err)
    }
}

func TestVerifySignedApprovalRejectsMalformedOrNoncanonicalEvidence(t *testing.T) {
    now := time.Date(2026, 11, 18, 8, 30, 0, 0, time.UTC)
    scope, evidence, pub, priv := fixtureApproval(t, now)
    bad := []struct{name string; change func(*Evidence)}{
        {"denied", func(e *Evidence){ e.Decision="DENIED" }},
        {"not approved", func(e *Evidence){ e.Decision="" }},
        {"wrong schema", func(e *Evidence){ e.SchemaVersion="unknown" }},
        {"missing approver", func(e *Evidence){ e.ApprovalID="" }},
        {"unbounded duration", func(e *Evidence){ e.ExpiresAt=e.IssuedAt.Add(24*time.Hour) }},
        {"zero expiry", func(e *Evidence){ e.ExpiresAt=time.Time{} }},
        {"invalid scope", func(e *Evidence){ e.Scope.TenantID="tenant\nadmin" }},
    }
    for _, tc := range bad {
        t.Run(tc.name, func(t *testing.T) {
            item:=evidence
            tc.change(&item)
            if _,err:=VerifySignedEvidence(signedApproval(t,item,pub,priv),pub,scope,now); !errors.Is(err,ErrApprovalRejected) {
                t.Fatalf("%s invalid approval accepted: %v",tc.name,err)
            }
        })
    }
    valid:=signedApproval(t,evidence,pub,priv)
    var wrapper SignedEvidence
    if err:=json.Unmarshal(valid,&wrapper);err!=nil { t.Fatal(err) }
    tests:=[][]byte{
        append([]byte(" "),valid...),
        bytes.Replace(valid,[]byte(`"key_id":`),[]byte(`"extra":true,"key_id":`),1),
        bytes.Replace(valid,[]byte(`"key_id":`),[]byte(`"key_id":"duplicate","key_id":`),1),
        bytes.Replace(valid,[]byte(`"signature":`),[]byte(`"signature":[],"signature":`),1),
        append(valid,[]byte(" null")...),
    }
    for i, wire:=range tests {
        if _,err:=VerifySignedEvidence(wire,pub,scope,now);!errors.Is(err,ErrApprovalRejected) {
            t.Fatalf("noncanonical envelope %d accepted: %v",i,err)
        }
    }
    // Even when re-signed by the pinned key, unknown and duplicate payload
    // fields must not gain an unreviewed interpretation.
    raw := bytes.Replace(wrapper.Payload,[]byte(`"decision":`),[]byte(`"decision":"APPROVED","decision":`),1)
    fingerprint:=sha256.Sum256(pub)
    msg:=append([]byte("engageguard/approval-proof/v1\x00"),raw...)
    duplicate,_:=json.Marshal(SignedEvidence{KeyID:hex.EncodeToString(fingerprint[:]),
        Payload:raw,Signature:ed25519.Sign(priv,msg)})
    if _,err:=VerifySignedEvidence(duplicate,pub,scope,now);!errors.Is(err,ErrApprovalRejected) {
        t.Fatalf("signed duplicate-key payload accepted: %v",err)
    }
}
