package approval

import (
    "crypto/ed25519"
    "errors"
    "strings"
    "testing"
    "time"

    "github.com/avaargsh/EngageGuard/internal/action"
)

func trustedWorkspaceAction() action.WorkspaceWrite {
    return action.WorkspaceWrite{
        SchemaVersion: "v0.1", TenantID: "tenant-1", SubjectID: "subject-001",
        AgentID: "agent-001", OperationID: "11111111-1111-4111-8111-111111111111",
        CapabilityID: "workspace.write",
        ToolBindingDigest: strings.Repeat("d",64),
        PolicyVersion: "policy-001", Audience: "trusted-workspace-executor",
        WorkspaceID: "workspace-001", RelativePath: "docs/output.md",
        ContentDigest: strings.Repeat("e",64),
    }
}

func trustedDecisionExecution() ExecutionBinding {
    return ExecutionBinding{
        RunID: "run-001", AttemptID: "attempt-001", TurnID: "turn-001",
        AgentReleaseID: "release-001",
        DecisionID: "dec_" + strings.Repeat("a",64),
        PlanHash: strings.Repeat("b",64), StepID: "step-001",
    }
}

func TestVerifyResolvedWorkspaceApprovalRecomputesExactTrustedActionHash(t *testing.T) {
    now:=time.Date(2026,11,18,9,0,0,0,time.UTC)
    resolved:=trustedWorkspaceAction()
    execution:=trustedDecisionExecution()
    scope,err:=ScopeForResolvedWorkspace(resolved,execution)
    if err!=nil { t.Fatal(err) }
    digest,err:=action.Hash(resolved)
    if err!=nil { t.Fatal(err) }
    if scope.ActionHash!=digest||scope.PolicyVersion!=resolved.PolicyVersion||
        scope.TenantID!=resolved.TenantID||scope.OperationID!=resolved.OperationID||
        scope.ToolBindingDigest!=resolved.ToolBindingDigest||
        scope.SubjectID!=resolved.SubjectID||scope.ResourceRef!=resolved.WorkspaceID {
        t.Fatalf("unbound trusted ActionHash scope: %+v",scope)
    }
    pub,priv,err:=ed25519.GenerateKey(nil)
    if err!=nil { t.Fatal(err) }
    evidence:=Evidence{SchemaVersion:"engageguard.approval-evidence.v1",
        ApprovalID:"operator-approval-001",Decision:"APPROVED",Scope:scope,
        IssuedAt:now.Add(-time.Minute),ExpiresAt:now.Add(time.Minute)}
    proof:=signedApproval(t,evidence,pub,priv)
    accepted,err:=VerifyResolvedWorkspaceApproval(proof,pub,resolved,execution,now)
    if err!=nil||accepted.ApprovalID!=evidence.ApprovalID {
        t.Fatalf("correct resolved action denied: %+v %v",accepted,err)
    }
    changedActions:=[]struct{name string;modify func(*action.WorkspaceWrite)}{
        {"changed content",func(a *action.WorkspaceWrite){ a.ContentDigest=strings.Repeat("f",64) }},
        {"changed path",func(a *action.WorkspaceWrite){ a.RelativePath="docs/other.md" }},
        {"changed workspace",func(a *action.WorkspaceWrite){ a.WorkspaceID="workspace-002" }},
        {"changed tenant",func(a *action.WorkspaceWrite){ a.TenantID="tenant-2" }},
        {"changed subject",func(a *action.WorkspaceWrite){ a.SubjectID="subject-002" }},
        {"changed agent",func(a *action.WorkspaceWrite){ a.AgentID="agent-002" }},
        {"changed policy",func(a *action.WorkspaceWrite){ a.PolicyVersion="policy-002" }},
        {"changed binding",func(a *action.WorkspaceWrite){ a.ToolBindingDigest=strings.Repeat("f",64) }},
        {"changed audience",func(a *action.WorkspaceWrite){ a.Audience="other-executor" }},
        {"changed operation",func(a *action.WorkspaceWrite){ a.OperationID="22222222-2222-4222-8222-222222222222" }},
    }
    for _,tc:=range changedActions {
        t.Run(tc.name,func(t *testing.T){
            changed:=resolved;tc.modify(&changed)
            if _,err:=VerifyResolvedWorkspaceApproval(proof,pub,changed,execution,now);!errors.Is(err,ErrApprovalRejected){
                t.Fatalf("stale approval authorized changed action: %v",err)
            }
        })
    }
    changedExecution:=execution
    changedExecution.TurnID="turn-002"
    if _,err:=VerifyResolvedWorkspaceApproval(proof,pub,resolved,changedExecution,now);!errors.Is(err,ErrApprovalRejected){
        t.Fatalf("approval reused for another Turn: %v",err)
    }
    invalid:=resolved
    invalid.RelativePath="../secret"
    if _,err:=ScopeForResolvedWorkspace(invalid,execution);!errors.Is(err,ErrApprovalRejected){
        t.Fatalf("invalid unresolved action passed scope builder: %v",err)
    }
    changedExecution=execution
    changedExecution.AttemptID=""
    if _,err:=ScopeForResolvedWorkspace(resolved,changedExecution);!errors.Is(err,ErrApprovalRejected){
        t.Fatalf("untrusted missing Attempt accepted: %v",err)
    }
}
