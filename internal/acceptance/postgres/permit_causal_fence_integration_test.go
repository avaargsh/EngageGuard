package postgres

import (
    "context"
    "errors"
    "testing"

    "github.com/avaargsh/EngageGuard/internal/action"
)

func TestPermitStateChangesRequireCausalEvidenceAtCommit(t *testing.T) {
    for _,tc:=range []struct{name string;sql string}{
        {"claim without intent or audit", "UPDATE guard_permits SET state='CLAIMED',claimed_at=clock_timestamp() WHERE permit_id=$1::uuid"},
        {"revoke without journal", "UPDATE guard_permits SET revoked_at=clock_timestamp() WHERE permit_id=$1::uuid"},
    }{
        t.Run(tc.name,func(t *testing.T){
            store,_,permitID:=seededWorkspacePermit(t)
            tx,err:=store.db.BeginTx(context.Background(),nil)
            if err!=nil{t.Fatal(err)}
            defer tx.Rollback()
            if _,err=tx.ExecContext(context.Background(),tc.sql,permitID);err!=nil{t.Fatalf("legitimate v9 transition unexpectedly rejected before commit: %v",err)}
            if err=tx.Commit();err==nil{t.Fatal("state change committed without required immutable causal evidence")}
            var state string
            var revoked bool
            if err:=store.db.QueryRow("SELECT state,revoked_at IS NOT NULL FROM guard_permits WHERE permit_id=$1::uuid",permitID).Scan(&state,&revoked);err!=nil{t.Fatal(err)}
            if state!="ISSUED"||revoked{t.Fatalf("partial unauthorized state survived rollback: %s/%t",state,revoked)}
        })
    }
}

func TestPermitClaimRequiresCompleteMatchingIntentAudit(t *testing.T) {
    store,resolved,permitID:=seededWorkspacePermit(t)
    hash,err:=action.Hash(resolved)
    if err!=nil {t.Fatal(err)}
    tx,err:=store.db.BeginTx(context.Background(),nil)
    if err!=nil{t.Fatal(err)}
    defer tx.Rollback()
    if _,err=tx.ExecContext(context.Background(), "UPDATE guard_permits SET state='CLAIMED',claimed_at=clock_timestamp() WHERE permit_id=$1::uuid",permitID);err!=nil{t.Fatal(err)}
    if _,err=tx.ExecContext(context.Background(), `
        INSERT INTO guard_operation_intents (tenant_id,operation_id,permit_id,action_hash,binding_digest,state)
        VALUES ($1,$2::uuid,$3::uuid,$4,$5,'DISPATCHING')
    `,resolved.TenantID,resolved.OperationID,permitID,hash,resolved.ToolBindingDigest);err!=nil{t.Fatal(err)}
    if err=tx.Commit();err==nil{t.Fatal("claimed Permit committed with an Intent but no audit")}
    if _,err:=store.ClaimAuthorizedIntent(context.Background(),permitID,resolved);err!=nil{t.Fatalf("valid claim failed after rollback: %v",err)}
    if changed,err:=store.RevokeScopedPermit(context.Background(),resolved.TenantID,permitID,"causal-test","SECURITY_RESPONSE");err!=nil||!changed{t.Fatalf("valid claimed revocation failed: %t %v",changed,err)}
    if err:=Migrate(context.Background(),store.db);err!=nil{t.Fatalf("valid migration catalog rejected: %v",err)}
}

func TestMissingPermitCausalFenceTriggerFailsSchemaVerification(t *testing.T){
    store,_,_:=seededWorkspacePermit(t)
    if _,err:=store.db.Exec("ALTER TABLE guard_permits DISABLE TRIGGER guard_permit_causal_transition_v10");err!=nil{t.Fatal(err)}
    if err:=Migrate(context.Background(),store.db);!errors.Is(err,ErrSchemaDrift){t.Fatalf("missing always-on causal fence was accepted: %v",err)}
}
