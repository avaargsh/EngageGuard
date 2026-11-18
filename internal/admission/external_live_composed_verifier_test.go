package admission

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
)

type actualACPCapabilityWithHook struct {
	client *ACPCapabilityClient
	after func() error
}

func (c actualACPCapabilityWithHook) VerifyCapabilityAccess(ctx context.Context, p Principal, s RunSafetySnapshot, a action.ActionSubmission) error {
	if err := c.client.VerifyCapabilityAccess(ctx,p,s,a);err!=nil{return err}
	if c.after!=nil{return c.after()}
	return nil
}

// Live authorities are compiled from separate repositories. The exact
// same Run, original Decision/Step, ACP release and breaker are observed
// in ONE ComposedRunVerifier invocation. No synthetic authority responses.
func TestExternalLiveComposedRunVerifier(t *testing.T) {
	if os.Getenv("GUARD_EXTERNAL_LIVE_COMPOSED")!="1" {t.Skip("source-pinned live three-authority gate only")}
	required:=func(k string) string {t.Helper();v:=os.Getenv(k);if v==""{t.Fatalf("missing trusted test context %s",k)};return v}
	certRoots:=func(prefix string)(*x509.CertPool,tls.Certificate){
		t.Helper()
		raw,err:=os.ReadFile(required(prefix+"_ROOTS"));if err!=nil{t.Fatal(err)}
		roots:=x509.NewCertPool();if !roots.AppendCertsFromPEM(raw){t.Fatal("empty root trust")}
		cert,err:=tls.LoadX509KeyPair(required(prefix+"_CERT"),required(prefix+"_KEY"));if err!=nil{t.Fatal(err)}
		return roots,cert
	}
	tenant,runID:=required("GUARD_COMPOSED_TENANT"),required("GUARD_COMPOSED_RUN")
	rRoots,rCert:=certRoots("GUARD_COMPOSED_RUNTIME")
	dRoots,dCert:=certRoots("GUARD_COMPOSED_DECISION")
	aRoots,aCert:=certRoots("GUARD_COMPOSED_ACP")
	runtime,err:=NewRuntimeRunSafetyClient(required("GUARD_COMPOSED_RUNTIME_ORIGIN"),required("GUARD_COMPOSED_RUNTIME_PEER"),tenant,rRoots,rCert)
	if err!=nil{t.Fatal(err)};defer runtime.CloseIdleConnections()
	decision,err:=NewDecisionPlanClient(required("GUARD_COMPOSED_DECISION_ORIGIN"),required("GUARD_COMPOSED_DECISION_PEER"),tenant,dRoots,dCert)
	if err!=nil{t.Fatal(err)};defer decision.CloseIdleConnections()
	acp,err:=NewACPCapabilityClient(required("GUARD_COMPOSED_ACP_ORIGIN"),required("GUARD_COMPOSED_ACP_PEER"),tenant,aRoots,aCert)
	if err!=nil{t.Fatal(err)};defer acp.CloseIdleConnections()
	parse:=func(k string)uint64 {t.Helper();n,e:=strconv.ParseUint(required(k),10,64);if e!=nil||n==0{t.Fatalf("invalid %s",k)};return n}
	scope:=RunSafetySnapshot{TenantID:tenant,RunID:runID,
		AgentID:required("GUARD_COMPOSED_AGENT"),AgentReleaseID:required("GUARD_COMPOSED_RELEASE"),
		SessionID:required("GUARD_COMPOSED_SESSION"),Status:"RUNNING",BreakerState:"CLOSED",
		BreakerEpoch:parse("GUARD_COMPOSED_BREAKER_EPOCH"),BreakerVersion:parse("GUARD_COMPOSED_BREAKER_VERSION")}
	principal:=Principal{TenantID:tenant,SubjectID:"subject-1",ActorID:"subject-1",
		WorkloadID:"real-guard-test-client",ServiceID:"agent-runtime"}
	submission:=action.ActionSubmission{SchemaVersion:"action-submission.v1",RunID:runID,
		DecisionID:required("GUARD_COMPOSED_DECISION_ID"),PlanID:required("GUARD_COMPOSED_PLAN_ID"),
		PlanHash:required("GUARD_COMPOSED_PLAN_HASH"),StepID:required("GUARD_COMPOSED_STEP_ID"),
		Capability:action.ActionCapabilitySelector{ID:required("GUARD_COMPOSED_CAP_ID"),Version:required("GUARD_COMPOSED_CAP_VERSION")},
		ResourceRef:required("GUARD_COMPOSED_RESOURCE"),Arguments:json.RawMessage("{}")}
	if err:=submission.Validate();err!=nil{t.Fatal(err)}
	capability:=actualACPCapabilityWithHook{client:acp}
	mode:=required("GUARD_COMPOSED_EXPECT")
	if mode=="postflight" {
		dir:=required("GUARD_COMPOSED_SYNC_DIR")
		capability.after=func() error {
			ready:=filepath.Join(dir,"postflight-capability-verified")
			if err:=os.WriteFile(ready,[]byte(runID),0600);err!=nil{return err}
			deadline:=time.Now().Add(12*time.Second)
			for time.Now().Before(deadline) {
				if b,err:=os.ReadFile(filepath.Join(dir,"postflight-breaker-changed"));err==nil&&string(b)==runID{return nil}
				time.Sleep(40*time.Millisecond)
			}
			return ErrAuthorityUnavailable
		}
	}
	composed,err:=NewComposedRunVerifier(runtime,decision,capability)
	if err!=nil{t.Fatal(err)}
	ctx,cancel:=context.WithTimeout(context.Background(),25*time.Second);defer cancel()
	got:=composed.VerifySubmission(ctx,principal,submission)
	switch mode {
	case "verified":
		if got!=nil{t.Fatalf("three live independent authorities denied one Run: %v",got)}
		// Wrong Step/target and effectful request never become a Permit.
		bad:=submission;bad.Capability.ID="workspace.write"
		if e:=composed.VerifySubmission(ctx,principal,bad);!errors.Is(e,ErrForbidden){
			t.Fatalf("effectful capability unexpectedly verified: %v",e)
		}
		t.Logf("real ComposedRunVerifier verified three authorities on same-Run %s",runID)
	case "postflight":
		if !errors.Is(got,ErrForbidden){t.Fatalf("live breaker generation changed but postflight accepted: %v",got)}
		if err:=os.WriteFile(filepath.Join(required("GUARD_COMPOSED_SYNC_DIR"),"postflight-denied"),[]byte(runID),0600);err!=nil{t.Fatal(err)}
		// The disposable owner must restore the original Runtime fixture
		// before Decision continues its subsequent source-revoke checks.
		restored:=false
		for until:=time.Now().Add(12*time.Second);time.Now().Before(until);{
			b,e:=os.ReadFile(filepath.Join(required("GUARD_COMPOSED_SYNC_DIR"),"postflight-restored"))
			if e==nil && string(b)==runID {restored=true;break}
			time.Sleep(40*time.Millisecond)
		}
		if !restored {t.Fatal("test-only breaker recovery did not complete")}
		t.Logf("real ComposedRunVerifier denied live postflight breaker drift same-Run %s",runID)
	case "revoked":
		if !errors.Is(got,ErrForbidden){t.Fatalf("source revoked but three-authority composite accepted: %v",got)}
		t.Logf("real ComposedRunVerifier denied revoked source same-Run %s",runID)
	default:
		t.Fatalf("unsupported composed verification expectation %q",mode)
	}
	// The independent sources, not a forwarded caller field, own both
	// current policy and Breaker Generation. This verifier never issues a Permit.
	if strings.Contains(runID,"/"){t.Fatal("noncanonical business identity")}
}
