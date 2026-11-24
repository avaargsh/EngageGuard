package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/avaargsh/EngageGuard/internal/action"
)

func TestClaimResolvedActionIntentBindsActionRequestV1Authority(t *testing.T) {
	store, _ := integrationStore(t)
	service, _, resolved := acceptedPermitIssuer(t, store)
	permit, err := service.Issue(context.Background(), resolved)
	if err != nil {
		t.Fatal(err)
	}

	intent, err := store.ClaimResolvedActionIntent(context.Background(), permit.PermitID, resolved)
	if err != nil {
		t.Fatalf("claim exact ActionRequest v1 Permit: %v", err)
	}
	if intent.TenantID != resolved.TenantID ||
		intent.OperationID != resolved.OperationID ||
		intent.PermitID != permit.PermitID ||
		intent.AttemptID == "" ||
		intent.ActionHash != permit.Draft.Values().ActionHash ||
		intent.State != "DISPATCHING" {
		t.Fatalf("claim returned unbound DispatchIntent: %+v", intent)
	}
	if _, err := store.ClaimResolvedActionIntent(context.Background(), permit.PermitID, resolved); !errors.Is(err, ErrPermitAlreadyClaimed) {
		t.Fatalf("second ActionRequest v1 claim=%v, want ErrPermitAlreadyClaimed", err)
	}
}

func TestClaimResolvedActionIntentRejectsRunPlanAndCapabilityDrift(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*action.ActionRequest)
	}{
		{"wrong run", func(a *action.ActionRequest) { a.RunID = "run-other" }},
		{"wrong decision", func(a *action.ActionRequest) { a.DecisionID = "decision-other" }},
		{"wrong plan", func(a *action.ActionRequest) { a.PlanID = "plan-other" }},
		{"wrong plan hash", func(a *action.ActionRequest) { a.PlanHash = strings.Repeat("9", 64) }},
		{"wrong step", func(a *action.ActionRequest) { a.StepID = "step-other" }},
		{"wrong capability id", func(a *action.ActionRequest) { a.Capability.ID = "workspace.delete" }},
		{"wrong capability version", func(a *action.ActionRequest) { a.Capability.Version = "2.0.0" }},
		{"wrong capability contract", func(a *action.ActionRequest) { a.Capability.ContractSHA256 = strings.Repeat("d", 64) }},
		{"wrong resource", func(a *action.ActionRequest) { a.ResourceRef = "workspace-other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := integrationStore(t)
			service, _, resolved := acceptedPermitIssuer(t, store)
			permit, err := service.Issue(context.Background(), resolved)
			if err != nil {
				t.Fatal(err)
			}
			changed := resolved
			tc.change(&changed)
			if _, err := store.ClaimResolvedActionIntent(context.Background(), permit.PermitID, changed); !errors.Is(err, ErrPermitMismatch) {
				t.Fatalf("drifted ActionRequest claim=%v, want ErrPermitMismatch", err)
			}
			var state string
			if err := store.db.QueryRowContext(context.Background(),
				"SELECT state FROM guard_permits WHERE permit_id=$1::uuid", permit.PermitID).Scan(&state); err != nil {
				t.Fatal(err)
			}
			if state != "ISSUED" {
				t.Fatalf("rejected drift changed Permit state to %s", state)
			}
			var intents int
			if err := store.db.QueryRowContext(context.Background(),
				"SELECT count(*) FROM guard_operation_intents WHERE permit_id=$1::uuid", permit.PermitID).Scan(&intents); err != nil {
				t.Fatal(err)
			}
			if intents != 0 {
				t.Fatalf("rejected drift created %d dispatch intents", intents)
			}
		})
	}
}
