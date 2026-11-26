package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avaargsh/EngageGuard/internal/provider"
)

type providerInspectorFunc func(context.Context, provider.Attempt) (provider.Observation, error)

func (f providerInspectorFunc) Inspect(ctx context.Context, attempt provider.Attempt) (provider.Observation, error) {
	return f(ctx, attempt)
}

type providerVerifier struct {
	id  string
	err error
}

func (v providerVerifier) VerifierID() string { return v.id }

func (v providerVerifier) Verify(context.Context, provider.Attempt, provider.Observation) error {
	return v.err
}

func providerObservationFor(attempt provider.Attempt, outcome provider.Outcome, evidence string) provider.Observation {
	raw := []byte(evidence)
	digest := providerEvidenceDigest(raw)
	now := time.Date(2026, 11, 26, 4, 0, 0, 0, time.UTC)
	observation := provider.Observation{
		Outcome: outcome, ProviderID: attempt.ProviderID,
		Evidence: raw, EvidenceDigest: digest, ObservedAt: now,
	}
	if outcome == provider.OutcomeFound || outcome == provider.OutcomeFailedConfirmed {
		effect := provider.EffectApplied
		if outcome == provider.OutcomeFailedConfirmed {
			effect = provider.EffectNotApplied
		}
		observation.Receipt = &provider.Receipt{
			ProviderID: attempt.ProviderID, ReceiptID: "receipt-1",
			TenantID: attempt.TenantID, OperationID: attempt.OperationID,
			AttemptID: attempt.AttemptID, IdempotencyKey: attempt.IdempotencyKey,
			ActionHash: attempt.ActionHash, Effect: effect,
			EvidenceDigest: digest, ObservedAt: now,
		}
	}
	return observation
}

func providerEvidenceDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func prepareUnknownProviderAttempt(t *testing.T) (*Store, provider.Attempt) {
	t.Helper()
	store, resolved, permitID := seededWorkspacePermit(t)
	ctx := context.Background()
	intent, err := store.ClaimAuthorizedIntent(ctx, permitID, resolved)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkDispatchUnknown(ctx, resolved.TenantID, resolved.OperationID, intent.AttemptID, "ACK_LOST"); err != nil {
		t.Fatal(err)
	}
	return store, provider.Attempt{
		ProviderID: "provider.test.v1", TenantID: resolved.TenantID,
		OperationID: resolved.OperationID, PermitID: permitID,
		AttemptID: intent.AttemptID,
		IdempotencyKey: "engageguard/" + resolved.OperationID + "/" + intent.AttemptID,
		ActionHash: intent.ActionHash,
	}
}

func TestReconcileProviderPersistsVerifiedObservationAcrossStoreRecreation(t *testing.T) {
	store, attempt := prepareUnknownProviderAttempt(t)
	ctx := context.Background()
	observation := providerObservationFor(attempt, provider.OutcomeFound, "signed provider receipt v1")
	inspector := providerInspectorFunc(func(context.Context, provider.Attempt) (provider.Observation, error) {
		return observation, nil
	})
	verifier := providerVerifier{id: "test-receipt-verifier/v1"}

	first, err := store.ReconcileProvider(ctx, attempt, inspector, verifier)
	if err != nil {
		t.Fatalf("persist verified provider receipt: %v", err)
	}
	if first.Resolution != provider.ResolutionEffectObserved || first.VerifierID != verifier.id ||
		first.Observation.Receipt == nil || first.Observation.Receipt.ReceiptID != "receipt-1" {
		t.Fatalf("unexpected persisted observation: %+v", first)
	}

	restarted := newPinnedStoreCopy(t, store)
	records, err := restarted.ListProviderObservations(ctx, attempt.TenantID, attempt.OperationID, attempt.AttemptID)
	if err != nil || len(records) != 1 {
		t.Fatalf("read durable provider observation: count=%d err=%v", len(records), err)
	}
	if records[0].ObservationID != first.ObservationID ||
		records[0].EvidenceDigest != observation.EvidenceDigest ||
		records[0].VerifierID != verifier.id ||
		string(records[0].Observation.Evidence) != string(observation.Evidence) {
		t.Fatalf("persisted receipt changed across store recreation: %+v", records[0])
	}

	// Exact evidence replay is idempotent and never creates a second row.
	second, err := restarted.ReconcileProvider(ctx, attempt, inspector, verifier)
	if err != nil || second.ObservationID != first.ObservationID {
		t.Fatalf("exact provider evidence replay: first=%+v second=%+v err=%v", first, second, err)
	}
	records, err = restarted.ListProviderObservations(ctx, attempt.TenantID, attempt.OperationID, attempt.AttemptID)
	if err != nil || len(records) != 1 {
		t.Fatalf("duplicate receipt row created: count=%d err=%v", len(records), err)
	}

	// Recording evidence is not a state transition or a redispatch grant.
	state, err := restarted.GetDispatchState(ctx, attempt.TenantID, attempt.OperationID, attempt.AttemptID)
	if err != nil || state.State != "UNKNOWN" {
		t.Fatalf("provider receipt silently rewrote UNKNOWN: state=%+v err=%v", state, err)
	}
}

func TestReconcileProviderRequiresCommittedUnknownBeforeProviderCall(t *testing.T) {
	store, resolved, permitID := seededWorkspacePermit(t)
	intent, err := store.ClaimAuthorizedIntent(context.Background(), permitID, resolved)
	if err != nil {
		t.Fatal(err)
	}
	attempt := provider.Attempt{
		ProviderID: "provider.test.v1", TenantID: resolved.TenantID,
		OperationID: resolved.OperationID, PermitID: permitID,
		AttemptID: intent.AttemptID, IdempotencyKey: "key-1", ActionHash: intent.ActionHash,
	}
	calls := 0
	_, err = store.ReconcileProvider(context.Background(), attempt,
		providerInspectorFunc(func(context.Context, provider.Attempt) (provider.Observation, error) {
			calls++
			return providerObservationFor(attempt, provider.OutcomeAbsentUncertain, "provider query"), nil
		}),
		providerVerifier{id: "test-receipt-verifier/v1"},
	)
	if !errors.Is(err, ErrProviderObservationNotUnknown) || calls != 0 {
		t.Fatalf("provider inspection before durable UNKNOWN was not fenced: calls=%d err=%v", calls, err)
	}
}

func TestReconcileProviderVerifierFailureDoesNotPersistEvidence(t *testing.T) {
	store, attempt := prepareUnknownProviderAttempt(t)
	_, err := store.ReconcileProvider(context.Background(), attempt,
		providerInspectorFunc(func(context.Context, provider.Attempt) (provider.Observation, error) {
			return providerObservationFor(attempt, provider.OutcomeFound, "invalid signature"), nil
		}),
		providerVerifier{id: "test-receipt-verifier/v1", err: errors.New("signature rejected")},
	)
	if !errors.Is(err, provider.ErrEvidenceRejected) {
		t.Fatalf("invalid provider evidence accepted: %v", err)
	}
	records, readErr := store.ListProviderObservations(context.Background(), attempt.TenantID, attempt.OperationID, attempt.AttemptID)
	if readErr != nil || len(records) != 0 {
		t.Fatalf("unverified evidence persisted: records=%d err=%v", len(records), readErr)
	}
}

func TestReconcileProviderRejectsConflictingTerminalEvidence(t *testing.T) {
	store, attempt := prepareUnknownProviderAttempt(t)
	ctx := context.Background()
	verifier := providerVerifier{id: "test-receipt-verifier/v1"}
	first := providerObservationFor(attempt, provider.OutcomeFound, "same provider bytes")
	if _, err := store.ReconcileProvider(ctx, attempt,
		providerInspectorFunc(func(context.Context, provider.Attempt) (provider.Observation, error) { return first, nil }),
		verifier); err != nil {
		t.Fatal(err)
	}
	conflicting := providerObservationFor(attempt, provider.OutcomeFailedConfirmed, "same provider bytes")
	_, err := store.ReconcileProvider(ctx, attempt,
		providerInspectorFunc(func(context.Context, provider.Attempt) (provider.Observation, error) { return conflicting, nil }),
		verifier)
	if !errors.Is(err, ErrProviderObservationConflict) {
		t.Fatalf("same evidence digest with contradictory outcome accepted: %v", err)
	}
	records, err := store.ListProviderObservations(ctx, attempt.TenantID, attempt.OperationID, attempt.AttemptID)
	if err != nil || len(records) != 1 || records[0].Observation.Outcome != provider.OutcomeFound {
		t.Fatalf("conflict mutated append-only provider evidence: records=%+v err=%v", records, err)
	}
}

func TestReconcileProviderConcurrentSameEvidenceIsIdempotent(t *testing.T) {
	store, attempt := prepareUnknownProviderAttempt(t)
	ctx := context.Background()
	observation := providerObservationFor(attempt, provider.OutcomeAbsentUncertain, "provider lookup has no receipt")
	inspector := providerInspectorFunc(func(context.Context, provider.Attempt) (provider.Observation, error) {
		return observation, nil
	})
	verifier := providerVerifier{id: "test-receipt-verifier/v1"}
	const workers = 12
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	ids := make(chan string, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			record, err := store.ReconcileProvider(ctx, attempt, inspector, verifier)
			if err != nil {
				errs <- err
				return
			}
			ids <- record.ObservationID
		}()
	}
	wg.Wait()
	close(errs)
	close(ids)
	for err := range errs {
		t.Fatalf("concurrent exact evidence replay failed: %v", err)
	}
	var first string
	for id := range ids {
		if first == "" {
			first = id
		} else if first != id {
			t.Fatalf("same provider evidence created multiple IDs: %s != %s", first, id)
		}
	}
	records, err := store.ListProviderObservations(ctx, attempt.TenantID, attempt.OperationID, attempt.AttemptID)
	if err != nil || len(records) != 1 || records[0].Resolution != provider.ResolutionRemainUnknown {
		t.Fatalf("concurrent UNKNOWN observations not idempotent: records=%+v err=%v", records, err)
	}
}

func TestProviderObservationLedgerRejectsMutationAndCrossAttemptRead(t *testing.T) {
	store, attempt := prepareUnknownProviderAttempt(t)
	ctx := context.Background()
	observation := providerObservationFor(attempt, provider.OutcomeAbsentUncertain, "provider lookup evidence")
	if _, err := store.ReconcileProvider(ctx, attempt,
		providerInspectorFunc(func(context.Context, provider.Attempt) (provider.Observation, error) { return observation, nil }),
		providerVerifier{id: "test-receipt-verifier/v1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListProviderObservations(ctx, "tenant-b", attempt.OperationID, attempt.AttemptID); err != nil {
		t.Fatalf("cross-tenant read must be indistinguishable from empty: %v", err)
	}
	for _, statement := range []string{
		"UPDATE guard_provider_observations SET verifier_id='forged'",
		"DELETE FROM guard_provider_observations",
		"TRUNCATE guard_provider_observations",
	} {
		if _, err := store.db.ExecContext(ctx, statement); err == nil {
			t.Errorf("immutable provider evidence allowed mutation: %s", statement)
		}
	}
}
