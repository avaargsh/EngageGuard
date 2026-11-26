package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

type inspectorFunc func(context.Context, Attempt) (Observation, error)

func (f inspectorFunc) Inspect(ctx context.Context, attempt Attempt) (Observation, error) {
	return f(ctx, attempt)
}

type verifierFunc func(context.Context, Attempt, Observation) error

func (f verifierFunc) Verify(ctx context.Context, attempt Attempt, observation Observation) error {
	return f(ctx, attempt, observation)
}

func reconciliationAttempt() Attempt {
	attempt := Attempt{
		ProviderID:  "provider.workspace.v1",
		TenantID:    "tenant-a",
		OperationID: "11111111-1111-4111-8111-111111111111",
		PermitID:    "33333333-3333-4333-8333-333333333333",
		AttemptID:   "22222222-2222-4222-8222-222222222222",
		ActionHash:  strings.Repeat("a", 64),
	}
	attempt.IdempotencyKey = ExpectedIdempotencyKey(attempt)
	return attempt
}

func reconciliationObservation(attempt Attempt, outcome Outcome) Observation {
	now := time.Date(2026, 11, 26, 3, 0, 0, 0, time.UTC)
	evidence := []byte("signed provider observation")
	digest := sha256.Sum256(evidence)
	observation := Observation{
		Outcome:        outcome,
		ProviderID:     attempt.ProviderID,
		Evidence:       evidence,
		EvidenceDigest: hex.EncodeToString(digest[:]),
		ObservedAt:     now,
	}
	if outcome != OutcomeAbsentUncertain {
		effect := EffectApplied
		if outcome == OutcomeFailedConfirmed {
			effect = EffectNotApplied
		}
		observation.Receipt = &Receipt{
			ProviderID:     attempt.ProviderID,
			ReceiptID:      "receipt-123",
			TenantID:       attempt.TenantID,
			OperationID:    attempt.OperationID,
			AttemptID:      attempt.AttemptID,
			IdempotencyKey: attempt.IdempotencyKey,
			ActionHash:     attempt.ActionHash,
			Effect:         effect,
			EvidenceDigest: observation.EvidenceDigest,
			ObservedAt:     now,
		}
	}
	return observation
}

func TestReconcileProviderOutcome(t *testing.T) {
	for _, tc := range []struct {
		name    string
		outcome Outcome
		want    Resolution
	}{
		{"effect found", OutcomeFound, ResolutionEffectObserved},
		{"absence remains uncertain", OutcomeAbsentUncertain, ResolutionRemainUnknown},
		{"failure confirmed without effect", OutcomeFailedConfirmed, ResolutionNoEffectConfirmed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempt := reconciliationAttempt()
			observation := reconciliationObservation(attempt, tc.outcome)
			inspected, verified := 0, 0
			got, err := Reconcile(context.Background(), attempt,
				inspectorFunc(func(_ context.Context, received Attempt) (Observation, error) {
					inspected++
					if received != attempt {
						t.Fatalf("inspector received changed attempt: %+v", received)
					}
					return observation, nil
				}),
				verifierFunc(func(_ context.Context, received Attempt, got Observation) error {
					verified++
					if received != attempt || got.Outcome != tc.outcome {
						t.Fatalf("verifier received wrong evidence: %+v %+v", received, got)
					}
					return nil
				}),
			)
			if err != nil || got != tc.want {
				t.Fatalf("resolution=%q want=%q err=%v", got, tc.want, err)
			}
			if inspected != 1 || verified != 1 {
				t.Fatalf("inspection/verification calls=%d/%d", inspected, verified)
			}
		})
	}
}

func TestReconcileRejectsMismatchedProviderReceipt(t *testing.T) {
	attempt := reconciliationAttempt()
	for _, mutate := range []struct {
		name   string
		change func(*Receipt)
	}{
		{"provider", func(r *Receipt) { r.ProviderID = "provider.other" }},
		{"tenant", func(r *Receipt) { r.TenantID = "tenant-b" }},
		{"operation", func(r *Receipt) { r.OperationID = "33333333-3333-4333-8333-333333333333" }},
		{"attempt", func(r *Receipt) { r.AttemptID = "44444444-4444-4444-8444-444444444444" }},
		{"idempotency key", func(r *Receipt) { r.IdempotencyKey = "different-key" }},
		{"action hash", func(r *Receipt) { r.ActionHash = strings.Repeat("c", 64) }},
		{"evidence digest", func(r *Receipt) { r.EvidenceDigest = strings.Repeat("d", 64) }},
		{"missing receipt id", func(r *Receipt) { r.ReceiptID = "" }},
		{"missing observation time", func(r *Receipt) { r.ObservedAt = time.Time{} }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			observation := reconciliationObservation(attempt, OutcomeFound)
			mutate.change(observation.Receipt)
			verified := 0
			_, err := Reconcile(context.Background(), attempt,
				inspectorFunc(func(context.Context, Attempt) (Observation, error) { return observation, nil }),
				verifierFunc(func(context.Context, Attempt, Observation) error { verified++; return nil }),
			)
			if !errors.Is(err, ErrInvalidObservation) {
				t.Fatalf("mismatched receipt must fail closed: %v", err)
			}
			if verified != 0 {
				t.Fatalf("unbound receipt reached evidence verifier: %d", verified)
			}
		})
	}
}

func TestReconcileRequiresShapeConsistentEvidence(t *testing.T) {
	attempt := reconciliationAttempt()
	cases := []struct {
		name   string
		change func(*Observation)
	}{
		{"unknown outcome", func(o *Observation) { o.Outcome = Outcome("MAYBE") }},
		{"missing provider", func(o *Observation) { o.ProviderID = "" }},
		{"wrong provider", func(o *Observation) { o.ProviderID = "provider.other" }},
		{"bad evidence digest", func(o *Observation) { o.EvidenceDigest = "not-a-sha256" }},
		{"missing observed time", func(o *Observation) { o.ObservedAt = time.Time{} }},
		{"missing raw evidence", func(o *Observation) { o.Evidence = nil }},
		{"evidence digest mismatch", func(o *Observation) { o.EvidenceDigest = strings.Repeat("d", 64) }},
		{"found receipt says no effect", func(o *Observation) { o.Receipt.Effect = EffectNotApplied }},
		{"failed receipt says effect applied", func(o *Observation) { o.Outcome = OutcomeFailedConfirmed; o.Receipt.Effect = EffectApplied }},
		{"found without receipt", func(o *Observation) { o.Receipt = nil }},
		{"failed without receipt", func(o *Observation) { o.Outcome = OutcomeFailedConfirmed; o.Receipt = nil }},
		{"absent with receipt", func(o *Observation) { o.Outcome = OutcomeAbsentUncertain }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			observation := reconciliationObservation(attempt, OutcomeFound)
			tc.change(&observation)
			_, err := Reconcile(context.Background(), attempt,
				inspectorFunc(func(context.Context, Attempt) (Observation, error) { return observation, nil }),
				verifierFunc(func(context.Context, Attempt, Observation) error { return nil }),
			)
			if !errors.Is(err, ErrInvalidObservation) {
				t.Fatalf("invalid evidence must fail closed: %v", err)
			}
		})
	}
}

func TestReconcileNeverPromotesUncertainAbsenceToRetry(t *testing.T) {
	attempt := reconciliationAttempt()
	observation := reconciliationObservation(attempt, OutcomeAbsentUncertain)
	got, err := Reconcile(context.Background(), attempt,
		inspectorFunc(func(context.Context, Attempt) (Observation, error) { return observation, nil }),
		verifierFunc(func(context.Context, Attempt, Observation) error { return nil }),
	)
	if err != nil || got != ResolutionRemainUnknown {
		t.Fatalf("absence without proof must remain UNKNOWN, got=%q err=%v", got, err)
	}
}

func TestReconcileFailsClosedOnInspectionAndVerificationErrors(t *testing.T) {
	attempt := reconciliationAttempt()
	sourceErr := errors.New("provider inspection unavailable")
	if _, err := Reconcile(context.Background(), attempt,
		inspectorFunc(func(context.Context, Attempt) (Observation, error) { return Observation{}, sourceErr }),
		verifierFunc(func(context.Context, Attempt, Observation) error { return nil }),
	); !errors.Is(err, ErrUnavailable) || !errors.Is(err, sourceErr) {
		t.Fatalf("inspection outage must remain unavailable: %v", err)
	}
	verifyErr := errors.New("provider signature invalid")
	observation := reconciliationObservation(attempt, OutcomeFound)
	if _, err := Reconcile(context.Background(), attempt,
		inspectorFunc(func(context.Context, Attempt) (Observation, error) { return observation, nil }),
		verifierFunc(func(context.Context, Attempt, Observation) error { return verifyErr }),
	); !errors.Is(err, ErrEvidenceRejected) || !errors.Is(err, verifyErr) {
		t.Fatalf("untrusted provider evidence must be rejected: %v", err)
	}
}

func TestReconcileHonorsCancellationBetweenProviderAndVerification(t *testing.T) {
	attempt := reconciliationAttempt()
	ctx, cancel := context.WithCancel(context.Background())
	observation := reconciliationObservation(attempt, OutcomeFound)
	verified := 0
	_, err := Reconcile(ctx, attempt,
		inspectorFunc(func(context.Context, Attempt) (Observation, error) { cancel(); return observation, nil }),
		verifierFunc(func(context.Context, Attempt, Observation) error { verified++; return nil }),
	)
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reconciliation must be unavailable: %v", err)
	}
	if verified != 0 {
		t.Fatalf("verification started after cancellation: %d", verified)
	}
}

func TestReconcileRejectsInvalidAttemptAndMissingDependencies(t *testing.T) {
	attempt := reconciliationAttempt()
	inspector := inspectorFunc(func(context.Context, Attempt) (Observation, error) { return Observation{}, nil })
	verifier := verifierFunc(func(context.Context, Attempt, Observation) error { return nil })
	if _, err := Reconcile(context.Background(), attempt, nil, verifier); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing inspector: %v", err)
	}
	if _, err := Reconcile(context.Background(), attempt, inspector, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing verifier: %v", err)
	}
	attempt.ActionHash = "bad"
	if _, err := Reconcile(context.Background(), attempt, inspector, verifier); !errors.Is(err, ErrInvalidAttempt) {
		t.Fatalf("invalid attempt must be rejected: %v", err)
	}
}

func TestReconcileHonorsCancellationDuringEvidenceVerification(t *testing.T) {
	attempt := reconciliationAttempt()
	ctx, cancel := context.WithCancel(context.Background())
	observation := reconciliationObservation(attempt, OutcomeFound)
	_, err := Reconcile(ctx, attempt,
		inspectorFunc(func(context.Context, Attempt) (Observation, error) { return observation, nil }),
		verifierFunc(func(context.Context, Attempt, Observation) error {
			cancel()
			return context.Canceled
		}),
	)
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled evidence verification must be unavailable, not rejected: %v", err)
	}
	if errors.Is(err, ErrEvidenceRejected) {
		t.Fatalf("context cancellation was misclassified as invalid evidence: %v", err)
	}
}

func TestReconcileVerifiedReturnsDetachedEvidenceAfterVerifier(t *testing.T) {
	attempt := reconciliationAttempt()
	original := reconciliationObservation(attempt, OutcomeFound)
	result, err := ReconcileVerified(context.Background(), attempt,
		inspectorFunc(func(context.Context, Attempt) (Observation, error) { return original, nil }),
		verifierFunc(func(_ context.Context, _ Attempt, observation Observation) error {
			observation.Evidence[0] = 'X'
			observation.Receipt.ReceiptID = "mutated-by-verifier"
			return nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Observation.Evidence) != string(original.Evidence) ||
		result.Observation.Receipt.ReceiptID != "receipt-123" {
		t.Fatalf("verifier mutated returned persistence evidence: %+v", result.Observation)
	}
	result.Observation.Evidence[0] = 'Y'
	if string(original.Evidence) == string(result.Observation.Evidence) {
		t.Fatal("verified result shares mutable evidence with provider adapter")
	}
}

func TestExpectedIdempotencyKeyIsStableAndAttemptBound(t *testing.T) {
	attempt := reconciliationAttempt()
	key := attempt.IdempotencyKey
	if key == "" || key != ExpectedIdempotencyKey(attempt) {
		t.Fatalf("idempotency key is not deterministic: %q", key)
	}
	for _, mutate := range []func(*Attempt){
		func(a *Attempt) { a.ProviderID = "provider.other.v1" },
		func(a *Attempt) { a.TenantID = "tenant-b" },
		func(a *Attempt) { a.PermitID = "44444444-4444-4444-8444-444444444444" },
		func(a *Attempt) { a.AttemptID = "55555555-5555-4555-8555-555555555555" },
		func(a *Attempt) { a.ActionHash = strings.Repeat("c", 64) },
	} {
		changed := attempt
		mutate(&changed)
		if ExpectedIdempotencyKey(changed) == key {
			t.Fatal("idempotency key did not change with immutable Attempt identity")
		}
		if err := ValidateAttempt(changed); !errors.Is(err, ErrInvalidAttempt) {
			t.Fatalf("changed Attempt reused old idempotency key: %v", err)
		}
	}
}
