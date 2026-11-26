package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
)

var (
	ErrInvalidAttempt     = errors.New("invalid provider reconciliation attempt")
	ErrInvalidObservation = errors.New("invalid provider inspection evidence")
	ErrEvidenceRejected   = errors.New("provider inspection evidence rejected")
	ErrUnavailable        = errors.New("provider inspection unavailable")
)

type Outcome string

const (
	// OutcomeFound means the provider returned a receipt proving the effect exists.
	OutcomeFound Outcome = "FOUND"
	// OutcomeAbsentUncertain means no receipt was found, but absence is not proof
	// that the external effect did not occur.
	OutcomeAbsentUncertain Outcome = "ABSENT_UNCERTAIN"
	// OutcomeFailedConfirmed means a verified provider receipt proves no effect
	// was applied for this exact attempt.
	OutcomeFailedConfirmed Outcome = "FAILED_CONFIRMED"
)

type Effect string

const (
	EffectApplied    Effect = "APPLIED"
	EffectNotApplied Effect = "NOT_APPLIED"
)

type Resolution string

const (
	ResolutionEffectObserved    Resolution = "EFFECT_OBSERVED"
	ResolutionRemainUnknown     Resolution = "REMAIN_UNKNOWN"
	ResolutionNoEffectConfirmed Resolution = "NO_EFFECT_CONFIRMED"
)

// Attempt is the immutable identity used for provider idempotency and receipt
// lookup. The idempotency key is stable across retries of this one attempt.
type Attempt struct {
	ProviderID     string
	TenantID       string
	OperationID    string
	PermitID       string
	AttemptID      string
	IdempotencyKey string
	ActionHash     string
}

// Receipt is a provider result bound to the exact Guard attempt. EvidenceDigest
// is the SHA-256 digest of the provider's authenticated receipt bytes.
type Receipt struct {
	ProviderID     string
	ReceiptID      string
	TenantID       string
	OperationID    string
	AttemptID      string
	IdempotencyKey string
	ActionHash     string
	Effect         Effect
	EvidenceDigest string
	ObservedAt     time.Time
}

// Observation is a provider's receipt lookup result. ABSENT_UNCERTAIN carries
// authenticated query evidence but no receipt; it must never authorize retry.
type Observation struct {
	Outcome        Outcome
	ProviderID     string
	Evidence       []byte
	EvidenceDigest string
	ObservedAt     time.Time
	Receipt        *Receipt
}

// VerifiedResult is returned only after structural validation and the
// configured EvidenceVerifier both accept the exact provider evidence.
type VerifiedResult struct {
	Resolution  Resolution
	Observation Observation
}

// Inspector is deliberately read-only. This package exposes no dispatch method.
type Inspector interface {
	Inspect(context.Context, Attempt) (Observation, error)
}

// EvidenceVerifier authenticates provider evidence and validates provider-
// specific semantics (including the meaning of NOT_APPLIED). It must be backed
// by independently configured provider trust, not caller-supplied assertions.
type EvidenceVerifier interface {
	Verify(context.Context, Attempt, Observation) error
}

// IdentifiedEvidenceVerifier supplies the stable trust-policy identifier
// recorded alongside durable evidence. Production IDs should include the
// provider, verifier version, and pinned trust-set revision.
type IdentifiedEvidenceVerifier interface {
	EvidenceVerifier
	VerifierID() string
}

func missingDependency(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func validToken(value string, max int) bool {
	if value == "" || len(value) > max || value != strings.TrimSpace(value) {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for i := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		c := value[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

// ValidateAttempt checks the immutable identity before any provider call.
func ValidateAttempt(attempt Attempt) error { return validateAttempt(attempt) }

// ExpectedIdempotencyKey derives a provider key from the immutable attempt
// identity. It is stable for retries of one Attempt and changes across
// providers, tenants, Permits, Operations, Attempts, or ActionHashes.
func ExpectedIdempotencyKey(attempt Attempt) string {
	sum := sha256.Sum256([]byte(
		"engageguard/provider-idempotency/v1\x00" +
			attempt.ProviderID + "\x00" + attempt.TenantID + "\x00" +
			attempt.OperationID + "\x00" + attempt.PermitID + "\x00" +
			attempt.AttemptID + "\x00" + attempt.ActionHash,
	))
	return "eg1_" + hex.EncodeToString(sum[:])
}

func validateAttempt(attempt Attempt) error {
	if !validToken(attempt.ProviderID, 256) ||
		!validToken(attempt.TenantID, 128) ||
		!validUUID(attempt.OperationID) ||
		!validUUID(attempt.PermitID) ||
		!validUUID(attempt.AttemptID) ||
		!validToken(attempt.IdempotencyKey, 256) ||
		!validSHA256(attempt.ActionHash) ||
		attempt.IdempotencyKey != ExpectedIdempotencyKey(attempt) {
		return ErrInvalidAttempt
	}
	return nil
}

const maxProviderEvidenceBytes = 256 * 1024

func validateObservation(attempt Attempt, observation Observation) error {
	if observation.ProviderID != attempt.ProviderID ||
		!validToken(observation.ProviderID, 256) ||
		len(observation.Evidence) == 0 || len(observation.Evidence) > maxProviderEvidenceBytes ||
		!validSHA256(observation.EvidenceDigest) ||
		observation.ObservedAt.IsZero() {
		return ErrInvalidObservation
	}
	digest := sha256.Sum256(observation.Evidence)
	if hex.EncodeToString(digest[:]) != observation.EvidenceDigest {
		return ErrInvalidObservation
	}

	switch observation.Outcome {
	case OutcomeAbsentUncertain:
		if observation.Receipt != nil {
			return ErrInvalidObservation
		}
		return nil
	case OutcomeFound, OutcomeFailedConfirmed:
		receipt := observation.Receipt
		if receipt == nil ||
			receipt.ProviderID != attempt.ProviderID ||
			!validToken(receipt.ReceiptID, 256) ||
			receipt.TenantID != attempt.TenantID ||
			receipt.OperationID != attempt.OperationID ||
			receipt.AttemptID != attempt.AttemptID ||
			receipt.IdempotencyKey != attempt.IdempotencyKey ||
			receipt.ActionHash != attempt.ActionHash ||
			receipt.EvidenceDigest != observation.EvidenceDigest ||
			!validSHA256(receipt.EvidenceDigest) ||
			!receipt.ObservedAt.Equal(observation.ObservedAt) {
			return ErrInvalidObservation
		}
		if observation.Outcome == OutcomeFound && receipt.Effect != EffectApplied {
			return ErrInvalidObservation
		}
		if observation.Outcome == OutcomeFailedConfirmed && receipt.Effect != EffectNotApplied {
			return ErrInvalidObservation
		}
		return nil
	default:
		return ErrInvalidObservation
	}
}

// Reconcile performs read-only provider inspection and evidence verification.
// It never dispatches, retries, claims a Permit, or mutates the Guard ledger.
// Any absence without provider proof remains UNKNOWN.
func Reconcile(
	ctx context.Context,
	attempt Attempt,
	inspector Inspector,
	verifier EvidenceVerifier,
) (Resolution, error) {
	result, err := ReconcileVerified(ctx, attempt, inspector, verifier)
	if err != nil {
		return "", err
	}
	return result.Resolution, nil
}

// ReconcileVerified returns a detached copy of the exact bytes and receipt
// fields that passed verification. The returned observation does not share
// mutable slices or pointers with the provider adapter or verifier.
func ReconcileVerified(
	ctx context.Context,
	attempt Attempt,
	inspector Inspector,
	verifier EvidenceVerifier,
) (VerifiedResult, error) {
	if ctx == nil || missingDependency(inspector) || missingDependency(verifier) {
		return VerifiedResult{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return VerifiedResult{}, fmt.Errorf("%w: context: %w", ErrUnavailable, err)
	}
	if err := validateAttempt(attempt); err != nil {
		return VerifiedResult{}, err
	}

	observation, err := inspector.Inspect(ctx, attempt)
	if err != nil {
		return VerifiedResult{}, fmt.Errorf("%w: inspect provider attempt: %w", ErrUnavailable, err)
	}
	if err := ctx.Err(); err != nil {
		return VerifiedResult{}, fmt.Errorf("%w: context after provider inspection: %w", ErrUnavailable, err)
	}
	// Freeze provider-owned mutable data before validating or sharing it.
	observation = cloneObservation(observation)
	if err := validateObservation(attempt, observation); err != nil {
		return VerifiedResult{}, err
	}
	// The verifier receives a second detached copy. Its implementation cannot
	// mutate the exact observation that will be returned for persistence.
	verifyObservation := cloneObservation(observation)
	if err := verifier.Verify(ctx, attempt, verifyObservation); err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrUnavailable) {
			return VerifiedResult{}, fmt.Errorf("%w: evidence verification: %w", ErrUnavailable, err)
		}
		return VerifiedResult{}, fmt.Errorf("%w: %w", ErrEvidenceRejected, err)
	}
	if err := ctx.Err(); err != nil {
		return VerifiedResult{}, fmt.Errorf("%w: context after evidence verification: %w", ErrUnavailable, err)
	}

	var resolution Resolution
	switch observation.Outcome {
	case OutcomeFound:
		resolution = ResolutionEffectObserved
	case OutcomeAbsentUncertain:
		resolution = ResolutionRemainUnknown
	case OutcomeFailedConfirmed:
		resolution = ResolutionNoEffectConfirmed
	default:
		return VerifiedResult{}, ErrInvalidObservation
	}
	return VerifiedResult{Resolution: resolution, Observation: observation}, nil
}

func cloneObservation(observation Observation) Observation {
	observation.Evidence = append([]byte(nil), observation.Evidence...)
	if observation.Receipt != nil {
		receipt := *observation.Receipt
		observation.Receipt = &receipt
	}
	return observation
}
