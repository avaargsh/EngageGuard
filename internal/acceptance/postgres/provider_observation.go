package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/avaargsh/EngageGuard/internal/provider"
)

var (
	ErrProviderObservationAttemptNotFound = errors.New("Guard provider observation Attempt not found")
	ErrProviderObservationNotUnknown      = errors.New("Guard provider observation requires durable UNKNOWN")
	ErrProviderObservationConflict        = errors.New("conflicting provider observation for Guard Attempt")
	ErrProviderObservationCorrupt         = errors.New("durable provider observation evidence is corrupt")
	ErrProviderVerifierIdentity           = errors.New("identified provider evidence verifier required")
)

// ProviderObservationRecord is immutable evidence already authenticated by
// VerifierID. Persisting it does not transition UNKNOWN or grant a retry.
type ProviderObservationRecord struct {
	ObservationID  string
	Attempt        provider.Attempt
	Resolution     provider.Resolution
	Observation    provider.Observation
	EvidenceDigest string
	VerifierID     string
	RecordedAt     time.Time
}

// ReconcileProvider checks the exact durable UNKNOWN Attempt before contacting
// the provider, verifies the provider's raw evidence, and appends that evidence
// to the Guard ledger. It never dispatches, changes Intent state, or grants retry.
func (s *Store) ReconcileProvider(
	ctx context.Context,
	attempt provider.Attempt,
	inspector provider.Inspector,
	verifier provider.EvidenceVerifier,
) (ProviderObservationRecord, error) {
	var zero ProviderObservationRecord
	if s == nil || s.db == nil || ctx == nil {
		return zero, ErrPreEffectUnavailable
	}
	if err := provider.ValidateAttempt(attempt); err != nil {
		return zero, err
	}
	identified, ok := verifier.(provider.IdentifiedEvidenceVerifier)
	if !ok {
		return zero, ErrProviderVerifierIdentity
	}

	// Do not make a provider call for a fabricated, foreign, or not-yet-UNKNOWN
	// Attempt. The network call happens outside a DB transaction.
	if err := s.assertUnknownProviderAttempt(ctx, attempt); err != nil {
		return zero, err
	}

	verified, err := provider.ReconcileVerified(ctx, attempt, inspector, verifier)
	if err != nil {
		return zero, err
	}
	// Read the verifier identity only after ReconcileVerified has rejected nil
	// typed dependencies and completed verification.
	verifierID := identified.VerifierID()
	if !validPermitEvidence(verifierID) {
		return zero, ErrProviderVerifierIdentity
	}
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("%w: context before durable provider evidence: %w", ErrPreEffectUnavailable, err)
	}
	return s.persistProviderObservation(ctx, attempt, verified, verifierID)
}

func (s *Store) assertUnknownProviderAttempt(ctx context.Context, attempt provider.Attempt) error {
	tx, err := s.beginProviderObservationTx(ctx)
	if err != nil {
		return fmt.Errorf("%w: inspect provider Attempt: %w", ErrPreEffectUnavailable, err)
	}
	defer tx.Rollback()
	if err := lockUnknownProviderAttempt(ctx, tx, attempt); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit provider Attempt preflight: %w", ErrPreEffectUnavailable, err)
	}
	return nil
}

func lockUnknownProviderAttempt(ctx context.Context, tx *sql.Tx, attempt provider.Attempt) error {
	var state, permitState string
	var unknownEvent, dispatchAudit bool
	err := tx.QueryRowContext(ctx, `
		SELECT i.state, p.state,
		       EXISTS (
		           SELECT 1 FROM guard_operation_unknown_events u
		           WHERE u.tenant_id=i.tenant_id AND u.operation_id=i.operation_id
		             AND u.permit_id=i.permit_id AND u.attempt_id=i.attempt_id
		             AND u.action_hash=i.action_hash
		       ),
		       EXISTS (
		           SELECT 1 FROM guard_execution_audit a
		           WHERE a.tenant_id=i.tenant_id AND a.operation_id=i.operation_id
		             AND a.permit_id=i.permit_id AND a.attempt_id=i.attempt_id
		             AND a.action_hash=i.action_hash
		             AND a.event_type='guard.operation.dispatching.v1'
		       )
		FROM guard_operation_intents i
		JOIN guard_permits p
		  ON p.tenant_id=i.tenant_id AND p.operation_id=i.operation_id
		 AND p.permit_id=i.permit_id AND p.action_hash=i.action_hash
		WHERE i.tenant_id=$1 AND i.operation_id=$2::uuid
		  AND i.permit_id=$3::uuid AND i.attempt_id=$4::uuid
		  AND i.action_hash=$5
		FOR UPDATE OF i
	`, attempt.TenantID, attempt.OperationID, attempt.PermitID,
		attempt.AttemptID, attempt.ActionHash).Scan(&state, &permitState, &unknownEvent, &dispatchAudit)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrProviderObservationAttemptNotFound
	}
	if err != nil {
		return fmt.Errorf("%w: read locked provider Attempt: %w", ErrPreEffectUnavailable, err)
	}
	if state != "UNKNOWN" || permitState != "CLAIMED" || !unknownEvent || !dispatchAudit {
		return ErrProviderObservationNotUnknown
	}
	return nil
}

func (s *Store) persistProviderObservation(
	ctx context.Context,
	attempt provider.Attempt,
	verified provider.VerifiedResult,
	verifierID string,
) (ProviderObservationRecord, error) {
	var zero ProviderObservationRecord
	tx, err := s.beginProviderObservationTx(ctx)
	if err != nil {
		return zero, fmt.Errorf("%w: begin provider observation append: %w", ErrPreEffectUnavailable, err)
	}
	defer tx.Rollback()
	if err := lockUnknownProviderAttempt(ctx, tx, attempt); err != nil {
		return zero, err
	}

	observation := verified.Observation
	var existing ProviderObservationRecord
	existing, err = readProviderObservationByDigest(ctx, tx, attempt.TenantID, attempt.AttemptID, observation.EvidenceDigest)
	if err == nil {
		if !sameProviderObservation(existing, attempt, verified.Resolution, observation, verifierID) {
			return zero, ErrProviderObservationConflict
		}
		if err := tx.Commit(); err != nil {
			return zero, fmt.Errorf("%w: commit provider evidence replay: %w", ErrPreEffectUnavailable, err)
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return zero, fmt.Errorf("%w: inspect provider evidence replay: %w", ErrPreEffectUnavailable, err)
	}

	var terminalExists bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM guard_provider_observations
			WHERE tenant_id=$1 AND attempt_id=$2::uuid
			  AND outcome IN ('FOUND','FAILED_CONFIRMED')
		)
	`, attempt.TenantID, attempt.AttemptID).Scan(&terminalExists); err != nil {
		return zero, fmt.Errorf("%w: inspect terminal provider evidence: %w", ErrPreEffectUnavailable, err)
	}
	if terminalExists {
		return zero, ErrProviderObservationConflict
	}

	var receiptID, effect any
	if observation.Receipt != nil {
		receiptID = observation.Receipt.ReceiptID
		effect = string(observation.Receipt.Effect)
	}
	var observationID string
	var recordedAt time.Time
	err = tx.QueryRowContext(ctx, `
		INSERT INTO guard_provider_observations
		    (tenant_id,operation_id,permit_id,attempt_id,provider_id,idempotency_key,
		     action_hash,outcome,receipt_id,effect,evidence_digest,evidence_bytes,
		     verifier_id,observed_at)
		VALUES ($1,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT ON CONSTRAINT guard_provider_observation_attempt_digest_uq DO NOTHING
		RETURNING observation_id::text,recorded_at
	`, attempt.TenantID, attempt.OperationID, attempt.PermitID, attempt.AttemptID,
		attempt.ProviderID, attempt.IdempotencyKey, attempt.ActionHash,
		string(observation.Outcome), receiptID, effect, observation.EvidenceDigest,
		observation.Evidence, verifierID, observation.ObservedAt).Scan(&observationID, &recordedAt)
	if errors.Is(err, sql.ErrNoRows) {
		existing, readErr := readProviderObservationByDigest(ctx, tx, attempt.TenantID, attempt.AttemptID, observation.EvidenceDigest)
		if readErr != nil {
			return zero, fmt.Errorf("%w: read conflicting provider evidence: %w", ErrPreEffectUnavailable, readErr)
		}
		if !sameProviderObservation(existing, attempt, verified.Resolution, observation, verifierID) {
			return zero, ErrProviderObservationConflict
		}
		if err := tx.Commit(); err != nil {
			return zero, fmt.Errorf("%w: commit provider evidence replay: %w", ErrPreEffectUnavailable, err)
		}
		return existing, nil
	}
	if err != nil {
		if stateErr, ok := err.(interface{ SQLState() string }); ok &&
			(stateErr.SQLState() == "23505" || stateErr.SQLState() == "23514") {
			return zero, ErrProviderObservationConflict
		}
		return zero, fmt.Errorf("%w: append verified provider observation: %w", ErrPreEffectUnavailable, err)
	}

	record := ProviderObservationRecord{
		ObservationID:  observationID,
		Attempt:        attempt,
		Resolution:     verified.Resolution,
		Observation:    cloneProviderObservation(observation),
		EvidenceDigest: observation.EvidenceDigest,
		VerifierID:     verifierID,
		RecordedAt:     recordedAt,
	}
	if err := tx.Commit(); err != nil {
		return zero, fmt.Errorf("%w: commit verified provider observation: %w", ErrPreEffectUnavailable, err)
	}
	return record, nil
}

func readProviderObservationByDigest(
	ctx context.Context, tx *sql.Tx, tenantID, attemptID, digest string,
) (ProviderObservationRecord, error) {
	var record ProviderObservationRecord
	var outcome string
	var receiptID, effect sql.NullString
	var evidence []byte
	err := tx.QueryRowContext(ctx, `
		SELECT observation_id::text,operation_id::text,permit_id::text,attempt_id::text,
		       provider_id,idempotency_key,action_hash,outcome,receipt_id,effect,
		       evidence_digest,evidence_bytes,verifier_id,observed_at,recorded_at
		FROM guard_provider_observations
		WHERE tenant_id=$1 AND attempt_id=$2::uuid AND evidence_digest=$3
	`, tenantID, attemptID, digest).Scan(
		&record.ObservationID, &record.Attempt.OperationID, &record.Attempt.PermitID,
		&record.Attempt.AttemptID, &record.Attempt.ProviderID, &record.Attempt.IdempotencyKey,
		&record.Attempt.ActionHash, &outcome, &receiptID, &effect,
		&record.EvidenceDigest, &evidence, &record.VerifierID,
		&record.Observation.ObservedAt, &record.RecordedAt,
	)
	if err != nil {
		return ProviderObservationRecord{}, err
	}
	record.Attempt.TenantID = tenantID
	record.Observation.EvidenceDigest = record.EvidenceDigest
	record.Observation.Outcome = provider.Outcome(outcome)
	record.Observation.ProviderID = record.Attempt.ProviderID
	record.Observation.Evidence = append([]byte(nil), evidence...)
	if receiptID.Valid {
		if !effect.Valid {
			return ProviderObservationRecord{}, ErrProviderObservationCorrupt
		}
		record.Observation.Receipt = &provider.Receipt{
			ProviderID:     record.Attempt.ProviderID,
			ReceiptID:      receiptID.String,
			TenantID:       tenantID,
			OperationID:    record.Attempt.OperationID,
			AttemptID:      record.Attempt.AttemptID,
			IdempotencyKey: record.Attempt.IdempotencyKey,
			ActionHash:     record.Attempt.ActionHash,
			Effect:         provider.Effect(effect.String),
			EvidenceDigest: record.Observation.EvidenceDigest,
			ObservedAt:     record.Observation.ObservedAt,
		}
	} else if effect.Valid {
		return ProviderObservationRecord{}, ErrProviderObservationCorrupt
	}
	digestBytes := sha256.Sum256(record.Observation.Evidence)
	if hex.EncodeToString(digestBytes[:]) != record.Observation.EvidenceDigest ||
		provider.ValidateAttempt(record.Attempt) != nil ||
		provider.ValidateObservation(record.Attempt, record.Observation) != nil {
		return ProviderObservationRecord{}, ErrProviderObservationCorrupt
	}
	switch record.Observation.Outcome {
	case provider.OutcomeFound:
		record.Resolution = provider.ResolutionEffectObserved
	case provider.OutcomeAbsentUncertain:
		record.Resolution = provider.ResolutionRemainUnknown
	case provider.OutcomeFailedConfirmed:
		record.Resolution = provider.ResolutionNoEffectConfirmed
	default:
		return ProviderObservationRecord{}, ErrProviderObservationCorrupt
	}
	return record, nil
}

func sameProviderObservation(
	existing ProviderObservationRecord,
	attempt provider.Attempt,
	resolution provider.Resolution,
	observation provider.Observation,
	verifierID string,
) bool {
	if existing.Attempt != attempt || existing.Resolution != resolution ||
		existing.VerifierID != verifierID ||
		existing.Observation.Outcome != observation.Outcome ||
		existing.Observation.ProviderID != observation.ProviderID ||
		existing.Observation.EvidenceDigest != observation.EvidenceDigest ||
		!existing.Observation.ObservedAt.Equal(observation.ObservedAt) ||
		!bytes.Equal(existing.Observation.Evidence, observation.Evidence) {
		return false
	}
	if existing.Observation.Receipt == nil || observation.Receipt == nil {
		return existing.Observation.Receipt == nil && observation.Receipt == nil
	}
	left, right := existing.Observation.Receipt, observation.Receipt
	return left.ProviderID == right.ProviderID &&
		left.ReceiptID == right.ReceiptID &&
		left.TenantID == right.TenantID &&
		left.OperationID == right.OperationID &&
		left.AttemptID == right.AttemptID &&
		left.IdempotencyKey == right.IdempotencyKey &&
		left.ActionHash == right.ActionHash &&
		left.Effect == right.Effect &&
		left.EvidenceDigest == right.EvidenceDigest &&
		left.ObservedAt.Equal(right.ObservedAt)
}

func (s *Store) beginProviderObservationTx(ctx context.Context) (*sql.Tx, error) {
	tx, err := s.beginLedgerTx(ctx, true)
	if err != nil {
		return nil, err
	}
	var safe bool
	err = tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM pg_catalog.pg_class c
			JOIN pg_catalog.pg_class m
			  ON m.oid=pg_catalog.to_regclass(
			    pg_catalog.format('%I.%I', pg_catalog.current_schema(), 'guard_schema_migrations'))
			WHERE c.oid=pg_catalog.to_regclass(
			    pg_catalog.format('%I.%I', pg_catalog.current_schema(), 'guard_provider_observations'))
			  AND c.relkind='r' AND c.relpersistence='p'
			  AND c.relnamespace=pg_catalog.current_schema()::regnamespace
			  AND c.relowner=m.relowner
			  AND pg_catalog.to_regclass('guard_provider_observations') IS NOT DISTINCT FROM c.oid
		)
	`).Scan(&safe)
	if err != nil || !safe {
		_ = tx.Rollback()
		return nil, fmt.Errorf("%w: provider observation relation identity: %v", ErrSchemaDrift, err)
	}
	return tx, nil
}

func cloneProviderObservation(observation provider.Observation) provider.Observation {
	observation.Evidence = append([]byte(nil), observation.Evidence...)
	if observation.Receipt != nil {
		receipt := *observation.Receipt
		observation.Receipt = &receipt
	}
	return observation
}

// ListProviderObservations reconstructs only evidence bound to the exact
// tenant/operation/attempt selector. A cross-tenant selector is indistinguishable
// from an empty result; each row's raw evidence digest is checked on read.
func (s *Store) ListProviderObservations(
	ctx context.Context, tenantID, operationID, attemptID string,
) ([]ProviderObservationRecord, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrPreEffectUnavailable
	}
	if !tenantIDPattern.MatchString(tenantID) ||
		!validDispatchUUID(operationID) || !validDispatchUUID(attemptID) {
		return nil, ErrProviderObservationAttemptNotFound
	}
	tx, err := s.beginProviderObservationTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: begin provider observation read: %w", ErrPreEffectUnavailable, err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `
		SELECT observation_id::text,operation_id::text,permit_id::text,attempt_id::text,
		       provider_id,idempotency_key,action_hash,outcome,receipt_id,effect,
		       evidence_digest,evidence_bytes,verifier_id,observed_at,recorded_at
		FROM guard_provider_observations
		WHERE tenant_id=$1 AND operation_id=$2::uuid AND attempt_id=$3::uuid
		ORDER BY recorded_at,observation_id
	`, tenantID, operationID, attemptID)
	if err != nil {
		return nil, fmt.Errorf("%w: query provider observations: %w", ErrPreEffectUnavailable, err)
	}
	defer rows.Close()
	var records []ProviderObservationRecord
	for rows.Next() {
		var record ProviderObservationRecord
		var outcome string
		var receiptID, effect sql.NullString
		var evidence []byte
		if err := rows.Scan(
			&record.ObservationID, &record.Attempt.OperationID, &record.Attempt.PermitID,
			&record.Attempt.AttemptID, &record.Attempt.ProviderID, &record.Attempt.IdempotencyKey,
			&record.Attempt.ActionHash, &outcome, &receiptID, &effect,
			&record.EvidenceDigest, &evidence, &record.VerifierID,
			&record.Observation.ObservedAt, &record.RecordedAt,
		); err != nil {
			return nil, fmt.Errorf("%w: scan provider observation: %w", ErrPreEffectUnavailable, err)
		}
		record.Attempt.TenantID = tenantID
		record.Observation.EvidenceDigest = record.EvidenceDigest
		record.Observation.Outcome = provider.Outcome(outcome)
		record.Observation.ProviderID = record.Attempt.ProviderID
		record.Observation.Evidence = append([]byte(nil), evidence...)
		if receiptID.Valid {
			if !effect.Valid {
				return nil, ErrProviderObservationCorrupt
			}
			record.Observation.Receipt = &provider.Receipt{
				ProviderID: record.Attempt.ProviderID, ReceiptID: receiptID.String,
				TenantID: tenantID, OperationID: operationID, AttemptID: attemptID,
				IdempotencyKey: record.Attempt.IdempotencyKey, ActionHash: record.Attempt.ActionHash,
				Effect:         provider.Effect(effect.String),
				EvidenceDigest: record.Observation.EvidenceDigest,
				ObservedAt:     record.Observation.ObservedAt,
			}
		} else if effect.Valid {
			return nil, ErrProviderObservationCorrupt
		}
		sum := sha256.Sum256(record.Observation.Evidence)
		if hex.EncodeToString(sum[:]) != record.Observation.EvidenceDigest ||
			provider.ValidateAttempt(record.Attempt) != nil ||
			provider.ValidateObservation(record.Attempt, record.Observation) != nil {
			return nil, ErrProviderObservationCorrupt
		}
		switch record.Observation.Outcome {
		case provider.OutcomeFound:
			record.Resolution = provider.ResolutionEffectObserved
		case provider.OutcomeAbsentUncertain:
			record.Resolution = provider.ResolutionRemainUnknown
		case provider.OutcomeFailedConfirmed:
			record.Resolution = provider.ResolutionNoEffectConfirmed
		default:
			return nil, ErrProviderObservationCorrupt
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate provider observations: %w", ErrPreEffectUnavailable, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("%w: commit provider observation read: %w", ErrPreEffectUnavailable, err)
	}
	return records, nil
}
