package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrUnknownConflict requires manual reconciliation, never another dispatch.
// A different reason cannot rewrite an already journaled uncertain attempt.
var ErrUnknownConflict = errors.New("Guard uncertain operation conflicts with durable attempt")
var ErrDispatchNotFound = errors.New("Guard dispatch attempt is absent or outside tenant")
var ErrUnknownCause = errors.New("unrecognized dispatch uncertainty reason")

// DispatchState is a local ledger observation, not proof of a provider result,
// a Permit or a permission to retry an external effect.
type DispatchState struct {
	TenantID    string
	OperationID string
	PermitID    string
	AttemptID   string
	ActionHash  string
	State       string
	Reason      string
}

func validUnknownReason(reason string) bool {
	switch reason {
	case "ACK_LOST", "PROVIDER_TIMEOUT", "PROVIDER_UNAVAILABLE", "WORKER_KILLED":
		return true
	default:
		return false
	}
}

// GetDispatchState resolves a single already committed attempt by immutable
// tenant, operation and attempt IDs. UNKNOWN is not a confirmed failure.
func (s *Store) GetDispatchState(ctx context.Context, tenant, operationID, attemptID string) (DispatchState, error) {
	var value DispatchState
	if s == nil || s.db == nil {
		return value, errors.New("Guard database unavailable")
	}
	if !tenantIDPattern.MatchString(tenant) || !validDispatchUUID(operationID) || !validDispatchUUID(attemptID) {
		return value, ErrDispatchNotFound
	}
	var reason sql.NullString
	var claimed, audited bool
	// A standalone Intent is not proof of a committed dispatch. Bind the
	// CLAIMED Permit and exact immutable dispatch Audit in the same query,
	// without trusting a caller-supplied state or permitting redispatch.
	err := s.db.QueryRowContext(ctx, `
		SELECT i.tenant_id, i.operation_id::text, i.permit_id::text,
		       i.attempt_id::text, i.action_hash, i.state, e.reason,
		       EXISTS (
		           SELECT 1 FROM guard_permits p
		           WHERE p.tenant_id=i.tenant_id AND p.operation_id=i.operation_id
		             AND p.permit_id=i.permit_id AND p.action_hash=i.action_hash
		             AND p.binding_digest=i.binding_digest AND p.state='CLAIMED'
		             AND p.claimed_at IS NOT NULL
		       ),
		       EXISTS (
		           SELECT 1 FROM guard_execution_audit a
		           WHERE a.tenant_id=i.tenant_id AND a.operation_id=i.operation_id
		             AND a.permit_id=i.permit_id AND a.attempt_id=i.attempt_id
		             AND a.action_hash=i.action_hash
		             AND a.event_type='guard.operation.dispatching.v1'
		       )
		FROM guard_operation_intents i
		LEFT JOIN guard_operation_unknown_events e
		  ON e.tenant_id=i.tenant_id AND e.attempt_id=i.attempt_id
		WHERE i.tenant_id=$1 AND i.operation_id=$2::uuid AND i.attempt_id=$3::uuid
	`, tenant, operationID, attemptID).Scan(
		&value.TenantID, &value.OperationID, &value.PermitID,
		&value.AttemptID, &value.ActionHash, &value.State, &reason,
		&claimed, &audited,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return DispatchState{}, ErrDispatchNotFound
	}
	if err != nil {
		return DispatchState{}, fmt.Errorf("inspect Guard dispatch attempt: %w", err)
	}
	if reason.Valid {
		value.Reason = reason.String
	}
	if !claimed || !audited {
		return DispatchState{}, ErrUnknownConflict
	}
	if value.State != "DISPATCHING" && value.State != "UNKNOWN" ||
		(value.State == "UNKNOWN" && !validUnknownReason(value.Reason)) ||
		(value.State == "DISPATCHING" && value.Reason != "") {
		return DispatchState{}, ErrUnknownConflict
	}
	return value, nil
}

func validDispatchUUID(input string) bool {
	if len(input) != 36 || input[8] != '-' || input[13] != '-' ||
		input[18] != '-' || input[23] != '-' {
		return false
	}
	for i := 0; i < len(input); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		ch := input[i]
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

// MarkDispatchUnknown is an internal journal transition after an external
// ACK becomes uncertain. It cannot be invoked from an Agent HTTP submission,
// cannot return a new dispatch grant, and never calls an executor.
// A trusted Guard worker must supply the original committed Attempt ID.
func (s *Store) MarkDispatchUnknown(
	ctx context.Context, tenant, operationID, attemptID, reason string,
) (DispatchState, error) {
	var empty DispatchState
	if s == nil || s.db == nil {
		return empty, errors.New("Guard database unavailable")
	}
	if !tenantIDPattern.MatchString(tenant) || !validDispatchUUID(operationID) ||
		!validDispatchUUID(attemptID) {
		return empty, ErrDispatchNotFound
	}
	if !validUnknownReason(reason) {
		return empty, ErrUnknownCause
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return empty, fmt.Errorf("begin Guard UNKNOWN journal: %w", err)
	}
	defer tx.Rollback()
	var state, permitID, actionHash, permitState string
	var audited bool
	// Recheck the exact original immutable Audit under the locked Attempt
	// before creating UNKNOWN or acknowledging a same-reason UNKNOWN replay.
	err = tx.QueryRowContext(ctx, `
		SELECT i.state, i.permit_id::text, i.action_hash, p.state,
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
		  AND p.permit_id=i.permit_id
		WHERE i.tenant_id=$1 AND i.operation_id=$2::uuid
		  AND i.attempt_id=$3::uuid
		FOR UPDATE OF i
	`, tenant, operationID, attemptID).Scan(&state, &permitID, &actionHash, &permitState, &audited)
	if errors.Is(err, sql.ErrNoRows) {
		return empty, ErrDispatchNotFound
	}
	if err != nil {
		return empty, fmt.Errorf("lock Guard dispatch attempt: %w", err)
	}
	if permitState != "CLAIMED" || !audited {
		return empty, ErrUnknownConflict
	}
	if state == "UNKNOWN" {
		var stored string
		err := tx.QueryRowContext(ctx, `
			SELECT reason FROM guard_operation_unknown_events
			WHERE tenant_id=$1 AND operation_id=$2::uuid AND attempt_id=$3::uuid
		`, tenant, operationID, attemptID).Scan(&stored)
		if err != nil || stored != reason {
			return empty, ErrUnknownConflict
		}
		if err := tx.Commit(); err != nil {
			return empty, fmt.Errorf("commit Guard UNKNOWN replay: %w", err)
		}
		return DispatchState{
			TenantID: tenant, OperationID: operationID, PermitID: permitID,
			AttemptID: attemptID, ActionHash: actionHash, State: "UNKNOWN", Reason: reason,
		}, nil
	}
	if state != "DISPATCHING" {
		return empty, ErrUnknownConflict
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE guard_operation_intents SET state='UNKNOWN'
		WHERE tenant_id=$1 AND operation_id=$2::uuid AND attempt_id=$3::uuid
		  AND state='DISPATCHING'
	`, tenant, operationID, attemptID)
	if err != nil {
		return empty, fmt.Errorf("fence uncertain Guard dispatch: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return empty, ErrUnknownConflict
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO guard_operation_unknown_events
		    (tenant_id,operation_id,permit_id,attempt_id,action_hash,reason)
		VALUES ($1,$2::uuid,$3::uuid,$4::uuid,$5,$6)
	`, tenant, operationID, permitID, attemptID, actionHash, reason); err != nil {
		return empty, fmt.Errorf("persist Guard UNKNOWN journal: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return empty, fmt.Errorf("commit Guard UNKNOWN journal: %w", err)
	}
	return DispatchState{
		TenantID: tenant, OperationID: operationID, PermitID: permitID,
		AttemptID: attemptID, ActionHash: actionHash, State: "UNKNOWN", Reason: reason,
	}, nil
}
