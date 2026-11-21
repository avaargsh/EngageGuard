package postgres

import (
	"context"
	"errors"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// ErrPreEffectBlocked is the safe default when this Guard-local DB snapshot
// cannot show all necessary pre-effect conditions. It is not proof of effect
// absence and must never authorize automatic redispatch.
var ErrPreEffectBlocked = errors.New("Guard pre-effect ledger does not support a protected side effect")

// InspectPreEffectLedger is a future executor-PEP *input* only; it cannot
// authenticate the calling executor, pin source authority or issue a Permit.
// The stub intentionally denies until validated against a live DB snapshot.
func (s *Store) InspectPreEffectLedger(ctx context.Context, permitID, attemptID string, resolved action.WorkspaceWrite) error {
	return ErrPreEffectBlocked
}
