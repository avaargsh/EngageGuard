package executorpep

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"

	"github.com/avaargsh/EngageGuard/internal/action"
)

// ErrBlocked is the default for missing, mismatched, revoked or stale input.
// It never means an external side effect did not occur.
var ErrBlocked = errors.New("executor pre-effect checks blocked")

// ErrUnavailable denies operation if required local or live sources cannot
// be queried. It never authorizes fail-open or automatic UNKNOWN retries.
var ErrUnavailable = errors.New("executor pre-effect authority unavailable")

// Binding is operator provisioned, not taken from a model or request body.
type Binding struct {
	ExecutorSPIFFEID string
	TenantID         string
	Audience         string
	ClientRoot       *x509.Certificate
}

// Ledger is owned by Guard; reads are necessary facts, not an execution grant.
type Ledger interface {
	InspectPreEffectLedger(context.Context, string, string, action.WorkspaceWrite) error
}

// LiveAuthority must check authoritative current Runtime/Decision/ACP policy,
// approval and revocation, using authenticated service adapters.
type LiveAuthority interface {
	VerifyCurrent(context.Context, string, string, action.WorkspaceWrite) error
}

// Gate holds independent pre-effect inspections. It never performs an effect,
// issues a Permit, returns an executor token or proves provider outcome.
type Gate struct {
	binding Binding
	ledger  Ledger
	live    LiveAuthority
}

func NewGate(binding Binding, ledger Ledger, live LiveAuthority) (*Gate, error) {
	if binding.ClientRoot == nil || ledger == nil || live == nil {
		return nil, ErrUnavailable
	}
	return &Gate{binding: binding, ledger: ledger, live: live}, nil
}

// Check is deliberately inert in the initial RED implementation.
func (g *Gate) Check(ctx context.Context, peer *tls.ConnectionState, permitID, attemptID string, resolved action.WorkspaceWrite) error {
	return ErrBlocked
}
