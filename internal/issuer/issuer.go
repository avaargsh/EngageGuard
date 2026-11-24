package issuer

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/avaargsh/EngageGuard/internal/action"
)

var ErrDenied = errors.New("trusted Permit issuance denied")
var ErrConflict = errors.New("trusted Permit issuance conflicts with existing authority evidence")
var ErrUnavailable = errors.New("trusted Permit issuer unavailable")

var identityRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var permitIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// Authorization is a fresh result from independently authenticated authority
// sources. It is not accepted from an Agent request and is not itself a Permit.
type Authorization struct {
	RunID             string
	RuntimeAttemptID  string
	TurnID            string
	ApprovalRef       string
	RiskRevision      string
	ActionHash        string
	ToolBindingDigest string
	PolicyVersion     string
	Audience          string
	ValidUntil        time.Time
}

// PermitDraft is opaque outside this package. Only Service.Issue may
// construct a non-zero draft after validating an authority result.
type PermitDraft struct {
	values PermitDraftValues
}

// PermitDraftValues is a read-only snapshot of the values carried by a
// PermitDraft. Mutating this returned value never mutates the original draft.
type PermitDraftValues struct {
	TenantID          string
	OperationID       string
	RunID             string
	RuntimeAttemptID  string
	TurnID            string
	ApprovalRef       string
	RiskRevision      string
	ActionHash        string
	ToolBindingDigest string
	PolicyVersion     string
	Audience          string
	IssuedBy          string
	IssuedAt          time.Time
	ExpiresAt         time.Time
}

func (d PermitDraft) Values() PermitDraftValues {
	return d.values
}

// ScopedPermit is an internal issuance result. It is not a signed bearer token
// and cannot authorize an external side effect by itself.
type ScopedPermit struct {
	PermitID string
	Draft    PermitDraft
}

// Authority must independently verify current Run/Attempt/Turn, Decision,
// capability/tool binding, policy, approval and risk before returning success.
type Authority interface {
	VerifyIssue(context.Context, action.WorkspaceWrite) (Authorization, error)
}

// PermitLedger must persist a one-time Permit atomically and enforce replay
// fencing. Only Service.Issue can construct a non-zero PermitDraft.
type PermitLedger interface {
	PersistIssuedPermit(context.Context, PermitDraft) (ScopedPermit, error)
}

type Config struct {
	IssuerIdentity string
	MaxTTL         time.Duration
	Now            func() time.Time
}

type Service struct {
	cfg       Config
	authority Authority
	ledger    PermitLedger
}

func missing(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	default:
		return false
	}
}

func validSPIFFEID(value string) bool {
	uri, err := url.Parse(value)
	if err != nil || uri.Scheme != "spiffe" || uri.Host == "" ||
		uri.Host != uri.Hostname() || uri.User != nil || uri.Opaque != "" ||
		uri.RawQuery != "" || uri.Fragment != "" || uri.RawPath != "" ||
		uri.String() != value {
		return false
	}
	parts := strings.Split(uri.Path, "/")
	return len(parts) == 5 && parts[0] == "" && parts[1] == "ns" &&
		parts[3] == "sa" && identityRE.MatchString(parts[2]) &&
		identityRE.MatchString(parts[4])
}

// Authority references are protocol identifiers, not display text. Restrict
// them to visible ASCII so bidi controls, zero-width format characters,
// C1 controls and Unicode lookalikes cannot create ambiguous audit identities.
func validEvidence(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 512 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func New(cfg Config, authority Authority, ledger PermitLedger) (*Service, error) {
	if !validSPIFFEID(cfg.IssuerIdentity) || cfg.MaxTTL <= 0 || cfg.Now == nil ||
		missing(authority) || missing(ledger) {
		return nil, ErrUnavailable
	}
	return &Service{cfg: cfg, authority: authority, ledger: ledger}, nil
}

func (s *Service) Issue(ctx context.Context, resolved action.WorkspaceWrite) (ScopedPermit, error) {
	var zero ScopedPermit
	if s == nil || ctx == nil || missing(s.authority) || missing(s.ledger) || s.cfg.Now == nil {
		return zero, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("%w: context: %w", ErrUnavailable, err)
	}
	actionHash, err := action.Hash(resolved)
	if err != nil {
		return zero, fmt.Errorf("%w: invalid resolved action", ErrDenied)
	}

	auth, err := s.authority.VerifyIssue(ctx, resolved)
	if err != nil {
		if errors.Is(err, ErrDenied) || errors.Is(err, ErrConflict) {
			return zero, fmt.Errorf("authority verification: %w", err)
		}
		return zero, fmt.Errorf("%w: authority verification: %w", ErrUnavailable, err)
	}
	// A source may return after the caller's deadline. Do not let a custom
	// ledger implementation turn that canceled request into a new Permit.
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("%w: context after authority verification: %w", ErrUnavailable, err)
	}
	now := s.cfg.Now().UTC().Truncate(time.Microsecond)
	expiresAt := auth.ValidUntil.UTC().Truncate(time.Microsecond)
	if !validEvidence(auth.RunID) || !validEvidence(auth.RuntimeAttemptID) ||
		!validEvidence(auth.TurnID) || !validEvidence(auth.ApprovalRef) ||
		!validEvidence(auth.RiskRevision) ||
		auth.ActionHash != actionHash ||
		auth.ToolBindingDigest != resolved.ToolBindingDigest ||
		auth.PolicyVersion != resolved.PolicyVersion ||
		auth.Audience != resolved.Audience ||
		!expiresAt.After(now) ||
		expiresAt.After(now.Add(s.cfg.MaxTTL)) {
		return zero, ErrDenied
	}

	draft := PermitDraft{values: PermitDraftValues{
		TenantID:          resolved.TenantID,
		OperationID:       resolved.OperationID,
		RunID:             auth.RunID,
		RuntimeAttemptID:  auth.RuntimeAttemptID,
		TurnID:            auth.TurnID,
		ApprovalRef:       auth.ApprovalRef,
		RiskRevision:      auth.RiskRevision,
		ActionHash:        actionHash,
		ToolBindingDigest: resolved.ToolBindingDigest,
		PolicyVersion:     resolved.PolicyVersion,
		Audience:          resolved.Audience,
		IssuedBy:          s.cfg.IssuerIdentity,
		IssuedAt:          now,
		ExpiresAt:         expiresAt,
	}}
	permit, err := s.ledger.PersistIssuedPermit(ctx, draft)
	if err != nil {
		if errors.Is(err, ErrDenied) || errors.Is(err, ErrConflict) {
			return zero, fmt.Errorf("persist Permit: %w", err)
		}
		return zero, fmt.Errorf("%w: persist Permit: %w", ErrUnavailable, err)
	}
	if !permitIDRE.MatchString(permit.PermitID) || permit.Draft.Values() != draft.Values() {
		return zero, fmt.Errorf("%w: ledger returned inconsistent Permit", ErrUnavailable)
	}
	return permit, nil
}
