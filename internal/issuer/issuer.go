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
	TenantID                 string
	RunID                    string
	RuntimeAttemptID         string
	TurnID                   string
	ApprovalRef              string
	RiskRevision             string
	DecisionID               string
	PlanID                   string
	PlanHash                 string
	StepID                   string
	CapabilityID             string
	CapabilityVersion        string
	CapabilityContractSHA256 string
	ActionHash               string
	ToolBindingDigest        string
	PolicyVersion            string
	Audience                 string
	ValidUntil               time.Time
}

// PermitDraft is opaque outside this package. Only Service.Issue may
// construct a non-zero draft after validating an authority result.
type PermitDraft struct {
	values PermitDraftValues
}

// PermitDraftValues is a read-only snapshot of the values carried by a
// PermitDraft. Mutating this returned value never mutates the original draft.
type PermitDraftValues struct {
	TenantID                 string
	OperationID              string
	RunID                    string
	RuntimeAttemptID         string
	TurnID                   string
	ApprovalRef              string
	RiskRevision             string
	DecisionID               string
	PlanID                   string
	PlanHash                 string
	StepID                   string
	CapabilityID             string
	CapabilityVersion        string
	CapabilityContractSHA256 string
	ResourceRef              string
	ActionHash               string
	ToolBindingDigest        string
	PolicyVersion            string
	Audience                 string
	IssuedBy                 string
	IssuedAt                 time.Time
	ExpiresAt                time.Time
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

// PersistedPermit is the ledger's read-back of the immutable Permit row.
// Returning values rather than PermitDraft keeps the draft constructor private
// to this package while allowing an idempotent retry to return the original
// issuance timestamps instead of fabricating a new draft.
type PersistedPermit struct {
	PermitID string
	Values   PermitDraftValues
}

// Authority must independently verify current Run/Attempt/Turn, Decision,
// capability/tool binding, policy, approval and risk before returning success.
type Authority interface {
	VerifyIssue(context.Context, action.ActionRequest) (Authorization, error)
}

// PermitLedger must persist a one-time Permit atomically and enforce replay
// fencing. Only Service.Issue can construct a non-zero PermitDraft.
type PermitLedger interface {
	PersistIssuedPermit(context.Context, PermitDraft, time.Duration) (PersistedPermit, error)
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

func (s *Service) Issue(ctx context.Context, resolved action.ActionRequest) (ScopedPermit, error) {
	var zero ScopedPermit
	if s == nil || ctx == nil || missing(s.authority) || missing(s.ledger) || s.cfg.Now == nil {
		return zero, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("%w: context: %w", ErrUnavailable, err)
	}
	if err := resolved.Validate(); err != nil ||
		!identityRE.MatchString(resolved.TenantID) ||
		!permitIDRE.MatchString(resolved.OperationID) {
		return zero, fmt.Errorf("%w: invalid resolved ActionRequest v1", ErrDenied)
	}
	actionHash, err := action.ActionHash(resolved)
	if err != nil {
		return zero, fmt.Errorf("%w: invalid resolved ActionRequest v1", ErrDenied)
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
	if auth.TenantID != resolved.TenantID ||
		auth.RunID != resolved.RunID ||
		auth.DecisionID != resolved.DecisionID ||
		auth.PlanID != resolved.PlanID ||
		auth.PlanHash != resolved.PlanHash ||
		auth.StepID != resolved.StepID ||
		auth.CapabilityID != resolved.Capability.ID ||
		auth.CapabilityVersion != resolved.Capability.Version ||
		auth.CapabilityContractSHA256 != resolved.Capability.ContractSHA256 ||
		!validEvidence(auth.RunID) || !validEvidence(auth.RuntimeAttemptID) ||
		!validEvidence(auth.TurnID) || !validEvidence(auth.ApprovalRef) ||
		!validEvidence(auth.RiskRevision) ||
		!validEvidence(resolved.DecisionID) || !validEvidence(resolved.PlanID) ||
		!validEvidence(resolved.StepID) || !validEvidence(resolved.Capability.ID) ||
		!validEvidence(resolved.Capability.Version) || !validEvidence(resolved.ResourceRef) ||
		!permitIDRE.MatchString(resolved.OperationID) ||
		auth.ActionHash != actionHash ||
		auth.ToolBindingDigest != resolved.ToolBindingDigest ||
		auth.PolicyVersion != resolved.PolicyVersion ||
		auth.Audience != resolved.Audience ||
		!expiresAt.After(now) ||
		expiresAt.After(now.Add(s.cfg.MaxTTL)) {
		return zero, ErrDenied
	}

	draft := PermitDraft{values: PermitDraftValues{
		TenantID:                 resolved.TenantID,
		OperationID:              resolved.OperationID,
		RunID:                    resolved.RunID,
		RuntimeAttemptID:         auth.RuntimeAttemptID,
		TurnID:                   auth.TurnID,
		ApprovalRef:              auth.ApprovalRef,
		RiskRevision:             auth.RiskRevision,
		DecisionID:               resolved.DecisionID,
		PlanID:                   resolved.PlanID,
		PlanHash:                 resolved.PlanHash,
		StepID:                   resolved.StepID,
		CapabilityID:             resolved.Capability.ID,
		CapabilityVersion:        resolved.Capability.Version,
		CapabilityContractSHA256: resolved.Capability.ContractSHA256,
		ResourceRef:              resolved.ResourceRef,
		ActionHash:               actionHash,
		ToolBindingDigest:        resolved.ToolBindingDigest,
		PolicyVersion:            resolved.PolicyVersion,
		Audience:                 resolved.Audience,
		IssuedBy:                 s.cfg.IssuerIdentity,
		IssuedAt:                 now,
		ExpiresAt:                expiresAt,
	}}
	persisted, err := s.ledger.PersistIssuedPermit(ctx, draft, s.cfg.MaxTTL)
	if err != nil {
		if errors.Is(err, ErrDenied) || errors.Is(err, ErrConflict) {
			return zero, fmt.Errorf("persist Permit: %w", err)
		}
		return zero, fmt.Errorf("%w: persist Permit: %w", ErrUnavailable, err)
	}
	if !permitIDRE.MatchString(persisted.PermitID) ||
		!samePersistedPermit(draft.Values(), persisted.Values, now, s.cfg.MaxTTL) {
		return zero, fmt.Errorf("%w: ledger returned inconsistent Permit", ErrUnavailable)
	}
	return ScopedPermit{
		PermitID: persisted.PermitID,
		Draft:    PermitDraft{values: persisted.Values},
	}, nil
}

func samePersistedPermit(expected, persisted PermitDraftValues, now time.Time, maxTTL time.Duration) bool {
	return persisted.TenantID == expected.TenantID &&
		persisted.OperationID == expected.OperationID &&
		persisted.RunID == expected.RunID &&
		persisted.RuntimeAttemptID == expected.RuntimeAttemptID &&
		persisted.TurnID == expected.TurnID &&
		persisted.ApprovalRef == expected.ApprovalRef &&
		persisted.RiskRevision == expected.RiskRevision &&
		persisted.DecisionID == expected.DecisionID &&
		persisted.PlanID == expected.PlanID &&
		persisted.PlanHash == expected.PlanHash &&
		persisted.StepID == expected.StepID &&
		persisted.CapabilityID == expected.CapabilityID &&
		persisted.CapabilityVersion == expected.CapabilityVersion &&
		persisted.CapabilityContractSHA256 == expected.CapabilityContractSHA256 &&
		persisted.ResourceRef == expected.ResourceRef &&
		persisted.ActionHash == expected.ActionHash &&
		persisted.ToolBindingDigest == expected.ToolBindingDigest &&
		persisted.PolicyVersion == expected.PolicyVersion &&
		persisted.Audience == expected.Audience &&
		persisted.IssuedBy == expected.IssuedBy &&
		!persisted.IssuedAt.IsZero() &&
		persisted.IssuedAt.Equal(persisted.IssuedAt.Truncate(time.Microsecond)) &&
		!persisted.ExpiresAt.IsZero() &&
		persisted.ExpiresAt.Equal(persisted.ExpiresAt.Truncate(time.Microsecond)) &&
		persisted.ExpiresAt.After(persisted.IssuedAt) &&
		!persisted.ExpiresAt.After(persisted.IssuedAt.Add(maxTTL)) &&
		persisted.ExpiresAt.After(now) &&
		!persisted.ExpiresAt.After(expected.ExpiresAt)
}
