// Package admission defines a fail-closed HTTP seam between authenticated
// Agent Runtime and Guard's admission-only PostgreSQL operation ledger.
// It has no capability to approve, permit, publish or execute side effects.
package admission

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/avaargsh/EngageGuard/internal/action"
	"github.com/avaargsh/EngageGuard/internal/acceptance/postgres"
)

const maxHTTPSubmissionBytes = 64 * 1024

var (
	ErrUnauthenticated = errors.New("trusted runtime principal unavailable")
	ErrForbidden       = errors.New("runtime is not authorized for this run/plan")
)

// Principal must come from an authenticated deployment-resolved identity.
// Never construct this value from request headers or submission JSON.
type Principal struct {
	TenantID  string
	SubjectID string
	ServiceID string
}

// PrincipalResolver is an explicit required trust dependency. Its concrete
// implementation must validate mTLS/OIDC or a trusted auth gateway. This
// package supplies NO implementation or header fallback.
type PrincipalResolver interface {
	ResolvePrincipal(context.Context, *http.Request) (Principal, error)
}

// RunVerifier checks the authoritative Run, agent/release, Decision, PlanHash,
// step and capability against the already-resolved Principal. An unavailable
// authority is an error; cached or unchecked claims do not grant admission.
type RunVerifier interface {
	VerifySubmission(context.Context, Principal, action.ActionSubmission) error
}

// AcceptanceStore records intent only; it does not authorize or execute.
type AcceptanceStore interface {
	Accept(context.Context, string, string, []byte) (postgres.Operation, bool, error)
}

type handler struct {
	resolver PrincipalResolver
	verifier RunVerifier
	store    AcceptanceStore
}

func NewHandler(resolver PrincipalResolver, verifier RunVerifier, store AcceptanceStore) http.Handler {
	return &handler{resolver: resolver, verifier: verifier, store: store}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Path != "/v1/action-submissions" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.resolver == nil || h.verifier == nil || h.store == nil {
		http.Error(w, "Guard admission authority unavailable", http.StatusServiceUnavailable)
		return
	}
	principal, err := h.resolver.ResolvePrincipal(r.Context(), r)
	if err != nil {
		if errors.Is(err, ErrUnauthenticated) {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
		} else {
			http.Error(w, "Guard identity authority unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	if principal.TenantID == "" || principal.SubjectID == "" || principal.ServiceID == "" {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	if principal.ServiceID != "agent-runtime" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !validIdentity(principal.TenantID) || !validIdentity(principal.SubjectID) {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 || action.ValidateSubmissionKey(keys[0]) != nil {
		http.Error(w, "invalid Idempotency-Key", http.StatusBadRequest)
		return
	}
	if r.Body == nil {
		http.Error(w, "missing submission", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxHTTPSubmissionBytes+1))
	if err != nil || len(raw) > maxHTTPSubmissionBytes {
		http.Error(w, "invalid or oversized submission", http.StatusBadRequest)
		return
	}
	submission, err := action.ParseActionSubmission(raw)
	if err != nil {
		http.Error(w, "invalid ActionSubmission", http.StatusBadRequest)
		return
	}
	if err := h.verifier.VerifySubmission(r.Context(), principal, submission); err != nil {
		if errors.Is(err, ErrForbidden) {
			http.Error(w, "forbidden", http.StatusForbidden)
		} else {
			http.Error(w, "Guard Run authority unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	operation, created, err := h.store.Accept(r.Context(), principal.TenantID, keys[0], raw)
	if err != nil {
		if errors.Is(err, postgres.ErrConflict) {
			http.Error(w, "idempotency key conflicts with a prior submission", http.StatusConflict)
		} else {
			http.Error(w, "Guard admission unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	if operation.OperationID == "" || operation.Status != "ACCEPTED" || operation.TenantID != principal.TenantID {
		http.Error(w, "invalid Guard admission receipt", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if created {
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(struct{
		OperationID string `json:"operation_id"`
		Status      string `json:"status"`
	}{
		OperationID: operation.OperationID,
		Status:      "ACCEPTED",
	})
}

// Restricted opaque identity syntax. It is NOT proof of identity; only the
// authenticated resolver and authoritative RunVerifier supply that proof.
func validIdentity(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if i > 0 && (c == '.' || c == '_' || c == '-') {
			continue
		}
		return false
	}
	return true
}
