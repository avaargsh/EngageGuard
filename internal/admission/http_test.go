package admission

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/avaargsh/EngageGuard/internal/acceptance/postgres"
	"github.com/avaargsh/EngageGuard/internal/action"
)

type fakeResolver struct {
	principal Principal
	err       error
	calls     int
}

func (f *fakeResolver) ResolvePrincipal(_ context.Context, _ *http.Request) (Principal, error) {
	f.calls++
	return f.principal, f.err
}

type fakeVerifier struct {
	err           error
	calls         int
	last          action.ActionSubmission
	lastPrincipal Principal
}

func (f *fakeVerifier) VerifySubmission(_ context.Context, principal Principal, s action.ActionSubmission) error {
	f.calls++
	f.lastPrincipal = principal
	f.last = s
	return f.err
}

type fakeStore struct {
	mu     sync.Mutex
	calls  int
	digest string
	key    string
	tenant string
	err    error
}

func (f *fakeStore) Accept(_ context.Context, tenantID, key string, raw []byte) (postgres.Operation, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return postgres.Operation{}, false, f.err
	}
	digest, err := action.SubmissionDigest(raw)
	if err != nil {
		return postgres.Operation{}, false, err
	}
	if f.calls > 1 && f.key == key && f.tenant == tenantID {
		if digest != f.digest {
			return postgres.Operation{}, false, postgres.ErrConflict
		}
		return postgres.Operation{OperationID: "guard-created-operation", Status: "ACCEPTED", TenantID: tenantID}, false, nil
	}
	f.digest, f.key, f.tenant = digest, key, tenantID
	return postgres.Operation{OperationID: "guard-created-operation", Status: "ACCEPTED", TenantID: tenantID}, true, nil
}

func goodBody() string {
	return `{"schema_version":"action-submission.v1","run_id":"run-1","decision_id":"dec-1","plan_id":"plan-1","plan_hash":"` +
		strings.Repeat("a", 64) + `","step_id":"step-1","capability":{"id":"workspace.write","version":"1.0.0"},"resource_ref":"workspace-1","arguments":{"path":"docs/a.txt"}}`
}

func exercise(h http.Handler, key, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/action-submissions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", key)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuthenticatedAdmissionAndStableReplay(t *testing.T) {
	resolver := &fakeResolver{principal: Principal{TenantID: "tenant-a", SubjectID: "runtime-service", ActorID: "agent-runtime", WorkloadID: "runtime-workload", ServiceID: "agent-runtime"}}
	verifier := &fakeVerifier{}
	store := &fakeStore{}
	h := NewHandler(resolver, verifier, store)
	first := exercise(h, "run-1:step-1", goodBody())
	second := exercise(h, "run-1:step-1", goodBody())
	if first.Code != http.StatusCreated || second.Code != http.StatusOK {
		t.Fatalf("expected 201 then 200; got %d then %d: %s / %s", first.Code, second.Code, first.Body.String(), second.Body.String())
	}
	var a, b map[string]any
	if err := json.Unmarshal(first.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(second.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if a["operation_id"] != "guard-created-operation" || a["operation_id"] != b["operation_id"] {
		t.Fatalf("unexpected operation replay: %+v %+v", a, b)
	}
	if a["permit_id"] != nil || a["authorized"] != nil || a["executed"] != nil {
		t.Fatalf("acceptance falsely claimed authorization: %+v", a)
	}
	if verifier.calls != 2 || store.calls != 2 || resolver.calls != 2 {
		t.Fatalf("all replays must be authenticated and reverified: %d %d %d", resolver.calls, verifier.calls, store.calls)
	}
	if store.tenant != "tenant-a" || verifier.last.RunID != "run-1" ||
		verifier.lastPrincipal.ActorID != "agent-runtime" ||
		verifier.lastPrincipal.WorkloadID != "runtime-workload" {
		t.Fatal("resolved tenant or verified Run was lost")
	}
}

// A previously accepted idempotency key must not bypass a newly denied or
// unavailable Run authority. This is a revocation/ACK-loss replay boundary.
func TestReplayRevalidatesAuthoritativeRunState(t *testing.T) {
	resolver := &fakeResolver{principal: Principal{
		TenantID: "tenant-a", SubjectID: "runtime-service",
		ActorID: "agent-runtime", WorkloadID: "runtime-workload",
		ServiceID: "agent-runtime",
	}}
	verifier := &fakeVerifier{}
	store := &fakeStore{}
	h := NewHandler(resolver, verifier, store)

	first := exercise(h, "key-reverify", goodBody())
	if first.Code != http.StatusCreated || store.calls != 1 {
		t.Fatalf("initial acceptance: status=%d store calls=%d", first.Code, store.calls)
	}

	verifier.err = ErrForbidden
	denied := exercise(h, "key-reverify", goodBody())
	if denied.Code != http.StatusForbidden || store.calls != 1 {
		t.Fatalf("revoked Run replay: status=%d store calls=%d", denied.Code, store.calls)
	}

	verifier.err = errors.New("Run authority unavailable")
	unavailable := exercise(h, "key-reverify", goodBody())
	if unavailable.Code != http.StatusServiceUnavailable || store.calls != 1 {
		t.Fatalf("unavailable Run authority replay: status=%d store calls=%d", unavailable.Code, store.calls)
	}

	verifier.err = nil
	replay := exercise(h, "key-reverify", goodBody())
	if replay.Code != http.StatusOK || store.calls != 2 ||
		resolver.calls != 4 || verifier.calls != 4 {
		t.Fatalf("reverified replay: status=%d resolver=%d verifier=%d store=%d",
			replay.Code, resolver.calls, verifier.calls, store.calls)
	}

	for _, rec := range []*httptest.ResponseRecorder{first, replay} {
		var receipt map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &receipt); err != nil {
			t.Fatal(err)
		}
		if len(receipt) != 2 || receipt["status"] != "ACCEPTED" ||
			receipt["operation_id"] != "guard-created-operation" {
			t.Fatalf("admission response claims more than ACCEPTED: %+v", receipt)
		}
	}
}

func TestFailClosedWhenResolverOrVerifierMissing(t *testing.T) {
	realResolver := &fakeResolver{principal: Principal{TenantID: "tenant-a", SubjectID: "runtime-service", ActorID: "agent-runtime", WorkloadID: "runtime-workload", ServiceID: "agent-runtime"}}
	for name, h := range map[string]http.Handler{
		"no resolver": NewHandler(nil, &fakeVerifier{}, &fakeStore{}),
		"no verifier": NewHandler(realResolver, nil, &fakeStore{}),
		"no store":    NewHandler(realResolver, &fakeVerifier{}, nil),
	} {
		t.Run(name, func(t *testing.T) {
			if got := exercise(h, "key-1", goodBody()).Code; got != http.StatusServiceUnavailable {
				t.Fatalf("missing authority accepted: %d", got)
			}
		})
	}
}

func TestCallerCannotForgeTenantOrServiceIdentityInHeaders(t *testing.T) {
	resolver := &fakeResolver{principal: Principal{TenantID: "tenant-real", SubjectID: "runtime-service", ActorID: "agent-runtime", WorkloadID: "runtime-workload", ServiceID: "agent-runtime"}}
	store := &fakeStore{}
	h := NewHandler(resolver, &fakeVerifier{}, store)
	req := httptest.NewRequest(http.MethodPost, "/v1/action-submissions", strings.NewReader(goodBody()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "key-1")
	req.Header.Set("X-Tenant-ID", "tenant-forged")
	req.Header.Set("X-Service-ID", "attacker")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated || store.tenant != "tenant-real" {
		t.Fatalf("untrusted caller header overrode authenticated identity: status=%d tenant=%s", rec.Code, store.tenant)
	}
}

func TestRejectUnauthenticatedWrongCallerAndUnverifiedPlanBeforeStore(t *testing.T) {
	cases := []struct {
		name        string
		principal   Principal
		resolverErr error
		verifyErr   error
		want        int
	}{
		{"anonymous", Principal{}, ErrUnauthenticated, nil, http.StatusUnauthorized},
		{"wrong service", Principal{TenantID: "tenant-a", SubjectID: "attacker", ActorID: "attacker", WorkloadID: "runtime-workload", ServiceID: "other-service"}, nil, nil, http.StatusForbidden},
		{"missing subject", Principal{TenantID: "tenant-a", ActorID: "agent-runtime", WorkloadID: "runtime-workload", ServiceID: "agent-runtime"}, nil, nil, http.StatusUnauthorized},
		{"missing actor", Principal{TenantID: "tenant-a", SubjectID: "runtime-service", WorkloadID: "runtime-workload", ServiceID: "agent-runtime"}, nil, nil, http.StatusUnauthorized},
		{"missing workload", Principal{TenantID: "tenant-a", SubjectID: "runtime-service", ActorID: "agent-runtime", ServiceID: "agent-runtime"}, nil, nil, http.StatusUnauthorized},
		{"run denied", Principal{TenantID: "tenant-a", SubjectID: "runtime-service", ActorID: "agent-runtime", WorkloadID: "runtime-workload", ServiceID: "agent-runtime"}, nil, ErrForbidden, http.StatusForbidden},
		{"authority down", Principal{TenantID: "tenant-a", SubjectID: "runtime-service", ActorID: "agent-runtime", WorkloadID: "runtime-workload", ServiceID: "agent-runtime"}, nil, errors.New("authority backend unavailable"), http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &fakeResolver{principal: tc.principal, err: tc.resolverErr}
			verifier := &fakeVerifier{err: tc.verifyErr}
			store := &fakeStore{}
			code := exercise(NewHandler(resolver, verifier, store), "key-1", goodBody()).Code
			if code != tc.want || store.calls != 0 {
				t.Fatalf("wanted %d and no DB writes; got %d calls=%d", tc.want, code, store.calls)
			}
		})
	}
}

func TestRejectMalformedSubmissionBeforeStore(t *testing.T) {
	resolver := &fakeResolver{principal: Principal{TenantID: "tenant-a", SubjectID: "runtime-service", ActorID: "agent-runtime", WorkloadID: "runtime-workload", ServiceID: "agent-runtime"}}
	verifier := &fakeVerifier{}
	store := &fakeStore{}
	h := NewHandler(resolver, verifier, store)
	for _, tc := range []struct{ key, body string }{
		{"bad key", goodBody()},
		{"key-1", `{"operation_id":"caller-forged"}`},
		{"key-1", strings.Replace(goodBody(), `"run_id":`, `"tenant_id":"forged","run_id":`, 1)},
		{"key-1", strings.Replace(goodBody(), `"version":"1.0.0"`, `"version":"1.0.0","contract_sha256":"`+strings.Repeat("b", 64)+`"`, 1)},
		{"key-1", goodBody() + "{}"},
		{"key-1", goodBody() + strings.Repeat(" ", 65537)},
	} {
		if got := exercise(h, tc.key, tc.body).Code; got != http.StatusBadRequest {
			t.Fatalf("bad submission accepted with status %d", got)
		}
	}
	if store.calls != 0 || verifier.calls != 0 {
		t.Fatalf("invalid submission reached stateful layers: store=%d verify=%d", store.calls, verifier.calls)
	}
}

func TestConflictingBodyAndStoreOutage(t *testing.T) {
	resolver := &fakeResolver{principal: Principal{TenantID: "tenant-a", SubjectID: "runtime-service", ActorID: "agent-runtime", WorkloadID: "runtime-workload", ServiceID: "agent-runtime"}}
	verifier := &fakeVerifier{}
	store := &fakeStore{}
	h := NewHandler(resolver, verifier, store)
	if got := exercise(h, "key-1", goodBody()).Code; got != http.StatusCreated {
		t.Fatal(got)
	}
	changed := strings.Replace(goodBody(), "docs/a.txt", "docs/b.txt", 1)
	if got := exercise(h, "key-1", changed).Code; got != http.StatusConflict {
		t.Fatalf("changed payload status=%d", got)
	}
	store.err = errors.New("database failure")
	if got := exercise(h, "key-2", goodBody()).Code; got != http.StatusServiceUnavailable {
		t.Fatalf("DB failure status=%d", got)
	}
}

func TestContentTypeAndMethodAreRestricted(t *testing.T) {
	resolver := &fakeResolver{principal: Principal{TenantID: "tenant-a", SubjectID: "runtime-service", ActorID: "agent-runtime", WorkloadID: "runtime-workload", ServiceID: "agent-runtime"}}
	store := &fakeStore{}
	h := NewHandler(resolver, &fakeVerifier{}, store)
	get := httptest.NewRequest(http.MethodGet, "/v1/action-submissions", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, get)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status=%d", rec.Code)
	}
	bad := httptest.NewRequest(http.MethodPost, "/v1/action-submissions", strings.NewReader(goodBody()))
	bad.Header.Set("Content-Type", "text/plain")
	bad.Header.Set("Idempotency-Key", "key-1")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, bad)
	if rec.Code != http.StatusUnsupportedMediaType || store.calls != 0 {
		t.Fatalf("media mismatch accepted: %d", rec.Code)
	}
}
