package admission

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The dedicated cross-repository gate starts the pinned actual Runtime API
// with a disposable PostgreSQL DB. SQL writes below are test fixtures only;
// the Guard client reads exclusively through the authenticated network API.
func TestLiveRuntimeRunSafetyAuthority(t *testing.T) {
	if os.Getenv("GUARD_LIVE_RUNTIME_SAFETY") != "1" {
		t.Skip("pinned Runtime service integration only")
	}
	required := func(name string) string {
		t.Helper()
		if value := os.Getenv(name); value != "" {
			return value
		}
		t.Fatalf("live Runtime acceptance requires %s", name)
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca, err := os.ReadFile(required("GUARD_RUNTIME_CA"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid isolated CA")
	}
	cert, err := tls.LoadX509KeyPair(required("GUARD_RUNTIME_CERT"), required("GUARD_RUNTIME_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	tenant := required("GUARD_RUNTIME_TENANT")
	runID := required("GUARD_RUNTIME_RUN")
	ambiguousRunID := required("GUARD_RUNTIME_AMBIGUOUS_RUN")
	if ambiguousRunID == runID {
		t.Fatal("ambiguity fixture must use a separate ACP-accepted Run")
	}
	client, err := NewRuntimeRunSafetyClient(required("GUARD_RUNTIME_ORIGIN"), required("GUARD_RUNTIME_SPIFFE"), tenant, roots, cert)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	assertDenied := func() {
		t.Helper()
		if _, err := client.GetRunSafetySnapshot(ctx, tenant, runID); !errors.Is(err, ErrForbidden) {
			t.Fatalf("expected fresh Runtime safety denial: %v", err)
		}
	}
	assertDenied() // actual accepted Run is QUEUED.
	db, err := pgx.Connect(ctx, required("GUARD_RUNTIME_TEST_FIXTURE_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(context.Background())
	if _, err := db.Exec(ctx, "UPDATE runs SET status='RUNNING',updated_at=clock_timestamp() WHERE tenant_id=$1 AND run_id=$2::uuid", tenant, runID); err != nil {
		t.Fatal(err)
	}
	// A RUNNING Run without Runtime's current Attempt pointer cannot
	// authorize new Guard admission, even when its breaker is CLOSED.
	assertDenied()

	// Fixture setup only: the actual Runtime service supplies Run/principal/
	// breaker authority; create a matching immutable generation-one Attempt
	// and pointer in one transaction. A synthetic Temporal execution UUID in
	// this isolated database is NOT a production execution attestation.
	// The Guard client below still reads through the real mTLS Runtime API.
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	var attemptID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO runtime_run_attempts
		(tenant_id, run_id, run_attempt_id, workflow_id, temporal_execution_id)
		SELECT r.tenant_id, r.run_id, pg_catalog.gen_random_uuid(),
		       r.workflow_id, pg_catalog.gen_random_uuid()
		FROM runs r WHERE r.tenant_id=$1 AND r.run_id=$2::uuid
		RETURNING run_attempt_id::text
	`, tenant, runID).Scan(&attemptID); err != nil {
		t.Fatalf("create isolated Runtime Attempt fixture: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO runtime_current_attempts
		(tenant_id,run_id,attempt_id,generation,breaker_epoch)
		VALUES ($1,$2::uuid,$3::uuid,1,1)
	`, tenant, runID, attemptID); err != nil {
		t.Fatalf("create isolated current Attempt fixture: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit isolated current Attempt fixture: %v", err)
	}
	snapshot, err := client.GetRunSafetySnapshot(ctx, tenant, runID)
	if err != nil || snapshot.TenantID != tenant || snapshot.RunID != runID ||
		snapshot.AgentID != "agent-1" || snapshot.AgentReleaseID != "release-1" || snapshot.SessionID != "session-1" ||
		snapshot.BreakerState != "CLOSED" || snapshot.BreakerEpoch != 1 || snapshot.BreakerVersion != 1 {
		t.Fatalf("actual Runtime projection inconsistent: %+v %v", snapshot, err)
	}
	if _, err := client.GetRunSafetySnapshot(ctx, "foreign-tenant", runID); !errors.Is(err, ErrForbidden) {
		t.Fatal("foreign tenant accepted")
	}
	if _, err := client.GetRunSafetySnapshot(ctx, tenant, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("absent Run was not denied: %v", err)
	}
	// An independently accepted Run exercises historical Attempt ambiguity
	// while the original Run stays valid for breaker and terminal tests.
	if _, err := db.Exec(ctx,
		"UPDATE runs SET status='RUNNING',updated_at=clock_timestamp() WHERE tenant_id=$1 AND run_id=$2::uuid",
		tenant, ambiguousRunID); err != nil {
		t.Fatal(err)
	}
	assertAmbiguousDenied := func(stage string) {
		t.Helper()
		if _, err := client.GetRunSafetySnapshot(ctx, tenant, ambiguousRunID); !errors.Is(err, ErrForbidden) {
			t.Fatalf("%s: ambiguous Run gained Guard safety precondition: %v", stage, err)
		}
	}
	assertAmbiguousDenied("no current Attempt")
	fixture, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Rollback(context.Background())
	var currentAttempt string
	if err := fixture.QueryRow(ctx, `
		INSERT INTO runtime_run_attempts
		(tenant_id,run_id,run_attempt_id,workflow_id,temporal_execution_id)
		SELECT r.tenant_id,r.run_id,pg_catalog.gen_random_uuid(),
		       r.workflow_id,pg_catalog.gen_random_uuid()
		FROM runs r WHERE r.tenant_id=$1 AND r.run_id=$2::uuid
		RETURNING run_attempt_id::text
	`, tenant, ambiguousRunID).Scan(&currentAttempt); err != nil {
		t.Fatalf("insert isolated current Attempt fixture: %v", err)
	}
	if _, err := fixture.Exec(ctx, `
		INSERT INTO runtime_current_attempts(tenant_id,run_id,attempt_id,generation,breaker_epoch)
		VALUES ($1,$2::uuid,$3::uuid,1,1)
	`, tenant, ambiguousRunID, currentAttempt); err != nil {
		t.Fatalf("insert isolated generation-one pointer: %v", err)
	}
	if err := fixture.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	eligible, err := client.GetRunSafetySnapshot(ctx, tenant, ambiguousRunID)
	if err != nil || eligible.RunID != ambiguousRunID || eligible.BreakerState != "CLOSED" ||
		eligible.BreakerEpoch != 1 || eligible.Status != "RUNNING" {
		t.Fatalf("single current Attempt must pass live Runtime safety read: %+v err=%v", eligible, err)
	}
	// Fixture-only SQL models inconsistent durable history. A second
	// execution is never authorized here and no protected effect occurs.
	if _, err := db.Exec(ctx, `
		INSERT INTO runtime_run_attempts
		(tenant_id,run_id,run_attempt_id,workflow_id,temporal_execution_id)
		SELECT r.tenant_id,r.run_id,pg_catalog.gen_random_uuid(),
		       r.workflow_id,pg_catalog.gen_random_uuid()
		FROM runs r WHERE r.tenant_id=$1 AND r.run_id=$2::uuid
	`, tenant, ambiguousRunID); err != nil {
		t.Fatalf("seed second immutable historical Attempt: %v", err)
	}
	assertAmbiguousDenied("two immutable Attempts with one current pointer")
	var attempts, pointers int
	if err := db.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM runtime_run_attempts WHERE tenant_id=$1 AND run_id=$2::uuid),
			(SELECT count(*) FROM runtime_current_attempts WHERE tenant_id=$1 AND run_id=$2::uuid)
	`, tenant, ambiguousRunID).Scan(&attempts, &pointers); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || pointers != 1 {
		t.Fatalf("Guard safety read mutated durable historical identities: attempts=%d pointers=%d", attempts, pointers)
	}
	if stillEligible, err := client.GetRunSafetySnapshot(ctx, tenant, runID); err != nil ||
		stillEligible.Status != "RUNNING" || stillEligible.BreakerState != "CLOSED" {
		t.Fatalf("independent Run was incorrectly fenced: %+v err=%v", stillEligible, err)
	}
	if _, err := db.Exec(ctx, `
		UPDATE runtime_circuit_breakers
		SET state='OPEN',reason_code='UNAUTHORIZED_EGRESS',trigger_event_id='live-safety-test',
		    opened_at=clock_timestamp(),epoch=2,version=2,updated_at=clock_timestamp()
		WHERE scope_kind='RUN' AND scope_id=$1
	`, runID); err != nil {
		t.Fatal(err)
	}
	assertDenied()
	if _, err := db.Exec(ctx, "UPDATE runs SET status='CANCELLED',updated_at=clock_timestamp() WHERE tenant_id=$1 AND run_id=$2::uuid", tenant, runID); err != nil {
		t.Fatal(err)
	}
	assertDenied()
	var runs, events int
	if err := db.QueryRow(ctx, "SELECT (SELECT count(*) FROM runs),(SELECT count(*) FROM runtime_outbox)").Scan(&runs, &events); err != nil || runs != 2 || events != 2 {
		t.Fatalf("read-only network authority created effects: %d/%d %v", runs, events, err)
	}
	t.Logf("actual pinned Runtime safety authority read and denied the same Run %s", runID)
}
