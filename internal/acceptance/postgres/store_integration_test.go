package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func integrationStore(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("GUARD_PG_DSN")
	if dsn == "" {
		t.Skip("GUARD_PG_DSN required for real PostgreSQL integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin := stdlib.OpenDB(*adminConfig)
	if err := admin.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("guard_accept_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*config)
	db.SetMaxOpenConns(20)
	t.Cleanup(func() {
		db.Close()
		_, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
	})
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("migration: %v", err)
	}
	return New(db), db
}

func sampleSubmission() []byte {
	return []byte(`{"schema_version":"action-submission.v1","run_id":"run-1","decision_id":"dec-1","plan_id":"plan-1","plan_hash":"` +
		strings.Repeat("a", 64) + `","step_id":"step-1","capability":{"id":"workspace.write","version":"1.0.0","contract_sha256":"` +
		strings.Repeat("b", 64) + `"},"resource_ref":"workspace-1","arguments":{"path":"docs/a.txt","content":"hi"}}`)
}

func TestConcurrentSameKeyCreatesOneDurableOperationAndOutbox(t *testing.T) {
	store, db := integrationStore(t)
	const callers = 12
	type answer struct {
		op Operation
		created bool
		err error
	}
	out := make(chan answer, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			op, created, err := store.Accept(context.Background(), "tenant-a", "stable-key", sampleSubmission())
			out <- answer{op, created, err}
		}()
	}
	wg.Wait()
	close(out)
	var operationID string
	createdCount := 0
	for a := range out {
		if a.err != nil { t.Fatal(a.err) }
		if a.op.OperationID == "" || a.op.Status != "ACCEPTED" { t.Fatalf("bad operation: %+v", a.op) }
		if operationID != "" && operationID != a.op.OperationID { t.Fatal("duplicate operation created") }
		operationID = a.op.OperationID
		if a.created { createdCount++ }
	}
	if createdCount != 1 { t.Fatalf("created %d operations, want 1", createdCount) }
	var ops, events int
	if err := db.QueryRow("SELECT count(*) FROM guard_action_operations").Scan(&ops); err != nil { t.Fatal(err) }
	if err := db.QueryRow("SELECT count(*) FROM guard_outbox_events").Scan(&events); err != nil { t.Fatal(err) }
	if ops != 1 || events != 1 { t.Fatalf("operations=%d outbox=%d, want one each", ops, events) }
	var eventType string
	if err := db.QueryRow("SELECT event_type FROM guard_outbox_events").Scan(&eventType); err != nil { t.Fatal(err) }
	if eventType != "guard.submission.recorded.v1" { t.Fatalf("unsafe dispatchable event type: %s", eventType) }
}

func TestReplayConflictAndTenantScopeAcrossStoreRecreation(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	first, created, err := store.Accept(ctx, "tenant-a", "key-a", sampleSubmission())
	if err != nil || !created { t.Fatalf("initial: %v %v", created, err) }
	another := New(db)
	replay, created, err := another.Accept(ctx, "tenant-a", "key-a", sampleSubmission())
	if err != nil || created || replay.OperationID != first.OperationID { t.Fatalf("replay: %+v %v %v", replay, created, err) }
	mutated := strings.Replace(string(sampleSubmission()), "docs/a.txt", "docs/b.txt", 1)
	if _, _, err := another.Accept(ctx, "tenant-a", "key-a", []byte(mutated)); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed digest should conflict: %v", err)
	}
	separate, created, err := another.Accept(ctx, "tenant-b", "key-a", sampleSubmission())
	if err != nil || !created || separate.OperationID == first.OperationID { t.Fatalf("tenant isolation: %+v %v %v", separate, created, err) }
}

func TestOutboxFailureRollsBackOperation(t *testing.T) {
	store, db := integrationStore(t)
	_, err := db.Exec(`CREATE FUNCTION reject_guard_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test outbox failure'; END; $$`)
	if err != nil { t.Fatal(err) }
	_, err = db.Exec(`CREATE TRIGGER reject_outbox BEFORE INSERT ON guard_outbox_events FOR EACH ROW EXECUTE FUNCTION reject_guard_outbox()`)
	if err != nil { t.Fatal(err) }
	if _, _, err := store.Accept(context.Background(), "tenant-a", "key-failure", sampleSubmission()); err == nil {
		t.Fatal("outbox failure silently accepted")
	}
	var ops int
	if err := db.QueryRow(`SELECT count(*) FROM guard_action_operations`).Scan(&ops); err != nil { t.Fatal(err) }
	if ops != 0 { t.Fatalf("operation escaped failed outbox transaction: %d", ops) }
}

func TestInvalidSubmissionRejectedBeforePersistence(t *testing.T) {
	store, db := integrationStore(t)
	if _, _, err := store.Accept(context.Background(), "tenant-a", "bad key", sampleSubmission()); err == nil { t.Fatal("bad key accepted") }
	if _, _, err := store.Accept(context.Background(), "tenant-a", "valid-key", []byte(`{"operation_id":"spoofed"}`)); err == nil { t.Fatal("untrusted operation accepted") }
	if _, _, err := store.Accept(context.Background(), "", "valid-key", sampleSubmission()); err == nil { t.Fatal("missing authenticated tenant accepted") }
	var ops int
	if err := db.QueryRow(`SELECT count(*) FROM guard_action_operations`).Scan(&ops); err != nil { t.Fatal(err) }
	if ops != 0 { t.Fatalf("invalid input wrote %d operation(s)", ops) }
}
