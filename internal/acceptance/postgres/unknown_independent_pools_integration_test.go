package postgres

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Exercise two independent connection pools against the same durable ledger.
// This does not simulate a provider effect or an actual process SIGKILL.
func TestUnknownRecoveryAcrossIndependentStorePools(t *testing.T) {
	first, resolved, permitID := seededWorkspacePermit(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg, err := pgx.ParseConfig(os.Getenv("GUARD_PG_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["search_path"] = first.trustedSchema
	secondDB := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = secondDB.Close() })
	second, err := NewWithTrustedSchema(secondDB, first.trustedSchema)
	if err != nil {
		t.Fatal(err)
	}
	if err := secondDB.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	intent, err := first.ClaimAuthorizedIntent(ctx, permitID, resolved)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		state DispatchState
		err   error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, replica := range []*Store{first, second} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			state, err := replica.MarkDispatchUnknown(ctx, resolved.TenantID, resolved.OperationID, intent.AttemptID, "WORKER_KILLED")
			results <- result{state: state, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var expected DispatchState
	for got := range results {
		if got.err != nil || got.state.State != "UNKNOWN" ||
			got.state.Reason != "WORKER_KILLED" || got.state.AttemptID != intent.AttemptID ||
			got.state.PermitID != permitID {
			t.Fatalf("replica did not recover the same attempt: state=%+v err=%v", got.state, got.err)
		}
		if expected.AttemptID != "" && got.state != expected {
			t.Fatalf("replicas disagreed: expected=%+v got=%+v", expected, got.state)
		}
		expected = got.state
	}

	// Closing the original pool must not make recovery depend on its process
	// memory or connection lifetime.
	if err := first.db.Close(); err != nil {
		t.Fatal(err)
	}
	observed, err := second.GetDispatchState(ctx, resolved.TenantID, resolved.OperationID, intent.AttemptID)
	if err != nil || observed != expected {
		t.Fatalf("independent pool lost durable recovery state: state=%+v err=%v", observed, err)
	}
	var events, intents, audits int
	if err := secondDB.QueryRowContext(ctx, `
		SELECT (SELECT count(*) FROM guard_operation_unknown_events),
		       (SELECT count(*) FROM guard_operation_intents),
		       (SELECT count(*) FROM guard_execution_audit)
	`).Scan(&events, &intents, &audits); err != nil {
		t.Fatal(err)
	}
	if events != 1 || intents != 1 || audits != 1 {
		t.Fatalf("recovery changed ledger cardinality: events=%d intents=%d audits=%d", events, intents, audits)
	}
}
