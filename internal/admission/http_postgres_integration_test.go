package admission

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"encoding/json"
	"strings"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/avaargsh/EngageGuard/internal/acceptance/postgres"
)

func admissionPostgresStore(t *testing.T) (*postgres.Store, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("GUARD_PG_DSN")
	if dsn == "" {
		t.Skip("GUARD_PG_DSN required for real HTTP admission integration")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin := stdlib.OpenDB(*config)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("guard_http_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*config)
	db.SetMaxOpenConns(20)
	t.Cleanup(func() {
		_ = db.Close()
		_, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close()
	})
	if err := postgres.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	return postgres.New(db), db
}

func TestHTTPAdmissionUsesPostgresOperationReplayAndConflict(t *testing.T) {
	store, db := admissionPostgresStore(t)
	resolver := &fakeResolver{principal: Principal{
		TenantID: "tenant-http", SubjectID: "user-http",
		ActorID: "agent-runtime", WorkloadID: "runtime-http",
		ServiceID: "agent-runtime",
	}}
	verifier := &fakeVerifier{}
	handler := NewHandler(resolver, verifier, store)

	first := exercise(handler, "stable-http-key", goodBody())
	replay := exercise(handler, "stable-http-key", goodBody())
	if first.Code != http.StatusCreated || replay.Code != http.StatusOK {
		t.Fatalf("HTTP statuses = %d/%d, want 201/200; bodies: %s / %s",
			first.Code, replay.Code, first.Body.String(), replay.Body.String())
	}
	var firstResult, replayResult struct {
		OperationID string `json:"operation_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &firstResult); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(replay.Body.Bytes(), &replayResult); err != nil {
		t.Fatal(err)
	}
	if firstResult.OperationID == "" || firstResult.OperationID != replayResult.OperationID ||
		firstResult.Status != "ACCEPTED" || replayResult.Status != "ACCEPTED" {
		t.Fatalf("HTTP replay did not preserve the same accepted Operation: %+v / %+v", firstResult, replayResult)
	}

	changed := strings.Replace(goodBody(), "docs/a.txt", "docs/b.txt", 1)
	conflict := exercise(handler, "stable-http-key", changed)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("same key with changed body status = %d, want 409: %s", conflict.Code, conflict.Body.String())
	}
	if resolver.calls != 3 || verifier.calls != 3 {
		t.Fatalf("each retry must be authenticated and reverified: resolver=%d verifier=%d",
			resolver.calls, verifier.calls)
	}
	var operations, outbox int
	if err := db.QueryRow("SELECT count(*) FROM guard_action_operations").Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT count(*) FROM guard_outbox_events").Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if operations != 1 || outbox != 1 {
		t.Fatalf("HTTP retry created duplicate durable records: operations=%d outbox=%d", operations, outbox)
	}
}
