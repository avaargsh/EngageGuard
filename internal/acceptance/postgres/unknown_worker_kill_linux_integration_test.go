//go:build linux

package postgres

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

const unknownWorkerCommitted = "engageguard-test-unknown-committed"

// This test exercises a real Linux process termination after the UNKNOWN
// journal transaction commits. No provider is invoked, and the marker is
// test coordination, not a provider acknowledgement or receipt.
func TestUnknownJournalSurvivesWorkerProcessKill(t *testing.T) {
	if os.Getenv("ENGAGEGUARD_TEST_UNKNOWN_WORKER") == "1" {
		runUnknownJournalWorkerFixture(t)
		return
	}

	store, resolved, permitID := seededWorkspacePermit(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	intent, err := store.ClaimAuthorizedIntent(ctx, permitID, resolved)
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUnknownJournalSurvivesWorkerProcessKill$")
	cmd.Env = append(os.Environ(),
		"ENGAGEGUARD_TEST_UNKNOWN_WORKER=1",
		"ENGAGEGUARD_TEST_SCHEMA="+store.trustedSchema,
		"ENGAGEGUARD_TEST_TENANT="+resolved.TenantID,
		"ENGAGEGUARD_TEST_OPERATION="+resolved.OperationID,
		"ENGAGEGUARD_TEST_ATTEMPT="+intent.AttemptID,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	scanner := bufio.NewScanner(stdout)
	committed := false
	for scanner.Scan() {
		if scanner.Text() == unknownWorkerCommitted {
			committed = true
			break
		}
	}
	if !committed {
		waitErr := cmd.Wait()
		waited = true
		t.Fatalf("worker did not report a committed journal: wait=%v scan=%v stderr=%s", waitErr, scanner.Err(), stderr.String())
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	waitErr := cmd.Wait()
	waited = true
	var exitErr *exec.ExitError
	if !errors.As(waitErr, &exitErr) {
		t.Fatalf("expected killed worker, got %v", waitErr)
	}
	status, ok := exitErr.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("worker did not exit by SIGKILL: %v", waitErr)
	}

	observed, err := store.GetDispatchState(ctx, resolved.TenantID, resolved.OperationID, intent.AttemptID)
	if err != nil || observed.State != "UNKNOWN" || observed.Reason != "ACK_LOST" ||
		observed.PermitID != permitID || observed.AttemptID != intent.AttemptID {
		t.Fatalf("worker termination lost journal evidence: state=%+v err=%v", observed, err)
	}
	replayed, err := store.MarkDispatchUnknown(ctx, resolved.TenantID, resolved.OperationID, intent.AttemptID, "ACK_LOST")
	if err != nil || replayed != observed {
		t.Fatalf("recovery did not preserve the committed journal: state=%+v err=%v", replayed, err)
	}
	var events, intents, audits int
	if err := store.db.QueryRowContext(ctx, `
		SELECT (SELECT count(*) FROM guard_operation_unknown_events),
		       (SELECT count(*) FROM guard_operation_intents),
		       (SELECT count(*) FROM guard_execution_audit)
	`).Scan(&events, &intents, &audits); err != nil {
		t.Fatal(err)
	}
	if events != 1 || intents != 1 || audits != 1 {
		t.Fatalf("worker termination changed ledger cardinality: events=%d intents=%d audits=%d", events, intents, audits)
	}
}

func runUnknownJournalWorkerFixture(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	schema := os.Getenv("ENGAGEGUARD_TEST_SCHEMA")
	dsn := os.Getenv("GUARD_PG_DSN")
	if dsn == "" || !strings.HasPrefix(schema, "guard_accept_") {
		t.Fatal("worker fixture requires an isolated integration schema")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*cfg)
	defer db.Close()
	store, err := NewWithTrustedSchema(db, schema)
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.MarkDispatchUnknown(ctx,
		os.Getenv("ENGAGEGUARD_TEST_TENANT"),
		os.Getenv("ENGAGEGUARD_TEST_OPERATION"),
		os.Getenv("ENGAGEGUARD_TEST_ATTEMPT"),
		"ACK_LOST",
	)
	if err != nil || state.State != "UNKNOWN" {
		t.Fatalf("worker journal failed: state=%+v err=%v", state, err)
	}
	fmt.Println(unknownWorkerCommitted)
	// The parent must terminate this process rather than let it return
	// normally. The deadline prevents an abandoned test from hanging.
	<-ctx.Done()
	t.Fatal("worker was not terminated by its parent")
}
