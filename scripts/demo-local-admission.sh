#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname -- "${BASH_SOURCE[0]}")/.."

if ! command -v go >/dev/null; then
  printf 'Install Go 1.26 or newer to run the EngageGuard demo.\n' >&2
  exit 1
fi

if command -v initdb >/dev/null && command -v pg_ctl >/dev/null; then
  initdb_bin=initdb
  pg_ctl_bin=pg_ctl
elif command -v pg_config >/dev/null; then
  pg_bin=$(pg_config --bindir)
  initdb_bin="$pg_bin/initdb"
  pg_ctl_bin="$pg_bin/pg_ctl"
else
  printf 'Install PostgreSQL server tools (initdb and pg_ctl) to run the demo.\n' >&2
  exit 1
fi

if ! command -v "$initdb_bin" >/dev/null || ! command -v "$pg_ctl_bin" >/dev/null; then
  printf 'Install PostgreSQL server tools (initdb and pg_ctl) to run the demo.\n' >&2
  exit 1
fi

demo_dir=$(mktemp -d /tmp/engageguard-demo.XXXXXXXX)
cleanup() {
  if [[ -f "$demo_dir/data/postmaster.pid" ]]; then
    if ! "$pg_ctl_bin" -D "$demo_dir/data" -m fast -s -w stop; then
      printf 'Could not stop the demo database. Its files are in %s.\n' "$demo_dir" >&2
      return 1
    fi
  fi
  rm -rf -- "$demo_dir"
}
trap 'cleanup || exit 1' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"$initdb_bin" -D "$demo_dir/data" --auth=trust --username=guard_demo --no-locale >/dev/null
if ! "$pg_ctl_bin" -D "$demo_dir/data" -o "-k $demo_dir -c listen_addresses=''" \
  -l "$demo_dir/postgres.log" -s -w start; then
  if [[ -f "$demo_dir/postgres.log" ]]; then
    cat "$demo_dir/postgres.log" >&2
  fi
  exit 1
fi

export GUARD_PG_DSN="host=$demo_dir dbname=postgres user=guard_demo"

# go test can exit successfully when a selected test is skipped or absent.
# Require a top-level PASS for each named fixture before reporting demo success.
run_demo_test() {
  local package=$1 test_name=$2
  go test -count=1 -v "$package" -run "^${test_name}$" | tee "$demo_dir/test.log"
  if ! grep -q "^--- PASS: ${test_name} (" "$demo_dir/test.log"; then
    printf 'Required demo test did not pass: %s\n' "$test_name" >&2
    return 1
  fi
}

run_demo_test ./internal/admission TestHTTPAdmissionUsesPostgresOperationReplayAndConflict
run_demo_test ./internal/acceptance/postgres TestPermitIssuerPostCommitCancellationPreservesReplayEvidence
run_demo_test ./internal/acceptance/postgres TestExecutorNecessaryGateAgainstRealPostgresClaimRevokeAndUnknown

run_demo_test ./internal/acceptance/postgres TestUnknownRecoveryAcrossIndependentStorePools
