#!/usr/bin/env bash
set -euo pipefail
: "${RUNTIME_SAFETY_BIN:?pinned Runtime API required}"
: "${GUARD_RUNTIME_TEST_FIXTURE_DSN:?isolated test database required}"
root="$(mktemp -d)"
pid=""
execution_pid=""
cleanup() {
  if [[ -n "$execution_pid" ]]; then
    kill "$execution_pid" 2>/dev/null || true
    wait "$execution_pid" 2>/dev/null || true
  fi
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf -- "$root"
}
trap cleanup EXIT
umask 077

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=Disposable Guard Runtime CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$root/ca.key" -out "$root/ca.crt" >/dev/null 2>&1
issue() {
  local name="$1" uri="$2" usage="$3" san="$4"
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$name" \
    -keyout "$root/$name.key" -out "$root/$name.csr" >/dev/null 2>&1
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\nsubjectAltName=%sURI:%s\n' \
    "$usage" "$san" "$uri" > "$root/$name.ext"
  openssl x509 -req -days 1 -in "$root/$name.csr" -CA "$root/ca.crt" \
    -CAkey "$root/ca.key" -CAcreateserial -extfile "$root/$name.ext" \
    -out "$root/$name.crt" >/dev/null 2>&1
}
export GUARD_RUNTIME_SPIFFE="spiffe://platform.example/ns/runtime/sa/agent-runtime"
export GUARD_RUNTIME_TENANT="tenant-1"
export GUARD_RUNTIME_ORIGIN="https://127.0.0.1:18443"
acp="spiffe://platform.example/ns/control/sa/agent-control-panel"
guard="spiffe://platform.example/ns/guard/sa/engageguard"
issue runtime "$GUARD_RUNTIME_SPIFFE" serverAuth 'IP:127.0.0.1,'
issue acp "$acp" clientAuth ''
issue guard "$guard" clientAuth ''

# Explicit minimal service environment. No tokens or inherited CI secrets.
env -i PATH="$PATH" HOME="$HOME" RUNTIME_DATABASE_URL="$GUARD_RUNTIME_TEST_FIXTURE_DSN" \
  RUNTIME_TLS_CERT="$root/runtime.crt" RUNTIME_TLS_KEY="$root/runtime.key" \
  RUNTIME_CLIENT_CA="$root/ca.crt" RUNTIME_ACP_SPIFFE_ID="$acp" \
  RUNTIME_ACP_LISTEN_ADDR=127.0.0.1:18443 RUNTIME_SAFETY_SPIFFE_ID="$guard" \
  RUNTIME_SAFETY_TENANT="$GUARD_RUNTIME_TENANT" "$RUNTIME_SAFETY_BIN" >"$root/runtime.log" 2>&1 &
pid=$!
request=(curl --silent --show-error --cacert "$root/ca.crt" --cert "$root/acp.crt" --key "$root/acp.key" --max-time 3)
ready=0
for _ in $(seq 1 60); do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo 'isolated Runtime API startup failed'
    exit 1
  fi
  if code="$("${request[@]}" -o /dev/null -w '%{http_code}' "$GUARD_RUNTIME_ORIGIN/health-probe" 2>/dev/null)" && [[ "$code" == 404 ]]; then
    ready=1
    break
  fi
  sleep 1
done
[[ "$ready" == 1 ]]
cat > "$root/accept.json" <<'JSON'
{"tenant_id":"tenant-1","run_intent_id":"11111111-1111-4111-8111-111111111111","request_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","agent_id":"agent-1","agent_release_id":"release-1","session_id":"session-1","input":{"objective":"sre_incident_triage","service":"payments","signal":"latency"},"principal_context":{"version":"acp-principal/v1","project_id":"project-1","subject_id":"subject-1","actor_id":"subject-1","policy_revision":"policy-1","config_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}
JSON
code="$("${request[@]}" -o "$root/receipt.json" -w '%{http_code}' -H 'Content-Type: application/json' --data-binary "@$root/accept.json" "$GUARD_RUNTIME_ORIGIN/internal/v2/run-intents:accept")"
[[ "$code" == 201 ]]
export GUARD_RUNTIME_RUN="$(python3 - "$root/receipt.json" <<'PY'
import json, sys, uuid
r = json.load(open(sys.argv[1]))
assert r["status"] == "FOUND" and r["created"] is True
assert str(uuid.UUID(r["run_id"])) == r["run_id"]
print(r["run_id"])
PY
)"
# Second isolated ACP-accepted Run verifies an ambiguous persisted Attempt
# without weakening the original Run's breaker and terminal-state assertions.
python3 - "$root/accept.json" "$root/ambiguous.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    data = json.load(stream)
data["run_intent_id"] = "33333333-3333-4333-8333-333333333333"
with open(sys.argv[2], "w", encoding="utf-8") as stream:
    json.dump(data, stream)
PY
code="$("${request[@]}" -o "$root/ambiguous-receipt.json" -w '%{http_code}' \
  -H 'Content-Type: application/json' --data-binary "@$root/ambiguous.json" \
  "$GUARD_RUNTIME_ORIGIN/internal/v2/run-intents:accept")"
[[ "$code" == 201 ]]
export GUARD_RUNTIME_AMBIGUOUS_RUN="$(python3 - "$root/ambiguous-receipt.json" <<'PY'
import json, sys, uuid
with open(sys.argv[1], encoding="utf-8") as stream:
    receipt = json.load(stream)
assert receipt["status"] == "FOUND" and receipt["created"] is True
assert str(uuid.UUID(receipt["run_id"])) == receipt["run_id"]
print(receipt["run_id"])
PY
)"
export GUARD_RUNTIME_CA="$root/ca.crt" GUARD_RUNTIME_CERT="$root/guard.crt" GUARD_RUNTIME_KEY="$root/guard.key"
# The dedicated Runtime execution reader uses a different server identity
# and a SELECT-only PostgreSQL role, not the ACP API's writer credential.
if [[ -n "${RUNTIME_EXECUTION_AUTHORITY_BIN:-}" ]]; then
  : "${GUARD_RUNTIME_EXECUTION_TEST_DSN:?isolated read-only role DSN required}"
  psql "$GUARD_RUNTIME_TEST_FIXTURE_DSN" -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE guard_execution_reader LOGIN PASSWORD 'isolated-reader-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO guard_execution_reader;
GRANT SELECT ON TABLE public.runs, public.runtime_run_principal_snapshots,
  public.runtime_run_attempts, public.runtime_current_attempts,
  public.runtime_decision_turns, public.runtime_circuit_breakers TO guard_execution_reader;
SQL
  # No write privilege even with an ordinary read-write transaction.
  if psql "$GUARD_RUNTIME_EXECUTION_TEST_DSN" -v ON_ERROR_STOP=1 -c 'UPDATE public.runs SET status=status WHERE false' >"$root/reader-write.log" 2>&1; then
    echo 'execution reader has unexpected UPDATE privilege'
    exit 1
  fi
  grep -Fq 'permission denied for table runs' "$root/reader-write.log"
  export GUARD_RUNTIME_EXECUTION_SPIFFE="spiffe://platform.example/ns/runtime/sa/guard-authority"
  export GUARD_RUNTIME_EXECUTION_ORIGIN="https://127.0.0.1:18446"
  issue execution "$GUARD_RUNTIME_EXECUTION_SPIFFE" serverAuth 'IP:127.0.0.1,'
  env -i PATH="$PATH" HOME="$HOME" \
    RUNTIME_GUARD_AUTHORITY_DATABASE_URL="$GUARD_RUNTIME_EXECUTION_TEST_DSN" \
    RUNTIME_GUARD_AUTHORITY_TLS_CERT="$root/execution.crt" \
    RUNTIME_GUARD_AUTHORITY_TLS_KEY="$root/execution.key" \
    RUNTIME_GUARD_AUTHORITY_CLIENT_CA="$root/ca.crt" \
    RUNTIME_GUARD_AUTHORITY_PEER_SPIFFE_ID="$guard" \
    RUNTIME_GUARD_AUTHORITY_TENANT="$GUARD_RUNTIME_TENANT" \
    RUNTIME_GUARD_AUTHORITY_LISTEN_ADDR=127.0.0.1:18446 \
    "$RUNTIME_EXECUTION_AUTHORITY_BIN" >"$root/execution.log" 2>&1 &
  execution_pid=$!
  ready=0
  for _ in $(seq 1 60); do
    if ! kill -0 "$execution_pid" 2>/dev/null; then
      echo 'isolated Runtime execution authority startup failed'
      cat "$root/execution.log"
      exit 1
    fi
    if code="$(curl --silent --show-error --cacert "$root/ca.crt" --cert "$root/guard.crt" --key "$root/guard.key" --max-time 3 -o /dev/null -w '%{http_code}' "$GUARD_RUNTIME_EXECUTION_ORIGIN/health-probe" 2>/dev/null)" && [[ "$code" == 400 ]]; then
      ready=1
      break
    fi
    sleep 1
  done
  [[ "$ready" == 1 ]]
  export GUARD_LIVE_RUNTIME_EXECUTION=1
fi
export GUARD_LIVE_RUNTIME_SAFETY=1
go test -race -count=1 -v -run '^TestLiveRuntimeRunSafetyAuthority$' ./internal/admission | tee "$root/acceptance.log"
grep -Fq '=== RUN   TestLiveRuntimeRunSafetyAuthority' "$root/acceptance.log"
grep -Fq -- '--- PASS: TestLiveRuntimeRunSafetyAuthority ' "$root/acceptance.log"
if [[ "${GUARD_LIVE_RUNTIME_EXECUTION:-}" == 1 ]]; then
  grep -Fq 'actual pinned Runtime execution authority verified current Attempt/Turn and denied superseded Turn' "$root/acceptance.log"
fi
