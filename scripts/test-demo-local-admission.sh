#!/usr/bin/env bash
set -euo pipefail

# Exercise demo exit status with controlled command output, not a live database.
root=$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/bin"
for tool in initdb pg_ctl; do
  printf '#!/bin/sh\nexit 0\n' > "$tmp/bin/$tool"
done
cat > "$tmp/bin/go" <<'STUB'
#!/usr/bin/env bash
set -eu
for name in TestHTTPAdmissionUsesPostgresOperationReplayAndConflict TestPermitIssuerPostCommitCancellationPreservesReplayEvidence TestExecutorNecessaryGateAgainstRealPostgresClaimRevokeAndUnknown TestUnknownRecoveryAcrossIndependentStorePools; do
  if [[ "$*" == *"$name"* ]]; then
    if [[ "$name" == "$DEMO_TEST_TARGET" ]]; then
      case "$DEMO_TEST_MODE" in
        skip) printf '%s\n' "--- SKIP: $name (0.00s)"; continue ;;
        missing) continue ;;
        fail) printf '%s\n' "--- FAIL: $name (0.00s)"; exit 1 ;;
      esac
    fi
    printf '%s\n' "--- PASS: $name (0.00s)"
  fi
done
printf 'PASS\n'
STUB
chmod +x "$tmp/bin/"*

for target in TestPermitIssuerPostCommitCancellationPreservesReplayEvidence TestUnknownRecoveryAcrossIndependentStorePools; do
  for mode in pass skip missing fail; do
    if PATH="$tmp/bin:$PATH" DEMO_TEST_TARGET="$target" DEMO_TEST_MODE="$mode" bash "$root/scripts/demo-local-admission.sh" >"$tmp/output" 2>&1; then
      actual=0
    else
      actual=$?
    fi
    if [[ "$mode" == pass ]]; then
      expected=0
    else
      expected=1
    fi
    if (( actual != expected )); then
      printf 'FAIL: %s/%s: expected exit %s, got %s\n' "$target" "$mode" "$expected" "$actual" >&2
      cat "$tmp/output" >&2
      exit 1
    fi
    printf 'PASS: %s/%s\n' "$target" "$mode"
  done
done
