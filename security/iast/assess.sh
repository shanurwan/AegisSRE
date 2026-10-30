#!/usr/bin/env bash
# Judge an IAST run after the instrumented topology has been stopped with
# SIGTERM (which flushes coverage counters). Fails when the attack traffic
# triggered a data race, a panic or a non-zero exit, or when it never reached
# the code that enforces the security boundary.
#
# usage: security/iast/assess.sh <compose args...>
set -euo pipefail

coverage=build/iast
# Packages that authenticate, authorize and parse untrusted protocol input.
boundary=(
  github.com/shanurwan/AegisSRE/internal/security
  github.com/shanurwan/AegisSRE/internal/transport/a2a
  github.com/shanurwan/AegisSRE/internal/transport/mcp
)

status=0

if compgen -G "$coverage/race.*" >/dev/null; then
  echo "IAST: the race detector reported data races:"
  cat "$coverage"/race.*
  status=1
fi

logs="$(docker compose "$@" logs --no-color 2>&1)"
if grep -E 'panic:|fatal error:' <<<"$logs"; then
  echo "IAST: a process panicked under attack traffic"
  status=1
fi

# restart: unless-stopped hides a crash behind a fresh process, so a restart
# counts as a failure just like a non-zero exit.
mapfile -t containers < <(docker compose "$@" ps --all --quiet)
if [[ "${#containers[@]}" -eq 0 ]]; then
  echo "IAST: no containers found for the topology"
  exit 1
fi
while read -r name restarts code; do
  if [[ "$restarts" != "0" || "$code" != "0" ]]; then
    echo "IAST: $name restarted $restarts time(s), last exit $code"
    status=1
  fi
done < <(docker inspect --format '{{.Name}} {{.RestartCount}} {{.State.ExitCode}}' "${containers[@]}")

if ! compgen -G "$coverage/covmeta.*" >/dev/null; then
  echo "IAST: no coverage was written; the processes did not shut down cleanly"
  exit 1
fi

go tool covdata percent -i "$coverage" | tee "$coverage/percent.txt"
for package in "${boundary[@]}"; do
  line="$(grep -E "^[[:space:]]*$package[[:space:]]" "$coverage/percent.txt" || true)"
  if [[ -z "$line" ]] || grep -qE 'coverage: 0\.0% of statements' <<<"$line"; then
    echo "IAST: attack traffic never reached $package"
    status=1
  fi
done
go tool covdata textfmt -i "$coverage" -o "$coverage/profile.out"

exit "$status"
