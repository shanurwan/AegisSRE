#!/usr/bin/env bash
# Actively attack every service of a running compose topology with ZAP's API
# scan, one fresh ZAP container per service, all in parallel. ZAP joins the
# same segmented networks as the services, so it sees the real topology.
#
# A scan that cannot run, or any Low-or-higher alert that is not an exact
# reviewed entry in accepted-risks.json (see gate.py), fails the gate.
#
# usage: security/dast/scan.sh <report-dir>
set -euo pipefail

ZAP_IMAGE="ghcr.io/zaproxy/zaproxy:stable@sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238"
NETWORKS=(aegissre-observe aegissre-control aegissre-operate)
TARGETS=(
  "aegis-monitor agents"
  "aegis-investigator agents"
  "aegis-operator agents"
  "aegis-mcp-read mcp"
  "aegis-mcp-action mcp"
)

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
reports="$(mkdir -p "$1" && cd "$1" && pwd)"
cp "$here"/*.openapi.yaml "$reports/"
# ZAP runs as an unprivileged user inside its container.
chmod 0777 "$reports"

pids=()
names=()
for target in "${TARGETS[@]}"; do
  read -r service spec <<<"$target"
  container="zap-$service"
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker create --name "$container" --network "${NETWORKS[0]}" \
    -v "$reports:/zap/wrk:rw" "$ZAP_IMAGE" \
    zap-api-scan.py -t "/zap/wrk/$spec.openapi.yaml" -f openapi \
    -O "http://$service:8080" -J "$service.json" -r "$service.html" >/dev/null
  for network in "${NETWORKS[@]:1}"; do
    docker network connect "$network" "$container"
  done
  docker start -a "$container" >"$reports/$service.log" 2>&1 &
  pids+=("$!")
  names+=("$service")
done

status=0
reports_json=()
for i in "${!pids[@]}"; do
  service="${names[$i]}"
  code=0
  wait "${pids[$i]}" || code=$?
  docker rm -f "zap-$service" >/dev/null 2>&1 || true
  echo "$service: zap exit=$code $(grep -E '^FAIL-NEW' "$reports/$service.log" || echo 'scan did not complete')"
  # 0 = clean, 1 = FAIL alerts, 2 = WARN alerts: judged by gate.py below.
  # Anything else means the scan itself did not run to completion.
  if [[ "$code" -gt 2 || ! -s "$reports/$service.json" ]]; then
    echo "$service: scan error, see $reports/$service.log"
    status=1
  else
    reports_json+=("$reports/$service.json")
  fi
done

if [[ "${#reports_json[@]}" -gt 0 ]]; then
  python3 "$here/gate.py" "${reports_json[@]}" || status=1
fi
exit "$status"
