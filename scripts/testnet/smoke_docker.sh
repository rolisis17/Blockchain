#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found"
  exit 1
fi

wait_ready() {
  local base_url="$1"
  for _ in $(seq 1 90); do
    if curl -sf "$base_url/readyz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

extract_number() {
  local json="$1"
  local key="$2"
  local raw
  raw="$(printf '%s' "$json" | rg -o '"'"$key"'":\s*[0-9]+' | head -n1 || true)"
  raw="${raw##*:}"
  raw="${raw// /}"
  printf '%s' "$raw"
}

cleanup() {
  docker compose -f docker-compose.testnet.yml down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker compose -f docker-compose.testnet.yml up -d

for port in 18081 18082 18083; do
  if ! wait_ready "http://127.0.0.1:$port"; then
    echo "node on port $port did not become ready"
    exit 1
  fi
  echo "node on port $port is ready"
done

sleep 6

for port in 18081 18082 18083; do
  status_json="$(curl -sf "http://127.0.0.1:$port/p2p/status")"
  accepted="$(extract_number "$status_json" "acceptedTotal")"
  if [[ -z "$accepted" || "$accepted" -eq 0 ]]; then
    echo "p2p acceptedTotal is zero on node $port: $status_json"
    exit 1
  fi
  echo "node $port p2p.acceptedTotal=$accepted"
done

echo "docker multi-node smoke test passed"
