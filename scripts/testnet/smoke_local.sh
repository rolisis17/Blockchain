#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

LOG_DIR="${LOG_DIR:-/tmp/fastpos-testnet-logs}"
mkdir -p "$LOG_DIR"

NODE_CONFIGS=(
  "configs/testnet/local/node1.yaml"
  "configs/testnet/local/node2.yaml"
  "configs/testnet/local/node3.yaml"
)
NODE_PORTS=(18081 18082 18083)
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  for pid in "${PIDS[@]:-}"; do
    wait "$pid" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

wait_ready() {
  local base_url="$1"
  for _ in $(seq 1 60); do
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

for i in "${!NODE_CONFIGS[@]}"; do
  cfg="${NODE_CONFIGS[$i]}"
  node_name="node$((i+1))"
  log_file="$LOG_DIR/$node_name.log"
  go run ./cmd/node -config "$cfg" >"$log_file" 2>&1 &
  PIDS+=("$!")
  echo "started $node_name ($cfg), log=$log_file"
done

for port in "${NODE_PORTS[@]}"; do
  if ! wait_ready "http://127.0.0.1:$port"; then
    echo "node on port $port did not become ready"
    exit 1
  fi
  echo "node on port $port is ready"
done

sleep 6

for port in "${NODE_PORTS[@]}"; do
  status_json="$(curl -sf "http://127.0.0.1:$port/p2p/status")"
  accepted="$(extract_number "$status_json" "acceptedTotal")"
  if [[ -z "$accepted" || "$accepted" -eq 0 ]]; then
    echo "p2p acceptedTotal is zero on node $port: $status_json"
    exit 1
  fi

  metrics_json="$(curl -sf "http://127.0.0.1:$port/metrics.json")"
  height="$(extract_number "$metrics_json" "height")"
  if [[ -z "$height" || "$height" -lt 1 ]]; then
    echo "height check failed on node $port: $metrics_json"
    exit 1
  fi

  echo "node $port p2p.acceptedTotal=$accepted height=$height"
done

ALICE_PRIV="2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db186d6e90d5bf4a3fcce717b0388bcc2749ebc148ad9969b23f45ee1b605fd58778576ac4"
BOB_ADDR="34fec43c7fcab9aef3b3cf8aba855e41ee69ca3a"

submit_response="$(curl -sf -X POST http://127.0.0.1:18081/tx/sign-and-submit \
  -H 'content-type: application/json' \
  -d '{"privateKey":"'"$ALICE_PRIV"'","to":"'"$BOB_ADDR"'","amount":15,"fee":1}')"

echo "submitted tx via node1: $submit_response"

echo "local multi-node smoke test passed"
