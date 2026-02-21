# fastpos

Simplified PoS blockchain for iterative real-world hardening before product integration.

It currently provides:

- Signed account transfers (ed25519)
- Stake-weighted proposer selection + validator voting (`>=2/3` effective stake finality)
- Validator `workWeight` hook for external scoring
- Persistent snapshots + restart recovery
- Configurable genesis file
- Configurable node runtime via `config.yaml`
- Mempool policy controls: min fee, max pool size, higher-fee replacement
- Health/readiness/metrics endpoints

This is still pre-production.

## Quick Start

1. Run with defaults:

```bash
go run ./cmd/node
```

2. Run with config file:

```bash
go run ./cmd/node -config ./configs/node.example.yaml
```

3. Override config values with CLI flags:

```bash
go run ./cmd/node \
  -config ./configs/node.example.yaml \
  -http :8080 \
  -admin-token my-admin-token \
  -allow-dev-signing=false
```

Precedence is: `defaults < config file < CLI flags`.

## Key Runtime Flags

- `-config` path to YAML config
- `-genesis` genesis JSON path (optional)
- `-state` snapshot file path
- `-block-interval`
- `-max-tx`
- `-max-mempool`
- `-min-tx-fee`
- `-admin-token` (or env `FASTPOS_ADMIN_TOKEN`)
- `-allow-dev-signing` (unsafe; local dev only)
- `-readiness-max-lag` (0 = auto)

## API

- `GET /healthz`
- `GET /readyz`
- `GET /metrics` (Prometheus text format)
- `GET /metrics.json`
- `GET /status`
- `GET /validators`
- `POST /validators/work-weight` (admin token)
- `POST /validators/active` (admin token)
- `GET /accounts/{address}`
- `GET /nonce/{address}`
- `GET /blocks?from=0&limit=20`
- `POST /tx` (submit pre-signed tx)
- `POST /wallets` (dev signing mode only)
- `POST /tx/sign` (dev signing mode only)
- `POST /tx/sign-and-submit` (dev signing mode only)

Admin endpoints require header:

```text
X-Admin-Token: <token>
```

## Genesis

Example genesis: `configs/genesis.example.json`

- `accounts`: initial balances
- `validators`: validator set (`id`, `pubKey`, `stake`, `workWeight`, `active`)
- `genesisTimestampMs`: fixed genesis timestamp for deterministic replay/network startup

If no `-genesis` is provided, deterministic built-in genesis is used.

## Wallet CLI

Generate wallet:

```bash
go run ./cmd/wallet gen
```

Sign tx:

```bash
go run ./cmd/wallet sign \
  --priv <hex-private-key> \
  --to <recipient-address> \
  --amount 10 \
  --fee 1 \
  --nonce 1
```

Then submit signed JSON to `POST /tx`.

## Testing

```bash
go test ./...
```

## Roadmap

See `ROADMAP.md` for phased progress toward a production-usable network.

Phase 2 protocol draft and signed network message primitives are in:

- `docs/phase2-network-protocol.md`
- `internal/p2p/messages.go`
