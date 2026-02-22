# fastpos

Simplified PoS blockchain for iterative real-world hardening before product integration.

It currently provides:

- Signed account transfers (ed25519)
- Stake-weighted proposer selection + validator voting (`>=2/3` effective stake finality)
- Validator `workWeight` hook for external scoring
- Persistent state + restart recovery (JSON snapshot or SQLite backend)
- Configurable genesis file
- Configurable node runtime via `config.yaml`
- Mempool DoS controls: min fee, max pool size, higher-fee replacement, per-account pending caps, tx age expiry
- Health/readiness/metrics endpoints
- Signed p2p envelope validation (`/p2p/message`)
- Static peer gossip plus remote vote aggregation for proposal/vote/finalize consensus
- Periodic peer discovery/bootstrap from known peers via `/p2p/peers`
- Timeout-driven round/view-change fallback for offline scheduled proposers
- Runtime p2p peer management (`/p2p/peers`)
- Equivocation evidence capture for conflicting signed votes/proposals with operator-triggered slash+jail
- Peer broadcast backoff and inbound per-peer rate limiting defaults
- Startup peer sync for recovering nodes (block catch-up with snapshot fallback)
- On-chain validator lifecycle tx kinds (`validator_bond`, `validator_unbond`, `validator_slash`, `validator_jail`, `validator_unjail`)
- Height-based jail recovery rule with configurable minimum jail duration
- On-chain delegation tx kinds (`delegation_delegate`, `delegation_undelegate`) included in effective stake
- Epoch transitions with validator-set snapshot updates (`epochLengthBlocks`)
- Product integration tx kinds (`product_settle`, `product_attest`, `product_challenge`, `product_resolve_challenge`)
- Product treasury + epoch reward distribution from product signals (attestation score)
- Product proof/challenge/settlement state with fraud challenge resolution flow
- Product billing/settlement/attestation API endpoints
- Validator lifecycle admin override endpoints (bond/unbond/slash/jail)

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
- `-state-backend` (`snapshot` or `sqlite`)
- `-state` state file path (snapshot JSON or sqlite DB)
- `-backup-dir`
- `-backup-every-blocks`
- `-backup-retain`
- `-block-interval`
- `-max-tx`
- `-max-mempool`
- `-max-pending-per-account`
- `-max-mempool-age-blocks`
- `-min-tx-fee`
- `-min-jail-blocks` (0 = auto/default behavior)
- `-epoch-length-blocks`
- `-product-reward-bps`
- `-product-challenge-min-bond`
- `-product-unit-price`
- `-admin-token` (or env `FASTPOS_ADMIN_TOKEN`)
- `-allow-dev-signing` (unsafe; local dev only)
- `-readiness-max-lag` (0 = auto)
- `-p2p-enabled`
- `-node-id`
- `-validator-priv`
- `-p2p-proposer-timeout-ticks`
- `-p2p-max-round-lookahead`
- `-p2p-peer-backoff-initial`
- `-p2p-peer-backoff-max`
- `-p2p-inbound-rate-limit-per-peer`
- `-p2p-inbound-rate-window`
- `-peers` (comma-separated peer URLs)

SQLite state backend example:

```bash
go run ./cmd/node -state-backend sqlite -state ./data/state.db
```

## API

- `GET /healthz`
- `GET /readyz`
- `GET /metrics` (Prometheus text format)
- `GET /metrics.json`
- `GET /p2p/status`
- `POST /p2p/message`
- `GET /p2p/peers`
- `POST /p2p/peers` (admin token)
- `DELETE /p2p/peers?url=...` (admin token)
- `GET /p2p/evidence`
- `POST /p2p/evidence` (admin token; apply slash+jail for one evidence entry)
- `GET /sync/snapshot`
- `GET /status`
- `GET /epoch`
- `GET /validators`
- `GET /delegations` (`?delegator=...&validatorId=...` filters optional)
- `GET /product/status`
- `GET /product/proofs` (`?validatorId=...&includeInvalid=true|false`)
- `POST /product/attestations` (submit pre-signed `product_attest` tx)
- `GET /product/challenges`
- `POST /product/challenges` (submit pre-signed `product_challenge` tx)
- `POST /product/challenges/resolve` (submit pre-signed `product_resolve_challenge` tx)
- `GET /product/settlements`
- `POST /product/settlements` (submit pre-signed `product_settle` tx)
- `GET /product/billing/quote?units=...`
- `POST /validators/work-weight` (admin token)
- `POST /validators/active` (admin token)
- `POST /validators/bond` (admin token)
- `POST /validators/unbond` (admin token)
- `POST /validators/slash` (admin token)
- `POST /validators/jail` (admin token)
- `GET /accounts/{address}`
- `GET /nonce/{address}`
- `GET /blocks?from=0&limit=20`
- `POST /tx` (submit pre-signed tx)
- `POST /wallets` (dev signing mode only)
- `POST /tx/sign` (dev signing mode only)
- `POST /tx/sign-and-submit` (dev signing mode only)

Supported transaction kinds for `POST /tx`:

- `transfer`: requires `to`, `amount`, `fee`, `nonce`, `timestamp`
- `validator_bond`: requires `validatorId`, `amount`, `fee`, `nonce`, `timestamp`
- `validator_unbond`: requires `validatorId`, `amount`, `fee`, `nonce`, `timestamp`
- `validator_slash`: requires `validatorId`, `basisPoints`, `fee`, `nonce`, `timestamp`
- `validator_jail`: requires `validatorId`, `fee`, `nonce`, `timestamp`
- `validator_unjail`: requires `validatorId`, `fee`, `nonce`, `timestamp`
- `delegation_delegate`: requires `validatorId`, `amount`, `fee`, `nonce`, `timestamp`
- `delegation_undelegate`: requires `validatorId`, `amount`, `fee`, `nonce`, `timestamp`
- `product_settle`: requires `to` (product reference), `amount`, `fee`, `nonce`, `timestamp`
- `product_attest`: requires `to` (proof reference), `validatorId`, `amount`, `basisPoints`, `fee`, `nonce`, `timestamp`
- `product_challenge`: requires `to` (proof id), `amount` (bond), `fee`, `nonce`, `timestamp`
- `product_resolve_challenge`: requires `to` (challenge id), optional `amount` (bonus payout), `basisPoints` (`0` reject, `>0` accept+slash), `fee`, `nonce`, `timestamp`

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
  --kind transfer \
  --to <recipient-address> \
  --amount 10 \
  --fee 1 \
  --nonce 1
```

Sign validator bond tx:

```bash
go run ./cmd/wallet sign \
  --priv <hex-private-key> \
  --kind validator_bond \
  --validator-id v1 \
  --amount 100 \
  --fee 1 \
  --nonce 1
```

Sign validator slash tx:

```bash
go run ./cmd/wallet sign \
  --priv <hex-private-key> \
  --kind validator_slash \
  --validator-id v1 \
  --basis-points 500 \
  --fee 1 \
  --nonce 1
```

Sign validator unjail tx:

```bash
go run ./cmd/wallet sign \
  --priv <hex-private-key> \
  --kind validator_unjail \
  --validator-id v1 \
  --fee 1 \
  --nonce 1
```

Sign delegation tx:

```bash
go run ./cmd/wallet sign \
  --priv <hex-private-key> \
  --kind delegation_delegate \
  --validator-id v1 \
  --amount 25 \
  --fee 1 \
  --nonce 1
```

Sign product settlement tx:

```bash
go run ./cmd/wallet sign \
  --priv <hex-private-key> \
  --kind product_settle \
  --to order-123 \
  --amount 50 \
  --fee 1 \
  --nonce 1
```

Sign product attestation tx:

```bash
go run ./cmd/wallet sign \
  --priv <hex-private-key> \
  --kind product_attest \
  --to proof-hash \
  --validator-id v1 \
  --amount 12 \
  --basis-points 9000 \
  --fee 1 \
  --nonce 1
```

Then submit signed JSON to `POST /tx`.

## Disaster Recovery

Migrate state between backends:

```bash
go run ./cmd/node migrate-state \
  -from-backend snapshot -from ./data/state.json \
  -to-backend sqlite -to ./data/state.db
```

Restore latest backup snapshot:

```bash
./scripts/ops/restore_snapshot.sh ./data/backups ./data/state.json
```

Runbook: `docs/phase4-disaster-recovery.md`

## Testing

```bash
go test ./...
```

Includes deterministic 3-node consensus integration coverage in `internal/integration/multinode_consensus_test.go`.

Run fuzz targets explicitly:

```bash
go test -run=^$ -fuzz=Fuzz -fuzztime=10s ./...
```

Local 3-node p2p smoke test:

```bash
./scripts/testnet/smoke_local.sh
```

Docker 3-node p2p smoke test:

```bash
./scripts/testnet/smoke_docker.sh
```

Docker testnet compose file: `docker-compose.testnet.yml`

## Roadmap

See `ROADMAP.md` for phased progress toward a production-usable network.

Phase 2 protocol draft and signed network message primitives are in:

- `docs/phase2-network-protocol.md`
- `internal/p2p/messages.go`
- `internal/p2p/service.go`

Security threat model baseline:

- `docs/security-threat-model.md`

Product integration and proof/challenge schema:

- `docs/phase5-product-integration.md`
