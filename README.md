# fastpos

Simplified proof-of-stake blockchain node written in Go. The project is designed as a practical sandbox for validator logic, transaction handling, peer messaging, persistence, and product-integration flows before real production hardening.

## Highlights

- Signed account transfers with Ed25519
- Stake-weighted proposer selection and validator voting
- Mempool controls for fee replacement, size limits, pending caps, and expiry
- Snapshot or SQLite-backed persistent state
- Configurable genesis and node runtime
- HTTP health, readiness, metrics, transaction, validator, and product APIs
- Signed peer-to-peer envelopes and static peer gossip
- Multi-node testnet configs for local and Docker runs
- Validator lifecycle, delegation, slashing, jailing, and epoch transitions
- Product settlement, attestation, challenge, fraud-resolution, and treasury reward flows
- Unit, integration, and fuzz tests around consensus, persistence, p2p, and transaction logic

## Quick start

Run a single node with defaults:

```bash
go run ./cmd/node
```

Run with an example config:

```bash
go run ./cmd/node -config ./configs/node.example.yaml
```

Run the Docker testnet:

```bash
docker compose -f docker-compose.testnet.yml up
```

## Useful commands

```bash
go test ./...
go run ./cmd/wallet
go run ./cmd/node -config ./configs/testnet/local/node1.yaml
```

## Repository structure

```text
cmd/node/        Node runtime, config, backup, sync, migration
cmd/wallet/      Wallet helper
configs/         Genesis and node/testnet configuration
docs/            Protocol, recovery, product, and threat-model notes
internal/chain/  Chain state, consensus, tx types, persistence
internal/node/   HTTP server
internal/p2p/    P2P message and service layer
scripts/         Testnet and operations scripts
```

## Status

This is a pre-production research and implementation project. It is intentionally explicit and test-heavy so the consensus and product-flow behavior can be inspected, challenged, and improved.
