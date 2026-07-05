# fastpos

`fastpos` is a simplified proof-of-stake blockchain node written in Go. It is built as a practical sandbox for consensus, validator behavior, transaction processing, persistence, peer messaging, and product-facing settlement flows.

The project is not presented as a production chain. Its value is in making blockchain mechanics concrete and inspectable: keys, signatures, mempool rules, validator voting, finality, slashing, state recovery, and application-level transaction types all live in one Go codebase.

## What it does

- Runs a configurable blockchain node over HTTP
- Supports signed account transfers with Ed25519
- Selects proposers using effective validator stake
- Finalizes blocks through validator voting
- Tracks validator lifecycle actions such as bond, unbond, slash, jail, and unjail
- Supports delegation and epoch-based validator-set updates
- Enforces mempool limits, minimum fees, replacement rules, pending caps, and transaction expiry
- Persists state through snapshot JSON or SQLite
- Exposes health, readiness, metrics, transaction, validator, and product APIs
- Sends signed peer-to-peer envelopes between nodes
- Supports static peer gossip and startup synchronization
- Includes product settlement, attestation, challenge, and reward-distribution transaction flows

## Why it is interesting

This repository goes beyond a toy transfer ledger. It explores how chain-level mechanics connect to real product requirements:

- idempotent settlement submission
- pending attestations
- challenge windows
- fraud-resolution flow
- oracle quorum thresholds
- product treasury and reward accounting
- finalized transaction queries for reconciliation

That makes it useful as a learning system for both consensus internals and application-facing blockchain design.

## Tech stack

- Go
- SQLite optional state backend
- YAML/JSON configuration
- Docker Compose testnet
- Go unit, integration, and fuzz tests

## Quick start

Run a single node with defaults:

```bash
go run ./cmd/node
```

Run with the example config:

```bash
go run ./cmd/node -config ./configs/node.example.yaml
```

Run the Docker testnet:

```bash
docker compose -f docker-compose.testnet.yml up
```

## Wallet helper

Generate a wallet:

```bash
go run ./cmd/wallet gen
```

Sign a transaction:

```bash
go run ./cmd/wallet sign -priv <private-key> -to <address> -amount 10 -nonce 1
```

## Tests

```bash
go test ./...
```

## Repository structure

```text
cmd/node/        Node runtime, config, backup, sync, and migration
cmd/wallet/      Wallet generation and transaction signing helper
configs/         Genesis and node/testnet configuration
docs/            Protocol, recovery, product, and threat-model notes
internal/chain/  Chain state, consensus, tx types, persistence, tests
internal/node/   HTTP server and API layer
internal/p2p/    P2P message and service layer
scripts/         Testnet and operations scripts
```

## Technical highlights

- Clear separation between chain logic, HTTP node API, and P2P service
- Config precedence through defaults, config file, and CLI flags
- Durable restart behavior through persistent state backends
- Multi-node local/Docker testnet configuration
- Tests around consensus, persistence, mempool, replay protection, validator lifecycle, and P2P messages
- Fuzz tests for consensus and signed envelope handling

## Skills demonstrated

- Go systems programming
- Consensus and validator-state modeling
- Cryptographic transaction signing
- API design for chain state and product workflows
- Persistence and recovery design
- Threat modeling and protocol documentation

## Status

This is a pre-production research and implementation project. It is built to be read, tested, challenged, and improved.
