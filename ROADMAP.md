# fastpos Roadmap

This roadmap targets a functional, simplified PoS blockchain that can be used in real environments before integrating with your product.

## Principles

- Safety over speed: no shortcut that can break consensus integrity.
- Start centralized for operability, then remove trust assumptions phase by phase.
- Keep the protocol simple and auditable.

## Current baseline (done)

- Account model with signed transfers
- PoS proposer selection and validator voting with `>=2/3` finality
- Validator `workWeight` integration hook
- HTTP API for txs, accounts, blocks, validator controls
- Snapshot persistence and restart recovery
- Configurable genesis file

## Phase 1: Single-node hardening (1-2 weeks)

Goal: make one node safe and operationally predictable.

- Done: state snapshots persisted on every finalized block
- Done: configurable genesis + deterministic default genesis
- Done: safer API defaults (admin token, signing endpoints disabled by default)
- Done: structured config file (`config.yaml`) with CLI override precedence
- Done: Prometheus metrics + health/readiness endpoints
- Done: transaction mempool policies (limits, eviction, fee prioritization)
- Done: deterministic replay test from genesis + transaction log sequence

Exit criteria:

- Node restarts without state loss
- Ops can monitor block finality, mempool pressure, and validator activity
- Basic abuse on public endpoints is bounded

## Phase 2: Multi-node consensus network (3-6 weeks)

Goal: move from single-process simulation to real validator networking.

- Done (foundation): signed proposal/vote/finalize envelope primitives and protocol draft (`internal/p2p`, `docs/phase2-network-protocol.md`)
- P2P or RPC gossip for block proposals and votes
- Separate node identities and validator signing keys
- Real vote aggregation from remote validators
- Peer discovery and static peer bootstrap
- Fork-choice and duplicate/late vote handling
- Deterministic integration tests for 3-7 node local cluster

Exit criteria:

- 3+ independent validator processes finalize blocks together
- One validator crash does not halt finality (as long as quorum remains)

## Phase 3: Validator economics and lifecycle (2-4 weeks)

Goal: stable incentives and governance for real operators.

- On-chain staking transactions (bond/unbond)
- Delegation model (optional, if needed for your tokenomics)
- Slashing for equivocation/double-signing
- Jailing and recovery rules
- Epoch transitions and validator set updates

Exit criteria:

- Validators can join/leave through protocol rules
- Malicious behavior has explicit economic penalties

## Phase 4: Production reliability and security (4-8 weeks)

Goal: be robust under realistic failures and adversarial traffic.

- Persistent storage backend (Pebble/Badger/SQLite) beyond JSON snapshots
- Mempool DoS controls, rate limiting, and size bounds
- State sync for new nodes
- Snapshot/backup and disaster recovery procedures
- Threat model + external security review
- Fuzz tests for tx/block decoding and consensus state transitions

Exit criteria:

- New node can sync from existing network reliably
- Chain remains stable under high tx load and malformed input

## Phase 5: Product integration layer (2-5 weeks)

Goal: connect your validator product to chain economics.

- Define product proof schema (what work evidence is accepted)
- Oracle/attestation path to update validator `workWeight`
- Reward distribution policy tied to product signals
- Fraud/challenge flow for bad work reports
- Billing/settlement endpoints for product users

Exit criteria:

- Your product can pay validators and settle user payments through chain state
- Fraudulent work claims are detectable and penalizable

## Proposed immediate sprint (next)

1. Design Phase 2 network protocol (proposal/vote messages, peer auth, block propagation).
2. Implement peer transport and message validation for 4 local validator nodes.
3. Build local `docker-compose` testnet with deterministic integration tests.

## Suggested milestone timeline (single engineer, part-time)

- Milestone A (2 weeks): hardened single-node
- Milestone B (4-8 weeks): working multi-node PoS testnet
- Milestone C (8-12+ weeks): staking/slashing + operational reliability

With two experienced engineers full-time, timeline can be significantly shorter.
