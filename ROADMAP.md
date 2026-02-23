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
- Done (initial): `POST /p2p/message` with validator registry, signature checks, strict payload validation, and duplicate/outdated detection
- Done (initial): static peer config + proposal/vote/finalize gossip broadcast between nodes
- Done: runtime peer management API (`GET/POST/DELETE /p2p/peers`)
- Done (initial): local 3-node smoke harness + Docker Compose testnet (`scripts/testnet`, `docker-compose.testnet.yml`)
- Done: real vote aggregation from remote validators into proposer finalization flow
- Done: timeout-driven round/view-change fallback when scheduled proposer is offline
- Done (initial): peer discovery/bootstrap from known peers via periodic `/p2p/peers` crawl
- Done: fork-choice and duplicate/late vote handling at same height
- Done: outbound peer health/backoff + inbound per-peer rate limiting defaults
- Done: deterministic 3-node integration test in CI (`internal/integration/multinode_consensus_test.go`)
- Done: deterministic 5-node partial-failure integration test with one offline validator (`internal/integration/multinode_consensus_test.go`)

Exit criteria:

- 3+ independent validator processes finalize blocks together
- One validator crash does not halt finality (as long as quorum remains)

## Phase 3: Validator economics and lifecycle (2-4 weeks)

Goal: stable incentives and governance for real operators.

- Done (initial): validator lifecycle primitives for bond/unbond/slash/jail are implemented in chain state + admin API
- Done (initial): on-chain validator lifecycle transactions (`validator_bond`, `validator_unbond`, `validator_slash`, `validator_jail`) execute in consensus state transitions
- Done (initial): on-chain delegation model (`delegation_delegate`/`delegation_undelegate`) included in effective stake and exposed via API
- Done (initial): equivocation/double-sign evidence capture with operator-triggered slash+jail workflow
- Done (initial): jailing recovery rule (`validator_unjail`) with minimum jail duration in blocks
- Done (initial): epoch transitions and validator-set snapshot updates (`epochLengthBlocks`) for consensus/routing stability

Exit criteria:

- Validators can join/leave through protocol rules
- Malicious behavior has explicit economic penalties

## Phase 4: Production reliability and security (4-8 weeks)

Goal: be robust under realistic failures and adversarial traffic.

- Done (initial): persistent SQLite state backend beyond JSON snapshots (configurable via `stateBackend`)
- Done (initial): mempool DoS controls and size bounds (per-account pending caps + tx age expiry)
- Done (initial): startup state sync for new/recovering nodes via peer status + block catch-up with snapshot fallback
- Done (initial): snapshot backup cadence + retention with restore tooling and state-backend migration command/runbook
- Done (initial): internal threat model baseline with external review checklist (`docs/security-threat-model.md`)
- Done (initial): fuzz tests for tx/block decoding and consensus state transitions

Exit criteria:

- New node can sync from existing network reliably
- Chain remains stable under high tx load and malformed input

## Phase 5: Product integration layer (2-5 weeks)

Goal: connect your validator product to chain economics.

- Done (initial): product proof schema with on-chain `ProductProof` records and references
- Done (initial): oracle/attestation path via `product_attest` transactions to update validator `workWeight`
- Done (initial): treasury-backed reward distribution policy tied to product signal score at epoch transition
- Done (initial): fraud/challenge flow via `product_challenge` and `product_resolve_challenge` transactions (slash+jail on successful challenge)
- Done (initial): billing/settlement endpoints and transaction path for product users (`product_settle`, quote + listing APIs)
- Done (initial): stake-weighted oracle quorum for proof attestation and challenge resolution voting
- Done (initial): challenge resolution delay window and pending attestation state tracking
- Done (initial): product read-side filters for precise proof/challenge/settlement lookups
- Done (initial): transaction indexing for fast finalized tx status lookup
- Done (initial): read API pagination controls for product lists
- Done (initial): idempotent product settlements keyed by payer/reference
- Done (initial): pending transaction query endpoint for operators and integrators
- Done (initial): direct settlement lookup by payer/reference for idempotent client flows
- Done (initial): optional pagination metadata envelopes (`withMeta=true`) for list APIs
- Done (initial): idempotent transaction submission retries (`POST /tx?idempotent=true`)
- Done (initial): idempotent product settlement submit retries (`POST /product/settlements?idempotent=true`)
- Done (initial): idempotent product attestation/challenge/resolve submit retries
- Done (initial): advanced product/pending-tx query filters (epoch, score/amount ranges, status, time windows)
- Done (initial): settlement lookup can include pending status for payer/reference reconciliation
- Done (initial): finalized transaction list endpoint with filter + pagination support (`GET /tx/finalized`)
- Done (initial): settlement stats endpoint for reconciliation totals (`GET /product/settlements/stats`)
- Done (initial): challenge stats endpoint for fraud/review monitoring (`GET /product/challenges/stats`)
- Done (initial): pending attestation stats endpoint for quorum-progress monitoring (`GET /product/attestations/stats`)

Exit criteria:

- Your product can pay validators and settle user payments through chain state
- Fraudulent work claims are detectable and penalizable

## Proposed immediate sprint (next)

1. Done: build remote vote aggregation into block finalization flow (replace local simulated votes).
2. Done: add peer-authenticated proposal relay + duplicate/late/conflict handling in consensus state machine.
3. Done (initial): add deterministic multi-node integration tests in CI (3 nodes), with Docker smoke tests.
4. Done: add runtime peer list management (`/p2p/peers`) for zero-downtime topology updates.
5. Done: add proposer-timeout view-change fallback and deterministic offline-proposer integration coverage.

## Active build queue (recommended order)

1. Done: consensus liveness under proposer failure
   Implemented proposer timeout + round/view-change so finality continues when scheduled proposer is offline.
2. Done: fork handling at same height
   Added deterministic fork-choice + vote tracking for competing proposals at equal height, including tests.
3. Done: safer networking defaults
   Added outbound peer health/backoff and inbound per-peer rate limiting to avoid repeated hot-loop failures.
4. Done: production state backend
   Added configurable SQLite durable state backend (`stateBackend=sqlite`) with startup load + finalize/shutdown persistence.
5. Done: sync for new/recovering nodes
   Added startup peer sync with block catch-up plus `/sync/snapshot` fallback and continuity checks through `FinalizeExternalBlock`.
6. Done (initial): validator lifecycle primitives
   Added chain-level bond/unbond, slashing, jailing, and admin endpoints for operational control.
7. Done (initial): on-chain validator lifecycle transaction kinds
   Added consensus-applied `validator_bond/unbond/slash/jail` transactions, dev-signing support, and deterministic tests.
8. Done (initial): jailing recovery rules
   Added `validator_unjail` transaction handling with deterministic minimum-jail-block enforcement.
9. Done (initial): equivocation evidence + penalty workflow
   Added p2p conflicting-message evidence capture plus admin-triggered slash/jail application (`/p2p/evidence`).
10. Done (initial): mempool DoS controls and bounded retention
   Added per-account pending transaction caps and block-age-based mempool expiry with metrics and config controls.
11. Done (initial): fuzz decoding/state-transition safety checks
   Added fuzz targets for p2p envelope decoding/meta extraction and randomized consensus state transitions.
12. Done (initial): peer discovery/bootstrap
   Added periodic peer discovery from known peers using `/p2p/peers` to expand static peer lists automatically.
13. Done (initial): on-chain delegation model
   Added `delegation_delegate`/`delegation_undelegate` transaction kinds, delegation state persistence, API visibility, and effective-stake integration.
14. Done (initial): backup restore + backend migration workflow
   Added backup restore script and `migrate-state` command for snapshot/sqlite conversion with disaster recovery runbook.
15. Done (initial): internal threat model baseline
   Added scoped threat model and external security review checklist (`docs/security-threat-model.md`).
16. Done (initial): epoch transitions and validator-set updates
   Added epoch model (`epochLengthBlocks`) and epoch-boundary validator set snapshot updates.
17. Done (initial): product proof schema
   Added on-chain `ProductProof` records with challenge linkage and proof references.
18. Done (initial): oracle/attestation work-weight updates
   Added `product_attest` transaction flow with oracle authorization and work-weight smoothing updates.
19. Done (initial): product-signal reward distribution
   Added epoch-boundary reward payouts from treasury proportional to attested signal score.
20. Done (initial): fraud/challenge flow
   Added challenge + resolve transactions with invalidation, slash+jail, and challenger payout behavior.
21. Done (initial): product billing and settlement APIs
   Added settlement submission/listing and billing quote endpoints for product users.
22. Done (initial): quorum-based oracle voting
   Added stake-weighted quorum thresholds (`productOracleQuorumBps`) for product attestation finalization and challenge resolution.
23. Done (initial): challenge timing guardrails
   Added `productChallengeResolveDelayBlocks`, challenge height metadata, and pending attestation visibility (`/product/attestations/pending`).
24. Done (initial): transaction lookup endpoint
   Added `GET /tx?id=...` to query pending/finalized transaction status and finalized block location metadata.
25. Done (initial): product query filters for integration reads
   Added targeted filters across product reads (`id`, `proofId`, `proofRef`, `reference`, `payer`, `challenger`, `openOnly`) to avoid full-list scans.
26. Done (initial): finalized tx index
   Added in-memory finalized transaction indexing so `GET /tx?id=...` lookups avoid full-chain scans and survive snapshot/sqlite reload.
27. Done (initial): product list pagination
   Added `offset`/`limit` pagination controls on product read endpoints (`proofs`, `pending attestations`, `challenges`, `settlements`).
28. Done (initial): settlement idempotency guard
   Added protocol-level duplicate settlement rejection for same `payer + reference` to prevent accidental double-charging.
29. Done (initial): pending tx query API
   Added `GET /tx/pending` with filters (`from`, `to`, `kind`, `validatorId`) and `offset`/`limit` pagination.
30. Done (initial): settlement lookup endpoint
   Added `GET /product/settlements/lookup?payer=...&reference=...` for direct retrieval of previously-settled references.
31. Done (initial): list metadata envelopes
   Added `withMeta=true` support for paginated read endpoints to return `items`, `total`, `offset`, `limit`, `count`, and `hasMore`.
32. Done (initial): idempotent tx submit mode
   Added `POST /tx?idempotent=true` duplicate-retry handling that returns existing tx state (`pending`/`finalized`) instead of failing.
33. Done (initial): idempotent product settlement submit mode
   Added `POST /product/settlements?idempotent=true` duplicate-retry handling that returns pending tx metadata or finalized settlement record.
34. Done (initial): idempotent product attest/challenge/resolve submit modes
   Added `?idempotent=true` duplicate-retry handling on `POST /product/attestations`, `POST /product/challenges`, and `POST /product/challenges/resolve`.
35. Done (initial): advanced read filters
   Added richer query filters for product and pending-tx endpoints (`epoch`, score/amount bounds, `successful`, time windows, fee bounds) with strict query validation.
36. Done (initial): pending-aware settlement lookup state
   Added `includePending=true` support on `GET /product/settlements/lookup` to return pending `txId` state before final settlement materialization.
37. Done (initial): finalized transaction query endpoint
   Added `GET /tx/finalized` with rich filters (`from`, `to`, `kind`, `validatorId`, fee and height bounds) and pagination metadata support.
38. Done (initial): settlement reconciliation stats endpoint
   Added `GET /product/settlements/stats` for aggregate `count`/`totalAmount` plus grouped totals by validator and epoch, with shared settlement filters.
39. Done (initial): challenge monitoring stats endpoint
   Added `GET /product/challenges/stats` for aggregate challenge counts/bond totals plus grouped challenger/resolver stats with existing challenge filters.
40. Done (initial): pending attestation monitoring stats endpoint
   Added `GET /product/attestations/stats` for aggregate pending-attestation stake/progress metrics with grouped validator breakdown and existing pending-attestation filters.

## Suggested milestone timeline (single engineer, part-time)

- Milestone A (2 weeks): hardened single-node
- Milestone B (4-8 weeks): working multi-node PoS testnet
- Milestone C (8-12+ weeks): staking/slashing + operational reliability

With two experienced engineers full-time, timeline can be significantly shorter.
