# Phase 2 Network Protocol (Draft)

This document defines the first network protocol slice for multi-node fastpos consensus.

## Goals

- Propagate block proposals and votes between independent validator processes.
- Authenticate every consensus message with validator keys.
- Keep wire format deterministic and easy to validate.

## Message Types

- `block_proposal`
- `block_vote`
- `block_finalize`

All network messages use an envelope:

```json
{
  "type": "block_proposal",
  "senderId": "v1",
  "payload": { ... },
  "signature": "<hex-ed25519-signature>"
}
```

Signature bytes are:

```text
<type>|<senderId>|<payload-json>
```

## Payloads

### block_proposal

```json
{
  "block": {
    "height": 12,
    "prevHash": "...",
    "timestamp": 1700000002000,
    "proposer": "v1",
    "transactions": [],
    "stateRoot": "...",
    "hash": "...",
    "votes": [],
    "finalized": false
  }
}
```

### block_vote

```json
{
  "height": 12,
  "blockHash": "...",
  "voterId": "v2",
  "approve": true,
  "timestamp": 1700000002100
}
```

### block_finalize

```json
{
  "block": {
    "height": 12,
    "prevHash": "...",
    "timestamp": 1700000002000,
    "proposer": "v1",
    "transactions": [],
    "stateRoot": "...",
    "hash": "...",
    "votes": [{ "validatorId": "v1", "effectiveStake": 400, "approved": true }],
    "finalized": true
  },
  "yesStake": 700,
  "totalStake": 1000,
  "timestamp": 1700000002200
}
```

## Validation Rules

On receive:

1. Validate envelope fields are present.
2. Verify sender is a known validator.
3. Verify ed25519 signature for `<type>|<senderId>|<payload-json>`.
4. Decode payload according to `type`.
5. Run type-specific checks (height continuity, hash consistency, duplicate vote rules).

Reject and log invalid messages.

## Transport (next implementation step)

Initial transport: HTTP RPC between validators.

- `POST /p2p/message`
- body: envelope JSON
- responses: `202` accepted, `400` invalid, `401` unauthorized/invalid signature, `409` duplicate/outdated/conflict, `429` rate-limited
- `GET /sync/snapshot` for startup state bootstrap/catch-up fallback

After correctness, upgrade to persistent streams/gossip.

## Sequence (single height)

1. Proposer sends `block_proposal` to all peers.
2. Peers validate proposal and respond with signed `block_vote`.
3. Proposer/aggregator computes quorum.
4. Aggregator broadcasts `block_finalize`.
5. Peers commit block when finalize message passes checks.
6. If proposer is offline, nodes increment round after timeout ticks and use round-specific proposer selection.

## Current status

- Signed message envelope primitives implemented in `internal/p2p/messages.go`.
- Message signing/verifying tests implemented in `internal/p2p/messages_test.go`.
- Initial message endpoint and validation service implemented in `internal/p2p/service.go` and `internal/node/server.go` (`POST /p2p/message`).
- Static peer gossip for proposal/vote/finalize is active via configured peer lists.
- Remote vote aggregation and proposer-driven finalization are implemented in `internal/p2p/service.go`.
- Timeout-driven round/view-change fallback is implemented when the scheduled proposer is offline.
- Deterministic fork-choice for competing same-height proposals is implemented (higher round wins, deterministic tie-breakers).
- Outbound peer broadcast uses health-based exponential backoff and inbound `POST /p2p/message` enforces per-peer rate limits.
- Conflicting signed proposal/vote messages now emit equivocation evidence, queryable via `GET /p2p/evidence`.
- Startup state sync for recovering nodes is implemented using peer status + block catch-up with `/sync/snapshot` fallback.
- Initial peer discovery/bootstrap is implemented by periodically crawling known peers' `GET /p2p/peers` responses.
- Deterministic 3-node multi-process integration tests are in `internal/integration/multinode_consensus_test.go`.
