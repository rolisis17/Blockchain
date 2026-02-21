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
  "height": 12,
  "prevHash": "...",
  "proposerId": "v1",
  "blockHash": "...",
  "stateRoot": "...",
  "timestamp": 1700000002000
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
  "height": 12,
  "blockHash": "...",
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
- responses: `200` accepted, `400` invalid, `409` duplicate/outdated

After correctness, upgrade to persistent streams/gossip.

## Sequence (single height)

1. Proposer sends `block_proposal` to all peers.
2. Peers validate proposal and respond with signed `block_vote`.
3. Proposer/aggregator computes quorum.
4. Aggregator broadcasts `block_finalize`.
5. Peers commit block when finalize message passes checks.

## Current status

- Signed message envelope primitives implemented in `internal/p2p/messages.go`.
- Message signing/verifying tests implemented in `internal/p2p/messages_test.go`.
- Network transport and consensus wiring are next.
