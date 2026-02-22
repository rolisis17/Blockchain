# fastpos Threat Model (Initial)

Date: 2026-02-22

This document is the baseline internal threat model for the current `fastpos` codebase.

## Scope

In scope:

- Consensus state machine (`internal/chain`)
- P2P envelope/message handling (`internal/p2p`)
- HTTP API/admin endpoints (`internal/node`)
- State persistence and recovery (snapshot/sqlite/backups)

Out of scope:

- Host/container hardening
- Cloud/network perimeter controls
- Key management outside process memory

## Security Goals

1. Prevent invalid state transitions from finalizing.
2. Preserve chain availability with partial validator/peer failure.
3. Bound resource exhaustion from malformed or abusive traffic.
4. Recover node state safely after crash/data loss.

## Trust Assumptions

- At least `>=2/3` effective stake is honest for finality safety.
- Validator private keys are not compromised.
- Operators protect admin tokens and do not expose dev-signing endpoints publicly.

## Threats and Current Mitigations

## Consensus manipulation

- Threat: invalid blocks/transactions force divergent state.
- Mitigations:
  - deterministic tx validation and state-root checks before finalization
  - vote quorum validation and duplicate/outdated/conflict rejection
  - fork-choice handling for same-height proposals

## Equivocation / double-signing

- Threat: validator signs conflicting proposals/votes.
- Mitigations:
  - conflicting signed-message evidence capture
  - operator-triggered slash + jail workflow
  - jailing/unjail minimum-duration enforcement

## P2P abuse and message flooding

- Threat: inbound spam, replay, and repeated failing peers degrade liveness.
- Mitigations:
  - strict message schema and signature verification
  - per-peer inbound rate limiting
  - duplicate/outdated message detection
  - outbound peer backoff with health tracking

## Mempool DoS

- Threat: low-value tx flood blocks useful traffic.
- Mitigations:
  - min-fee admission
  - mempool size bounds and higher-fee replacement
  - per-account pending tx cap
  - block-age-based tx expiry

## State corruption and disaster recovery

- Threat: node crash/disk loss causes extended downtime or unsafe restore.
- Mitigations:
  - durable snapshot/sqlite backends
  - periodic JSON backup snapshots + retention
  - restore script and backend migration command
  - startup peer sync + snapshot fallback

## Remaining High-Risk Gaps

1. No independent external audit yet.
2. No cryptoeconomic challenge protocol for delegated work claims.
3. No HSM/remote-signer integration for validator keys.
4. No byzantine network simulation at larger scale (latency/partition/adversarial peers).
5. No formal verification of consensus invariants.

## External Review Checklist

1. Cryptography and signature handling review.
2. Consensus safety/liveness analysis under byzantine peers.
3. P2P parser/fuzzing depth and malformed input hardening.
4. Mempool and API abuse-case load testing.
5. Persistence/backup restore integrity and rollback testing.
6. Key-management and secrets-handling review.

Status: internal threat model completed; external security review pending.
