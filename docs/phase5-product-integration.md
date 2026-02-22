# Phase 5 Product Integration (Initial)

This document describes the initial product-economics integration added to `fastpos`.

## On-chain Product Transaction Kinds

1. `product_settle`
- Purpose: user payment into product treasury.
- Required fields: `from`, `to` (product reference), `amount`, `fee`, `nonce`, `timestamp`.
- Effect: `amount` moves from payer balance to product treasury.

2. `product_attest`
- Purpose: oracle/validator attestation of completed product work.
- Required fields: `from` (oracle signer), `to` (proof reference), `validatorId`, `amount` (work units), `basisPoints` (quality), `fee`, `nonce`, `timestamp`.
- Effect:
  - stores a `ProductProof`
  - updates product signal score for the attested validator
  - updates attested validator `workWeight` via smoothing rule

3. `product_challenge`
- Purpose: challenge an attested proof with an economic bond.
- Required fields: `from`, `to` (proof id), `amount` (bond), `fee`, `nonce`, `timestamp`.
- Effect:
  - stores an open `ProductChallenge`
  - marks proof as challenged
  - moves challenge bond into treasury escrow

4. `product_resolve_challenge`
- Purpose: oracle resolution for an open challenge.
- Required fields: `from`, `to` (challenge id), `fee`, `nonce`, `timestamp`.
- Optional fields:
  - `basisPoints`:
    - `0` means challenge rejected
    - `>0` means challenge accepted and validator slash basis points
  - `amount`: optional challenger bonus payout when accepted
- Effect on accepted challenge:
  - proof is invalidated
  - validator is slashed and jailed
  - challenger receives bond refund + bonus from treasury

## Product Proof Schema

Stored per attestation as `ProductProof`:

- `id` (tx id)
- `proofRef` (external proof hash/reference)
- `reporter` (oracle address)
- `validatorId`
- `units`
- `qualityBps`
- `score`
- `epoch`
- `timestamp`
- `challenged`
- `invalidated`
- `challengeId`

## Product Challenge Schema

Stored per challenge as `ProductChallenge`:

- `id`
- `proofId`
- `challenger`
- `bond`
- `open`
- `successful`
- `resolver`
- `slashBasisPoints`
- `bonusPayout`
- `createdMs`
- `resolvedMs`

## Product Settlement Schema

Stored per settlement as `ProductSettlement`:

- `id`
- `payer`
- `reference`
- `validatorId` (optional routing hint)
- `amount`
- `epoch`
- `timestamp`

## Epoch-Coupled Reward Distribution

- Product attestation scores accumulate in `productSignalScore`.
- At epoch boundary (`height % epochLengthBlocks == 0`):
  - payout pool = `treasury * productRewardBps / 10000`
  - payouts are distributed proportionally to validator signal score
  - treasury decreases by distributed amount
  - signal score resets for next epoch

## API Surface

Read endpoints:

- `GET /product/status`
- `GET /product/proofs`
- `GET /product/challenges`
- `GET /product/settlements`
- `GET /product/billing/quote?units=...`

Submit endpoints (pre-signed tx JSON):

- `POST /product/settlements`
- `POST /product/attestations`
- `POST /product/challenges`
- `POST /product/challenges/resolve`

## Current Trust Model (Initial)

- Oracle authority is represented by active non-jailed validator signers.
- This keeps behavior deterministic and decentralized under existing validator assumptions.
- A future upgrade can add dedicated oracle sets or threshold attestations.
