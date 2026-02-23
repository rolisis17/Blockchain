# Phase 5 Product Integration (Initial)

This document describes the initial product-economics integration added to `fastpos`.

## On-chain Product Transaction Kinds

1. `product_settle`
- Purpose: user payment into product treasury.
- Required fields: `from`, `to` (product reference), `amount`, `fee`, `nonce`, `timestamp`.
- Rules:
  - `to` (reference) must be unique per payer (`from`) to avoid duplicate charges.
- Effect: `amount` moves from payer balance to product treasury.

2. `product_attest`
- Purpose: oracle/validator attestation of completed product work.
- Required fields: `from` (oracle signer), `to` (proof reference), `validatorId`, `amount` (work units), `basisPoints` (quality), `fee`, `nonce`, `timestamp`.
- Effect:
  - records a stake-weighted attestation vote under a deterministic proof id
  - finalizes `ProductProof` only when oracle quorum is reached (`productOracleQuorumBps`)
  - on finalization: updates product signal score and attested validator `workWeight`

3. `product_challenge`
- Purpose: challenge an attested proof with an economic bond.
- Required fields: `from`, `to` (proof id), `amount` (bond), `fee`, `nonce`, `timestamp`.
- Effect:
  - stores an open `ProductChallenge`
  - marks proof as challenged
  - moves challenge bond into treasury escrow

4. `product_resolve_challenge`
- Purpose: oracle vote for challenge resolution (stake-weighted quorum).
- Required fields: `from`, `to` (challenge id), `fee`, `nonce`, `timestamp`.
- Optional fields:
  - `basisPoints`:
    - `0` means challenge rejected
    - `>0` means challenge accepted and validator slash basis points
  - `amount`: optional challenger bonus payout when accepted (`basisPoints > 0`)
- Rules:
  - challenge cannot be resolved before `resolveAfterHeight` (`productChallengeResolveDelayBlocks`)
  - each oracle can vote once per challenge
  - accepted votes must agree on slash/bonus parameters
- Effect on accepted challenge:
  - proof is invalidated
  - validator is slashed and jailed
  - challenger receives bond refund + bonus from treasury

## Product Proof Schema

Stored per attestation as `ProductProof`:

- `id` (deterministic proof id)
- `proofRef` (external proof hash/reference)
- `reporter` (oracle address)
- `validatorId`
- `units`
- `qualityBps`
- `score`
- `epoch`
- `timestamp`
- `attestations` (oracle vote count used to finalize)
- `attestedStake` (oracle stake accumulated at finalization)
- `challenged`
- `invalidated`
- `challengeId`

## Pending Attestation Schema

Stored for in-progress proofs as `ProductPendingAttestation`:

- `id`
- `proofRef`
- `validatorId`
- `units`
- `qualityBps`
- `score`
- `epoch`
- `requiredStake`
- `collectedStake`
- `createdHeight`
- `expiresHeight`
- `createdMs`
- `lastUpdatedMs`
- `votes[]` (`oracle`, `oracleValidatorId`, `stake`, `timestamp`)

## Product Challenge Schema

Stored per challenge as `ProductChallenge`:

- `id`
- `proofId`
- `challenger`
- `bond`
- `createdHeight`
- `resolveAfterHeight`
- `maxOpenHeight`
- `requiredStake`
- `acceptedStake`
- `rejectedStake`
- `votes[]` (`oracle`, `oracleValidatorId`, `approve`, `stake`, `timestamp`, `slashBasisPoints`, `bonusPayout`)
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
- `GET /product/proofs` (`?id=...&proofRef=...&validatorId=...&reporter=...&epoch=...&minScore=...&maxScore=...&includeInvalid=true|false&offset=...&limit=...&withMeta=true|false`)
- `GET /product/attestations/stats` (`?id=...&proofId=...&proofRef=...&validatorId=...&epoch=...&minCollectedStake=...&sinceMs=...&untilMs=...`; aggregate pending-attestation count/stake/progress by validator)
- `GET /product/attestations/pending` (`?id=...&proofId=...&proofRef=...&validatorId=...&epoch=...&minCollectedStake=...&sinceMs=...&untilMs=...&offset=...&limit=...&withMeta=true|false`)
- `GET /product/challenges` (`?id=...&proofId=...&challenger=...&resolver=...&successful=true|false&openOnly=true|false&minBond=...&sinceMs=...&untilMs=...&offset=...&limit=...&withMeta=true|false`)
- `GET /product/challenges/stats` (`?id=...&proofId=...&challenger=...&resolver=...&successful=true|false&openOnly=true|false&minBond=...&sinceMs=...&untilMs=...`; aggregate totals + grouped challenger/resolver bond stats)
- `GET /product/settlements` (`?id=...&reference=...&payer=...&validatorId=...&epoch=...&minAmount=...&maxAmount=...&sinceMs=...&untilMs=...&offset=...&limit=...&withMeta=true|false`)
- `GET /product/settlements/lookup` (`?payer=...&reference=...&includePending=true|false`; returns `state=finalized` + `settlement` or `state=pending` + `txId` when enabled)
- `GET /product/settlements/stats` (`?id=...&reference=...&payer=...&validatorId=...&epoch=...&minAmount=...&maxAmount=...&sinceMs=...&untilMs=...`; aggregate totals grouped by validator/epoch)
- `GET /product/billing/quote?units=...`

Submit endpoints (pre-signed tx JSON):

- `POST /product/settlements` (`?idempotent=true` optional for duplicate payer/reference retries)
- `POST /product/attestations` (`?idempotent=true` optional for duplicate oracle vote retries)
- `POST /product/challenges` (`?idempotent=true` optional for duplicate challenge retries)
- `POST /product/challenges/resolve` (`?idempotent=true` optional for duplicate resolve-vote retries)

## Current Trust Model (Initial)

- Oracle authority is represented by active non-jailed validator signers.
- Oracle actions are now gated by stake-weighted quorum for both proof finalization and challenge outcomes.
- This keeps behavior deterministic and decentralized under existing validator assumptions.
