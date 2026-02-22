package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type Address string

type Account struct {
	Balance uint64 `json:"balance"`
	Nonce   uint64 `json:"nonce"`
}

type Transaction struct {
	Kind        string  `json:"kind,omitempty"`
	From        Address `json:"from"`
	To          Address `json:"to"`
	Amount      uint64  `json:"amount"`
	Fee         uint64  `json:"fee"`
	Nonce       uint64  `json:"nonce"`
	Timestamp   int64   `json:"timestamp"`
	ValidatorID string  `json:"validatorId,omitempty"`
	BasisPoints uint64  `json:"basisPoints,omitempty"`
	PubKey      string  `json:"pubKey"`
	Signature   string  `json:"signature"`
}

const (
	TxKindTransfer                = "transfer"
	TxKindValidatorBond           = "validator_bond"
	TxKindValidatorUnbond         = "validator_unbond"
	TxKindValidatorSlash          = "validator_slash"
	TxKindValidatorJail           = "validator_jail"
	TxKindValidatorUnjail         = "validator_unjail"
	TxKindDelegate                = "delegation_delegate"
	TxKindUndelegate              = "delegation_undelegate"
	TxKindProductSettle           = "product_settle"
	TxKindProductAttest           = "product_attest"
	TxKindProductChallenge        = "product_challenge"
	TxKindProductResolveChallenge = "product_resolve_challenge"
)

func normalizeTxKind(kind string) string {
	switch kind {
	case "", TxKindTransfer:
		return TxKindTransfer
	case TxKindValidatorBond:
		return TxKindValidatorBond
	case TxKindValidatorUnbond:
		return TxKindValidatorUnbond
	case TxKindValidatorSlash:
		return TxKindValidatorSlash
	case TxKindValidatorJail:
		return TxKindValidatorJail
	case TxKindValidatorUnjail:
		return TxKindValidatorUnjail
	case TxKindDelegate:
		return TxKindDelegate
	case TxKindUndelegate:
		return TxKindUndelegate
	case TxKindProductSettle:
		return TxKindProductSettle
	case TxKindProductAttest:
		return TxKindProductAttest
	case TxKindProductChallenge:
		return TxKindProductChallenge
	case TxKindProductResolveChallenge:
		return TxKindProductResolveChallenge
	default:
		return kind
	}
}

func (tx Transaction) txKind() string {
	return normalizeTxKind(tx.Kind)
}

func (tx Transaction) signingBytes() []byte {
	payload := fmt.Sprintf(
		"%s|%s|%d|%d|%d|%d|%s|%s|%d",
		tx.From,
		tx.To,
		tx.Amount,
		tx.Fee,
		tx.Nonce,
		tx.Timestamp,
		tx.txKind(),
		tx.ValidatorID,
		tx.BasisPoints,
	)
	return []byte(payload)
}

func (tx Transaction) ID() string {
	payload := append(tx.signingBytes(), []byte("|"+tx.Signature)...)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

type Vote struct {
	ValidatorID    string `json:"validatorId"`
	EffectiveStake uint64 `json:"effectiveStake"`
	Approved       bool   `json:"approved"`
}

type Validator struct {
	ID                string  `json:"id"`
	Address           Address `json:"address"`
	PubKey            string  `json:"pubKey"`
	Stake             uint64  `json:"stake"`
	WorkWeight        uint64  `json:"workWeight"`
	Active            bool    `json:"active"`
	Jailed            bool    `json:"jailed"`
	JailedUntilHeight uint64  `json:"jailedUntilHeight,omitempty"`
}

type Delegation struct {
	Delegator   Address `json:"delegator"`
	ValidatorID string  `json:"validatorId"`
	Amount      uint64  `json:"amount"`
}

type EpochValidatorStake struct {
	ValidatorID    string `json:"validatorId"`
	EffectiveStake uint64 `json:"effectiveStake"`
}

type EpochInfo struct {
	Current              uint64                `json:"current"`
	Length               uint64                `json:"length"`
	StartHeight          uint64                `json:"startHeight"`
	NextTransitionHeight uint64                `json:"nextTransitionHeight"`
	ValidatorSet         []EpochValidatorStake `json:"validatorSet"`
}

type ProductProof struct {
	ID          string  `json:"id"`
	ProofRef    string  `json:"proofRef"`
	Reporter    Address `json:"reporter"`
	ValidatorID string  `json:"validatorId"`
	Units       uint64  `json:"units"`
	QualityBps  uint64  `json:"qualityBps"`
	Score       uint64  `json:"score"`
	Epoch       uint64  `json:"epoch"`
	Timestamp   int64   `json:"timestamp"`
	Challenged  bool    `json:"challenged"`
	Invalidated bool    `json:"invalidated"`
	ChallengeID string  `json:"challengeId,omitempty"`
}

type ProductChallenge struct {
	ID               string  `json:"id"`
	ProofID          string  `json:"proofId"`
	Challenger       Address `json:"challenger"`
	Bond             uint64  `json:"bond"`
	Open             bool    `json:"open"`
	Successful       bool    `json:"successful"`
	Resolver         Address `json:"resolver,omitempty"`
	SlashBasisPoints uint64  `json:"slashBasisPoints,omitempty"`
	BonusPayout      uint64  `json:"bonusPayout,omitempty"`
	CreatedMs        int64   `json:"createdMs"`
	ResolvedMs       int64   `json:"resolvedMs,omitempty"`
}

type ProductSettlement struct {
	ID          string  `json:"id"`
	Payer       Address `json:"payer"`
	Reference   string  `json:"reference"`
	ValidatorID string  `json:"validatorId,omitempty"`
	Amount      uint64  `json:"amount"`
	Epoch       uint64  `json:"epoch"`
	Timestamp   int64   `json:"timestamp"`
}

type ProductReward struct {
	ValidatorID string `json:"validatorId"`
	Amount      uint64 `json:"amount"`
}

type ProductStatus struct {
	TreasuryBalance    uint64          `json:"treasuryBalance"`
	RewardBasisPoints  uint64          `json:"rewardBasisPoints"`
	ChallengeMinBond   uint64          `json:"challengeMinBond"`
	CurrentEpoch       uint64          `json:"currentEpoch"`
	LastRewardEpoch    uint64          `json:"lastRewardEpoch"`
	LastRewards        []ProductReward `json:"lastRewards"`
	PendingSignalScore []ProductReward `json:"pendingSignalScore"`
	ProofCount         int             `json:"proofCount"`
	OpenChallenges     int             `json:"openChallenges"`
	SettlementCount    int             `json:"settlementCount"`
}

type Block struct {
	Height       uint64        `json:"height"`
	Round        uint64        `json:"round"`
	PrevHash     string        `json:"prevHash"`
	Timestamp    int64         `json:"timestamp"`
	Proposer     string        `json:"proposer"`
	Transactions []Transaction `json:"transactions"`
	StateRoot    string        `json:"stateRoot"`
	Hash         string        `json:"hash"`
	Votes        []Vote        `json:"votes"`
	Finalized    bool          `json:"finalized"`
}

type Status struct {
	Height          uint64 `json:"height"`
	HeadHash        string `json:"headHash"`
	MempoolSize     int    `json:"mempoolSize"`
	LastFinalizedMs int64  `json:"lastFinalizedMs"`
	Epoch           uint64 `json:"epoch"`
}

type Metrics struct {
	Height                 uint64 `json:"height"`
	Epoch                  uint64 `json:"epoch"`
	MempoolSize            int    `json:"mempoolSize"`
	MempoolPeak            int    `json:"mempoolPeak"`
	SubmittedTxTotal       uint64 `json:"submittedTxTotal"`
	RejectedTxTotal        uint64 `json:"rejectedTxTotal"`
	EvictedTxTotal         uint64 `json:"evictedTxTotal"`
	ExpiredTxTotal         uint64 `json:"expiredTxTotal"`
	IncludedTxTotal        uint64 `json:"includedTxTotal"`
	FinalizedBlocksTotal   uint64 `json:"finalizedBlocksTotal"`
	FailedProduceTotal     uint64 `json:"failedProduceTotal"`
	TotalFeesCollected     uint64 `json:"totalFeesCollected"`
	ProductTreasuryBalance uint64 `json:"productTreasuryBalance"`
	LastFinalizedMs        int64  `json:"lastFinalizedMs"`
	ActiveValidatorsCount  int    `json:"activeValidatorsCount"`
}
