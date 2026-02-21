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
	From      Address `json:"from"`
	To        Address `json:"to"`
	Amount    uint64  `json:"amount"`
	Fee       uint64  `json:"fee"`
	Nonce     uint64  `json:"nonce"`
	Timestamp int64   `json:"timestamp"`
	PubKey    string  `json:"pubKey"`
	Signature string  `json:"signature"`
}

func (tx Transaction) signingBytes() []byte {
	payload := fmt.Sprintf("%s|%s|%d|%d|%d|%d", tx.From, tx.To, tx.Amount, tx.Fee, tx.Nonce, tx.Timestamp)
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
	ID         string  `json:"id"`
	Address    Address `json:"address"`
	PubKey     string  `json:"pubKey"`
	Stake      uint64  `json:"stake"`
	WorkWeight uint64  `json:"workWeight"`
	Active     bool    `json:"active"`
}

type Block struct {
	Height       uint64        `json:"height"`
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
}

type Metrics struct {
	Height                uint64 `json:"height"`
	MempoolSize           int    `json:"mempoolSize"`
	MempoolPeak           int    `json:"mempoolPeak"`
	SubmittedTxTotal      uint64 `json:"submittedTxTotal"`
	RejectedTxTotal       uint64 `json:"rejectedTxTotal"`
	EvictedTxTotal        uint64 `json:"evictedTxTotal"`
	IncludedTxTotal       uint64 `json:"includedTxTotal"`
	FinalizedBlocksTotal  uint64 `json:"finalizedBlocksTotal"`
	FailedProduceTotal    uint64 `json:"failedProduceTotal"`
	TotalFeesCollected    uint64 `json:"totalFeesCollected"`
	LastFinalizedMs       int64  `json:"lastFinalizedMs"`
	ActiveValidatorsCount int    `json:"activeValidatorsCount"`
}
