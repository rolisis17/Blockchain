package chain

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	_ "modernc.org/sqlite"
)

const (
	snapshotVersion = 1
	sqliteStateKey  = "latest"
)

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS chain_state (
  key TEXT PRIMARY KEY,
  version INTEGER NOT NULL,
  payload BLOB NOT NULL,
  updated_ms INTEGER NOT NULL
);`

type Snapshot struct {
	Version                            int                         `json:"version"`
	BlockIntervalMs                    int64                       `json:"blockIntervalMs"`
	BaseReward                         uint64                      `json:"baseReward"`
	MinJailBlocks                      uint64                      `json:"minJailBlocks"`
	EpochLengthBlocks                  uint64                      `json:"epochLengthBlocks"`
	CurrentEpoch                       uint64                      `json:"currentEpoch"`
	EpochStartHeight                   uint64                      `json:"epochStartHeight"`
	EpochEffectiveStake                map[string]uint64           `json:"epochEffectiveStake,omitempty"`
	MaxTxPerBlock                      int                         `json:"maxTxPerBlock"`
	MaxMempoolSize                     int                         `json:"maxMempoolSize"`
	MaxPendingTxPerAccount             int                         `json:"maxPendingTxPerAccount"`
	MaxMempoolTxAgeBlocks              uint64                      `json:"maxMempoolTxAgeBlocks"`
	MinTxFee                           uint64                      `json:"minTxFee"`
	ProductRewardBps                   uint64                      `json:"productRewardBps"`
	ProductChallengeMinBond            uint64                      `json:"productChallengeMinBond"`
	ProductOracleQuorumBps             uint64                      `json:"productOracleQuorumBps"`
	ProductChallengeResolveDelayBlocks uint64                      `json:"productChallengeResolveDelayBlocks"`
	ProductAttestationTTLBlocks        uint64                      `json:"productAttestationTtlBlocks"`
	ProductChallengeMaxOpenBlocks      uint64                      `json:"productChallengeMaxOpenBlocks"`
	ProductTreasuryBalance             uint64                      `json:"productTreasuryBalance"`
	ProductProofs                      []ProductProof              `json:"productProofs,omitempty"`
	ProductPendingAttestations         []ProductPendingAttestation `json:"productPendingAttestations,omitempty"`
	ProductChallenges                  []ProductChallenge          `json:"productChallenges,omitempty"`
	ProductSettlements                 []ProductSettlement         `json:"productSettlements,omitempty"`
	ProductSignalScore                 map[string]uint64           `json:"productSignalScore,omitempty"`
	ProductLastRewardEpoch             uint64                      `json:"productLastRewardEpoch"`
	ProductLastRewards                 map[string]uint64           `json:"productLastRewards,omitempty"`
	LastFinalizedMs                    int64                       `json:"lastFinalizedMs"`
	ExpiredTxTotal                     uint64                      `json:"expiredTxTotal"`
	Accounts                           map[Address]Account         `json:"accounts"`
	Validators                         []Validator                 `json:"validators"`
	Delegations                        []Delegation                `json:"delegations,omitempty"`
	Mempool                            []Transaction               `json:"mempool"`
	MempoolAddedHeight                 map[string]uint64           `json:"mempoolAddedHeight,omitempty"`
	Blocks                             []Block                     `json:"blocks"`
}

func (c *Chain) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	accounts := make(map[Address]Account, len(c.accounts))
	for addr, acc := range c.accounts {
		accounts[addr] = *acc
	}

	validators := make([]Validator, 0, len(c.validators))
	for _, id := range c.validatorOrder {
		validators = append(validators, *c.validators[id])
	}
	delegations := make([]Delegation, 0, len(c.delegations))
	for _, key := range c.sortedDelegationKeysLocked() {
		delegation := c.delegations[key]
		if delegation == nil || delegation.Amount == 0 {
			continue
		}
		delegations = append(delegations, *delegation)
	}
	epochEffectiveStake := make(map[string]uint64, len(c.epochEffectiveStake))
	for validatorID, stake := range c.epochEffectiveStake {
		epochEffectiveStake[validatorID] = stake
	}
	productProofIDs := make([]string, 0, len(c.productProofs))
	for id := range c.productProofs {
		productProofIDs = append(productProofIDs, id)
	}
	sort.Strings(productProofIDs)
	productProofs := make([]ProductProof, 0, len(productProofIDs))
	for _, id := range productProofIDs {
		proof := c.productProofs[id]
		if proof == nil {
			continue
		}
		productProofs = append(productProofs, *proof)
	}
	productPendingIDs := make([]string, 0, len(c.productPendingAttestations))
	for id := range c.productPendingAttestations {
		productPendingIDs = append(productPendingIDs, id)
	}
	sort.Strings(productPendingIDs)
	productPendingAttestations := make([]ProductPendingAttestation, 0, len(productPendingIDs))
	for _, id := range productPendingIDs {
		pending := c.productPendingAttestations[id]
		if pending == nil {
			continue
		}
		copied := *pending
		if len(pending.Votes) > 0 {
			copied.Votes = append([]ProductAttestationVote(nil), pending.Votes...)
		}
		productPendingAttestations = append(productPendingAttestations, copied)
	}
	productChallengeIDs := make([]string, 0, len(c.productChallenges))
	for id := range c.productChallenges {
		productChallengeIDs = append(productChallengeIDs, id)
	}
	sort.Strings(productChallengeIDs)
	productChallenges := make([]ProductChallenge, 0, len(productChallengeIDs))
	for _, id := range productChallengeIDs {
		challenge := c.productChallenges[id]
		if challenge == nil {
			continue
		}
		copied := *challenge
		if len(challenge.Votes) > 0 {
			copied.Votes = append([]ProductChallengeVote(nil), challenge.Votes...)
		}
		productChallenges = append(productChallenges, copied)
	}
	productSettlementIDs := make([]string, 0, len(c.productSettlements))
	for id := range c.productSettlements {
		productSettlementIDs = append(productSettlementIDs, id)
	}
	sort.Strings(productSettlementIDs)
	productSettlements := make([]ProductSettlement, 0, len(productSettlementIDs))
	for _, id := range productSettlementIDs {
		settlement := c.productSettlements[id]
		if settlement == nil {
			continue
		}
		productSettlements = append(productSettlements, *settlement)
	}
	productSignalScore := make(map[string]uint64, len(c.productSignalScore))
	for validatorID, score := range c.productSignalScore {
		productSignalScore[validatorID] = score
	}
	productLastRewards := make(map[string]uint64, len(c.lastProductRewards))
	for validatorID, reward := range c.lastProductRewards {
		productLastRewards[validatorID] = reward
	}

	mempool := append([]Transaction(nil), c.mempool...)
	mempoolAddedHeight := make(map[string]uint64, len(c.mempoolAddedHeight))
	for id, h := range c.mempoolAddedHeight {
		mempoolAddedHeight[id] = h
	}
	blocks := make([]Block, 0, len(c.blocks))
	for _, b := range c.blocks {
		copied := b
		if len(b.Transactions) > 0 {
			copied.Transactions = append([]Transaction(nil), b.Transactions...)
		}
		if len(b.Votes) > 0 {
			copied.Votes = append([]Vote(nil), b.Votes...)
		}
		blocks = append(blocks, copied)
	}

	return Snapshot{
		Version:                            snapshotVersion,
		BlockIntervalMs:                    c.blockInterval.Milliseconds(),
		BaseReward:                         c.baseReward,
		MinJailBlocks:                      c.minJailBlocks,
		EpochLengthBlocks:                  c.epochLengthBlocks,
		CurrentEpoch:                       c.currentEpoch,
		EpochStartHeight:                   c.epochStartHeight,
		EpochEffectiveStake:                epochEffectiveStake,
		MaxTxPerBlock:                      c.maxTxPerBlock,
		MaxMempoolSize:                     c.maxMempoolSize,
		MaxPendingTxPerAccount:             c.maxPendingTxPerAccount,
		MaxMempoolTxAgeBlocks:              c.maxMempoolTxAgeBlocks,
		MinTxFee:                           c.minTxFee,
		ProductRewardBps:                   c.productRewardBps,
		ProductChallengeMinBond:            c.productChallengeMinBond,
		ProductOracleQuorumBps:             c.productOracleQuorumBps,
		ProductChallengeResolveDelayBlocks: c.productChallengeResolveDelayBlocks,
		ProductAttestationTTLBlocks:        c.productAttestationTTLBlocks,
		ProductChallengeMaxOpenBlocks:      c.productChallengeMaxOpenBlocks,
		ProductTreasuryBalance:             c.productTreasuryBalance,
		ProductProofs:                      productProofs,
		ProductPendingAttestations:         productPendingAttestations,
		ProductChallenges:                  productChallenges,
		ProductSettlements:                 productSettlements,
		ProductSignalScore:                 productSignalScore,
		ProductLastRewardEpoch:             c.lastProductRewardEpoch,
		ProductLastRewards:                 productLastRewards,
		LastFinalizedMs:                    c.lastFinalizedAt.UnixMilli(),
		ExpiredTxTotal:                     c.expiredTxTotal,
		Accounts:                           accounts,
		Validators:                         validators,
		Delegations:                        delegations,
		Mempool:                            mempool,
		MempoolAddedHeight:                 mempoolAddedHeight,
		Blocks:                             blocks,
	}
}

func (c *Chain) SaveSnapshot(path string) error {
	if path == "" {
		return errors.New("snapshot path is required")
	}
	data, err := c.snapshotJSON(true)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create snapshot dir: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return fmt.Errorf("write temp snapshot: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace snapshot: %w", err)
	}
	return nil
}

func LoadSnapshot(path string, cfg Config) (*Chain, error) {
	if path == "" {
		return nil, errors.New("snapshot path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	ss, err := decodeSnapshotJSON(data)
	if err != nil {
		return nil, err
	}

	return chainFromSnapshot(ss, cfg)
}

func LoadSnapshotBytes(data []byte, cfg Config) (*Chain, error) {
	if len(data) == 0 {
		return nil, errors.New("snapshot data is empty")
	}
	ss, err := decodeSnapshotJSON(data)
	if err != nil {
		return nil, err
	}
	return chainFromSnapshot(ss, cfg)
}

func (c *Chain) SaveSQLiteSnapshot(path string) error {
	if path == "" {
		return errors.New("sqlite state path is required")
	}

	data, err := c.snapshotJSON(false)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create sqlite state dir: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("open sqlite state: %w", err)
	}
	defer db.Close()

	if _, err := db.Exec(sqliteSchema); err != nil {
		return fmt.Errorf("ensure sqlite schema: %w", err)
	}
	if _, err := db.Exec(
		`INSERT INTO chain_state (key, version, payload, updated_ms)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET
         version = excluded.version,
         payload = excluded.payload,
         updated_ms = excluded.updated_ms`,
		sqliteStateKey,
		snapshotVersion,
		data,
		time.Now().UnixMilli(),
	); err != nil {
		return fmt.Errorf("write sqlite snapshot: %w", err)
	}
	return nil
}

func LoadSQLiteSnapshot(path string, cfg Config) (*Chain, error) {
	if path == "" {
		return nil, errors.New("sqlite state path is required")
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite state: %w", err)
	}
	defer db.Close()

	if _, err := db.Exec(sqliteSchema); err != nil {
		return nil, fmt.Errorf("ensure sqlite schema: %w", err)
	}

	var data []byte
	err = db.QueryRow(`SELECT payload FROM chain_state WHERE key = ?`, sqliteStateKey).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("sqlite state has no snapshot")
	}
	if err != nil {
		return nil, fmt.Errorf("read sqlite snapshot: %w", err)
	}

	ss, err := decodeSnapshotJSON(data)
	if err != nil {
		return nil, err
	}

	return chainFromSnapshot(ss, cfg)
}

func (c *Chain) snapshotJSON(pretty bool) ([]byte, error) {
	ss := c.Snapshot()
	var (
		data []byte
		err  error
	)
	if pretty {
		data, err = json.MarshalIndent(ss, "", "  ")
	} else {
		data, err = json.Marshal(ss)
	}
	if err != nil {
		return nil, fmt.Errorf("marshal snapshot: %w", err)
	}
	return data, nil
}

func decodeSnapshotJSON(data []byte) (Snapshot, error) {
	var ss Snapshot
	if err := json.Unmarshal(data, &ss); err != nil {
		return Snapshot{}, fmt.Errorf("decode snapshot: %w", err)
	}
	if ss.Version != snapshotVersion {
		return Snapshot{}, fmt.Errorf("unsupported snapshot version %d", ss.Version)
	}
	return ss, nil
}

func chainFromSnapshot(ss Snapshot, cfg Config) (*Chain, error) {
	if len(ss.Blocks) == 0 {
		return nil, errors.New("snapshot has no blocks")
	}
	if len(ss.Validators) == 0 {
		return nil, ErrNoValidators
	}

	accounts := make(map[Address]*Account, len(ss.Accounts))
	for addr, acc := range ss.Accounts {
		copied := acc
		accounts[addr] = &copied
	}

	validators := make(map[string]*Validator, len(ss.Validators))
	order := make([]string, 0, len(ss.Validators))
	for _, v := range ss.Validators {
		copied := v
		if copied.ID == "" {
			return nil, errors.New("snapshot contains validator with empty id")
		}
		if copied.PubKey == "" {
			return nil, fmt.Errorf("snapshot validator %q has empty pubkey", copied.ID)
		}
		if _, exists := validators[copied.ID]; exists {
			return nil, fmt.Errorf("duplicate validator id %q in snapshot", copied.ID)
		}
		validators[copied.ID] = &copied
		order = append(order, copied.ID)
		if _, ok := accounts[copied.Address]; !ok {
			accounts[copied.Address] = &Account{}
		}
	}
	sort.Strings(order)

	delegations := make(map[string]*Delegation, len(ss.Delegations))
	for _, delegation := range ss.Delegations {
		if delegation.ValidatorID == "" {
			return nil, errors.New("snapshot contains delegation with empty validator id")
		}
		if delegation.Delegator == "" {
			return nil, errors.New("snapshot contains delegation with empty delegator")
		}
		if delegation.Amount == 0 {
			continue
		}
		if _, ok := validators[delegation.ValidatorID]; !ok {
			return nil, fmt.Errorf("snapshot delegation references unknown validator %q", delegation.ValidatorID)
		}
		key := delegationKey(delegation.Delegator, delegation.ValidatorID)
		if _, exists := delegations[key]; exists {
			return nil, fmt.Errorf("duplicate delegation in snapshot for %s -> %s", delegation.Delegator, delegation.ValidatorID)
		}
		copied := delegation
		delegations[key] = &copied
	}

	blocks := make([]Block, 0, len(ss.Blocks))
	for i, block := range ss.Blocks {
		if block.Height != uint64(i) {
			return nil, fmt.Errorf("invalid block height at index %d: got %d", i, block.Height)
		}
		if i > 0 {
			prev := ss.Blocks[i-1]
			if block.PrevHash != prev.Hash {
				return nil, fmt.Errorf("invalid prev hash at height %d", block.Height)
			}
		}
		blocks = append(blocks, block)
	}

	blockInterval := cfg.BlockInterval
	if blockInterval <= 0 {
		if ss.BlockIntervalMs > 0 {
			blockInterval = time.Duration(ss.BlockIntervalMs) * time.Millisecond
		} else {
			blockInterval = 2 * time.Second
		}
	}
	baseReward := ss.BaseReward
	if cfg.BaseReward != 0 {
		baseReward = cfg.BaseReward
	}
	minJailBlocks := ss.MinJailBlocks
	if cfg.MinJailBlocks != 0 {
		minJailBlocks = cfg.MinJailBlocks
	}
	if minJailBlocks == 0 {
		minJailBlocks = defaultMinJailBlocks
	}
	epochLength := ss.EpochLengthBlocks
	if cfg.EpochLengthBlocks > 0 {
		epochLength = cfg.EpochLengthBlocks
	}
	if epochLength == 0 {
		epochLength = defaultEpochLengthBlocks
	}
	maxTx := ss.MaxTxPerBlock
	if cfg.MaxTxPerBlock > 0 {
		maxTx = cfg.MaxTxPerBlock
	}
	if maxTx <= 0 {
		maxTx = 1000
	}
	maxMempool := ss.MaxMempoolSize
	if cfg.MaxMempoolSize > 0 {
		maxMempool = cfg.MaxMempoolSize
	}
	if maxMempool <= 0 {
		maxMempool = 20_000
	}
	maxPendingPerAccount := ss.MaxPendingTxPerAccount
	if cfg.MaxPendingTxPerAccount > 0 {
		maxPendingPerAccount = cfg.MaxPendingTxPerAccount
	}
	if maxPendingPerAccount <= 0 {
		maxPendingPerAccount = defaultMaxPendingPerAccount
	}
	maxMempoolAgeBlocks := ss.MaxMempoolTxAgeBlocks
	if cfg.MaxMempoolTxAgeBlocks > 0 {
		maxMempoolAgeBlocks = cfg.MaxMempoolTxAgeBlocks
	}
	if maxMempoolAgeBlocks == 0 {
		maxMempoolAgeBlocks = defaultMaxMempoolTxAgeBlocks
	}
	minTxFee := ss.MinTxFee
	if cfg.MinTxFee > 0 {
		minTxFee = cfg.MinTxFee
	}
	if minTxFee == 0 {
		minTxFee = 1
	}
	productRewardBps := ss.ProductRewardBps
	if cfg.ProductRewardBps > 0 {
		productRewardBps = cfg.ProductRewardBps
	}
	if productRewardBps > 10_000 {
		productRewardBps = 10_000
	}
	if productRewardBps == 0 {
		productRewardBps = defaultProductRewardBps
	}
	productChallengeMinBond := ss.ProductChallengeMinBond
	if cfg.ProductChallengeMinBond > 0 {
		productChallengeMinBond = cfg.ProductChallengeMinBond
	}
	if productChallengeMinBond == 0 {
		productChallengeMinBond = defaultProductChallengeBond
	}
	productOracleQuorumBps := ss.ProductOracleQuorumBps
	if cfg.ProductOracleQuorumBps > 0 {
		productOracleQuorumBps = cfg.ProductOracleQuorumBps
	}
	if productOracleQuorumBps > 10_000 {
		productOracleQuorumBps = 10_000
	}
	if productOracleQuorumBps == 0 {
		productOracleQuorumBps = defaultProductOracleQuorumBps
	}
	if productOracleQuorumBps <= 5_000 {
		productOracleQuorumBps = 5_001
	}
	productChallengeResolveDelayBlocks := ss.ProductChallengeResolveDelayBlocks
	if cfg.ProductChallengeResolveDelayBlocks > 0 {
		productChallengeResolveDelayBlocks = cfg.ProductChallengeResolveDelayBlocks
	}
	if productChallengeResolveDelayBlocks == 0 {
		productChallengeResolveDelayBlocks = defaultProductChallengeResolveDelayBlocks
	}
	productAttestationTTLBlocks := ss.ProductAttestationTTLBlocks
	if cfg.ProductAttestationTTLBlocks > 0 {
		productAttestationTTLBlocks = cfg.ProductAttestationTTLBlocks
	}
	if productAttestationTTLBlocks == 0 {
		productAttestationTTLBlocks = defaultProductAttestationTTLBlocks
	}
	productChallengeMaxOpenBlocks := ss.ProductChallengeMaxOpenBlocks
	if cfg.ProductChallengeMaxOpenBlocks > 0 {
		productChallengeMaxOpenBlocks = cfg.ProductChallengeMaxOpenBlocks
	}
	if productChallengeMaxOpenBlocks == 0 {
		productChallengeMaxOpenBlocks = defaultProductChallengeMaxOpenBlocks
	}

	lastFinalizedAt := time.UnixMilli(ss.LastFinalizedMs)
	if ss.LastFinalizedMs <= 0 {
		lastFinalizedAt = time.Now()
	}

	c := &Chain{
		accounts:                           accounts,
		validators:                         validators,
		delegations:                        delegations,
		validatorOrder:                     order,
		mempool:                            append([]Transaction(nil), ss.Mempool...),
		mempoolSet:                         make(map[string]struct{}, len(ss.Mempool)),
		mempoolAddedHeight:                 make(map[string]uint64, len(ss.Mempool)),
		blocks:                             blocks,
		txIndex:                            make(map[string]txIndexRecord),
		blockInterval:                      blockInterval,
		baseReward:                         baseReward,
		minJailBlocks:                      minJailBlocks,
		epochLengthBlocks:                  epochLength,
		currentEpoch:                       ss.CurrentEpoch,
		epochStartHeight:                   ss.EpochStartHeight,
		epochEffectiveStake:                make(map[string]uint64),
		maxTxPerBlock:                      maxTx,
		maxMempoolSize:                     maxMempool,
		maxPendingTxPerAccount:             maxPendingPerAccount,
		maxMempoolTxAgeBlocks:              maxMempoolAgeBlocks,
		minTxFee:                           minTxFee,
		productRewardBps:                   productRewardBps,
		productChallengeMinBond:            productChallengeMinBond,
		productOracleQuorumBps:             productOracleQuorumBps,
		productChallengeResolveDelayBlocks: productChallengeResolveDelayBlocks,
		productAttestationTTLBlocks:        productAttestationTTLBlocks,
		productChallengeMaxOpenBlocks:      productChallengeMaxOpenBlocks,
		productTreasuryBalance:             ss.ProductTreasuryBalance,
		productProofs:                      make(map[string]*ProductProof, len(ss.ProductProofs)),
		productPendingAttestations:         make(map[string]*ProductPendingAttestation, len(ss.ProductPendingAttestations)),
		productChallenges:                  make(map[string]*ProductChallenge, len(ss.ProductChallenges)),
		productOpenChallenges:              make(map[string]string, len(ss.ProductChallenges)),
		productSettlements:                 make(map[string]*ProductSettlement, len(ss.ProductSettlements)),
		productSettlementRefs:              make(map[string]string, len(ss.ProductSettlements)),
		productSignalScore:                 make(map[string]uint64, len(ss.ProductSignalScore)),
		lastProductRewardEpoch:             ss.ProductLastRewardEpoch,
		lastProductRewards:                 make(map[string]uint64, len(ss.ProductLastRewards)),
		finalizeHook:                       cfg.FinalizeHook,
		lastFinalizedAt:                    lastFinalizedAt,
		startedAt:                          time.Now(),
		expiredTxTotal:                     ss.ExpiredTxTotal,
	}
	if c.epochStartHeight == 0 {
		if c.epochLengthBlocks > 0 {
			c.epochStartHeight = (c.currentEpoch * c.epochLengthBlocks) + 1
		} else {
			c.epochStartHeight = 1
		}
	}
	for validatorID, stake := range ss.EpochEffectiveStake {
		c.epochEffectiveStake[validatorID] = stake
	}
	if len(c.epochEffectiveStake) == 0 {
		c.epochEffectiveStake = c.buildEpochStakeSnapshotForState(c.validators, c.delegations)
	}
	for _, proof := range ss.ProductProofs {
		if proof.ID == "" {
			continue
		}
		copied := proof
		c.productProofs[proof.ID] = &copied
	}
	for _, pending := range ss.ProductPendingAttestations {
		if pending.ID == "" {
			continue
		}
		copied := pending
		if len(pending.Votes) > 0 {
			copied.Votes = append([]ProductAttestationVote(nil), pending.Votes...)
		}
		c.productPendingAttestations[pending.ID] = &copied
	}
	for _, challenge := range ss.ProductChallenges {
		if challenge.ID == "" {
			continue
		}
		copied := challenge
		if len(challenge.Votes) > 0 {
			copied.Votes = append([]ProductChallengeVote(nil), challenge.Votes...)
		}
		c.productChallenges[challenge.ID] = &copied
		if copied.Open {
			c.productOpenChallenges[copied.ProofID] = copied.ID
		}
	}
	for _, settlement := range ss.ProductSettlements {
		if settlement.ID == "" {
			continue
		}
		copied := settlement
		c.productSettlements[settlement.ID] = &copied
		c.productSettlementRefs[settlementReferenceKey(copied.Payer, copied.Reference)] = copied.ID
	}
	for validatorID, score := range ss.ProductSignalScore {
		c.productSignalScore[validatorID] = score
	}
	for validatorID, reward := range ss.ProductLastRewards {
		c.lastProductRewards[validatorID] = reward
	}
	currentHeight := uint64(len(c.blocks))
	for _, tx := range c.mempool {
		txID := tx.ID()
		c.mempoolSet[txID] = struct{}{}
		addedHeight, ok := ss.MempoolAddedHeight[txID]
		if !ok {
			addedHeight = currentHeight
		}
		c.mempoolAddedHeight[txID] = addedHeight
	}
	c.mempoolPeak = len(c.mempool)

	if err := c.validateLoadedBlocks(); err != nil {
		return nil, err
	}
	c.rebuildTxIndexLocked()

	c.rebuildMempoolLocked(map[string]struct{}{})
	return c, nil
}

func (c *Chain) validateLoadedBlocks() error {
	if len(c.blocks) == 0 {
		return errors.New("loaded chain has no blocks")
	}
	for i, block := range c.blocks {
		expected := c.hashBlock(block)
		if block.Hash != expected {
			return fmt.Errorf("block hash mismatch at height %d", block.Height)
		}
		if i == 0 {
			if block.Height != 0 {
				return errors.New("genesis block height must be 0")
			}
			continue
		}
		if block.PrevHash != c.blocks[i-1].Hash {
			return fmt.Errorf("block %d has invalid prev hash", block.Height)
		}
	}
	return nil
}
