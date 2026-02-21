package chain

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const snapshotVersion = 1

type Snapshot struct {
	Version         int                 `json:"version"`
	BlockIntervalMs int64               `json:"blockIntervalMs"`
	BaseReward      uint64              `json:"baseReward"`
	MaxTxPerBlock   int                 `json:"maxTxPerBlock"`
	MaxMempoolSize  int                 `json:"maxMempoolSize"`
	MinTxFee        uint64              `json:"minTxFee"`
	LastFinalizedMs int64               `json:"lastFinalizedMs"`
	Accounts        map[Address]Account `json:"accounts"`
	Validators      []Validator         `json:"validators"`
	Mempool         []Transaction       `json:"mempool"`
	Blocks          []Block             `json:"blocks"`
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

	mempool := append([]Transaction(nil), c.mempool...)
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
		Version:         snapshotVersion,
		BlockIntervalMs: c.blockInterval.Milliseconds(),
		BaseReward:      c.baseReward,
		MaxTxPerBlock:   c.maxTxPerBlock,
		MaxMempoolSize:  c.maxMempoolSize,
		MinTxFee:        c.minTxFee,
		LastFinalizedMs: c.lastFinalizedAt.UnixMilli(),
		Accounts:        accounts,
		Validators:      validators,
		Mempool:         mempool,
		Blocks:          blocks,
	}
}

func (c *Chain) SaveSnapshot(path string) error {
	if path == "" {
		return errors.New("snapshot path is required")
	}
	ss := c.Snapshot()
	data, err := json.MarshalIndent(ss, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
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
	var ss Snapshot
	if err := json.Unmarshal(data, &ss); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	if ss.Version != snapshotVersion {
		return nil, fmt.Errorf("unsupported snapshot version %d", ss.Version)
	}
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
	minTxFee := ss.MinTxFee
	if cfg.MinTxFee > 0 {
		minTxFee = cfg.MinTxFee
	}
	if minTxFee == 0 {
		minTxFee = 1
	}

	lastFinalizedAt := time.UnixMilli(ss.LastFinalizedMs)
	if ss.LastFinalizedMs <= 0 {
		lastFinalizedAt = time.Now()
	}

	c := &Chain{
		accounts:        accounts,
		validators:      validators,
		validatorOrder:  order,
		mempool:         append([]Transaction(nil), ss.Mempool...),
		mempoolSet:      make(map[string]struct{}, len(ss.Mempool)),
		blocks:          blocks,
		blockInterval:   blockInterval,
		baseReward:      baseReward,
		maxTxPerBlock:   maxTx,
		maxMempoolSize:  maxMempool,
		minTxFee:        minTxFee,
		finalizeHook:    cfg.FinalizeHook,
		lastFinalizedAt: lastFinalizedAt,
		startedAt:       time.Now(),
	}
	for _, tx := range c.mempool {
		c.mempoolSet[tx.ID()] = struct{}{}
	}
	c.mempoolPeak = len(c.mempool)

	if err := c.validateLoadedBlocks(); err != nil {
		return nil, err
	}

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
