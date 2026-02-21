package chain

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrNoValidators           = errors.New("no validators configured")
	ErrNoQuorum               = errors.New("quorum not reached")
	ErrTxFeeTooLow            = errors.New("transaction fee below minimum")
	ErrMempoolFull            = errors.New("mempool is full")
	ErrMempoolInvariantBroken = errors.New("mempool invariant broken")
)

type GenesisValidator struct {
	ID         string `json:"id"`
	PubKey     string `json:"pubKey"`
	Stake      uint64 `json:"stake"`
	WorkWeight uint64 `json:"workWeight"`
	Active     bool   `json:"active"`
}

type Config struct {
	BlockInterval      time.Duration
	GenesisTimestampMs int64
	BaseReward         uint64
	MaxTxPerBlock      int
	MaxMempoolSize     int
	MinTxFee           uint64
	GenesisAccounts    map[Address]uint64
	GenesisValidators  []GenesisValidator
	FinalizeHook       func(Block)
}

type Chain struct {
	mu              sync.RWMutex
	accounts        map[Address]*Account
	validators      map[string]*Validator
	validatorOrder  []string
	mempool         []Transaction
	mempoolSet      map[string]struct{}
	blocks          []Block
	blockInterval   time.Duration
	baseReward      uint64
	maxTxPerBlock   int
	maxMempoolSize  int
	minTxFee        uint64
	finalizeHook    func(Block)
	lastFinalizedAt time.Time
	startedAt       time.Time

	submittedTxTotal     uint64
	rejectedTxTotal      uint64
	evictedTxTotal       uint64
	includedTxTotal      uint64
	finalizedBlocksTotal uint64
	failedProduceTotal   uint64
	totalFeesCollected   uint64
	mempoolPeak          int
}

func New(cfg Config) (*Chain, error) {
	if cfg.BlockInterval <= 0 {
		cfg.BlockInterval = 2 * time.Second
	}
	if cfg.MaxTxPerBlock <= 0 {
		cfg.MaxTxPerBlock = 1000
	}
	if cfg.MaxMempoolSize <= 0 {
		cfg.MaxMempoolSize = 20_000
	}
	if cfg.MinTxFee == 0 {
		cfg.MinTxFee = 1
	}
	if len(cfg.GenesisValidators) == 0 {
		return nil, ErrNoValidators
	}

	accounts := make(map[Address]*Account, len(cfg.GenesisAccounts))
	for addr, balance := range cfg.GenesisAccounts {
		accounts[addr] = &Account{Balance: balance, Nonce: 0}
	}

	validators := make(map[string]*Validator, len(cfg.GenesisValidators))
	order := make([]string, 0, len(cfg.GenesisValidators))
	for _, gv := range cfg.GenesisValidators {
		if gv.PubKey == "" {
			return nil, fmt.Errorf("validator %q has empty pubkey", gv.ID)
		}
		if gv.Stake == 0 {
			return nil, fmt.Errorf("validator %q has zero stake", gv.ID)
		}
		addr, err := AddressFromPubKeyHex(gv.PubKey)
		if err != nil {
			return nil, fmt.Errorf("validator %q invalid pubkey: %w", gv.ID, err)
		}

		id := gv.ID
		if id == "" {
			id = string(addr)
		}
		if _, exists := validators[id]; exists {
			return nil, fmt.Errorf("duplicate validator id %q", id)
		}

		workWeight := gv.WorkWeight
		if workWeight == 0 {
			workWeight = 100
		}

		validators[id] = &Validator{
			ID:         id,
			Address:    addr,
			PubKey:     gv.PubKey,
			Stake:      gv.Stake,
			WorkWeight: workWeight,
			Active:     gv.Active,
		}
		order = append(order, id)

		if _, ok := accounts[addr]; !ok {
			accounts[addr] = &Account{}
		}
	}
	sort.Strings(order)

	c := &Chain{
		accounts:        accounts,
		validators:      validators,
		validatorOrder:  order,
		mempool:         make([]Transaction, 0),
		mempoolSet:      make(map[string]struct{}),
		blocks:          make([]Block, 0, 1024),
		blockInterval:   cfg.BlockInterval,
		baseReward:      cfg.BaseReward,
		maxTxPerBlock:   cfg.MaxTxPerBlock,
		maxMempoolSize:  cfg.MaxMempoolSize,
		minTxFee:        cfg.MinTxFee,
		finalizeHook:    cfg.FinalizeHook,
		lastFinalizedAt: time.Now(),
		startedAt:       time.Now(),
	}

	stateRoot := c.computeStateRoot(c.accounts)
	genesisTimestamp := cfg.GenesisTimestampMs
	if genesisTimestamp <= 0 {
		genesisTimestamp = time.Now().UnixMilli()
	}
	genesis := Block{
		Height:       0,
		PrevHash:     "",
		Timestamp:    genesisTimestamp,
		Proposer:     "genesis",
		Transactions: nil,
		StateRoot:    stateRoot,
		Finalized:    true,
	}
	genesis.Hash = c.hashBlock(genesis)
	c.blocks = append(c.blocks, genesis)

	return c, nil
}

func (c *Chain) Start(ctx context.Context, logf func(format string, args ...any)) {
	ticker := time.NewTicker(c.blockInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				block, err := c.ProduceOnce()
				if err != nil {
					if logf != nil {
						logf("produce block failed: %v", err)
					}
					continue
				}
				if logf != nil {
					logf("finalized block height=%d txs=%d proposer=%s hash=%s", block.Height, len(block.Transactions), block.Proposer, shortHash(block.Hash))
				}
				hook := c.getFinalizeHook()
				if hook != nil {
					hook(block)
				}
			}
		}
	}()
}

func (c *Chain) ProduceOnce() (Block, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	success := false
	defer func() {
		if !success {
			c.failedProduceTotal++
		}
	}()

	if len(c.validators) == 0 {
		return Block{}, ErrNoValidators
	}
	if len(c.blocks) == 0 {
		return Block{}, errors.New("chain has no genesis block")
	}

	height := uint64(len(c.blocks))
	prevHash := c.blocks[len(c.blocks)-1].Hash
	proposerID, err := c.selectProposerLocked(height, prevHash)
	if err != nil {
		return Block{}, err
	}

	workingState := c.cloneAccounts(c.accounts)
	candidates := c.sortedMempoolCandidatesLocked()
	included := make([]Transaction, 0, min(c.maxTxPerBlock, len(candidates)))
	includedIDs := make(map[string]struct{}, len(candidates))
	dropIDs := make(map[string]struct{})
	var fees uint64

	remaining := append([]Transaction(nil), candidates...)
	for len(remaining) > 0 && len(included) < c.maxTxPerBlock {
		nextRemaining := make([]Transaction, 0, len(remaining))
		progressed := false
		for _, tx := range remaining {
			if len(included) >= c.maxTxPerBlock {
				nextRemaining = append(nextRemaining, tx)
				continue
			}
			txID := tx.ID()
			if _, alreadyIncluded := includedIDs[txID]; alreadyIncluded {
				continue
			}
			if _, dropped := dropIDs[txID]; dropped {
				continue
			}
			if err := c.validateTxBasic(tx); err != nil {
				dropIDs[txID] = struct{}{}
				continue
			}
			if err := applyTx(workingState, tx); err != nil {
				// Keep tx for future blocks if it becomes valid after prior nonces arrive.
				nextRemaining = append(nextRemaining, tx)
				continue
			}
			progressed = true
			includedIDs[txID] = struct{}{}
			included = append(included, tx)
			fees += tx.Fee
		}
		remaining = nextRemaining
		if !progressed {
			break
		}
	}

	proposer, ok := c.validators[proposerID]
	if !ok {
		return Block{}, fmt.Errorf("unknown proposer %q", proposerID)
	}
	if _, ok := workingState[proposer.Address]; !ok {
		workingState[proposer.Address] = &Account{}
	}
	workingState[proposer.Address].Balance += c.baseReward + fees

	block := Block{
		Height:       height,
		PrevHash:     prevHash,
		Timestamp:    c.nextBlockTimestampLocked(),
		Proposer:     proposerID,
		Transactions: included,
		StateRoot:    c.computeStateRoot(workingState),
	}
	block.Hash = c.hashBlock(block)

	votes, yesStake, totalStake := c.collectVotesLocked(block)
	block.Votes = votes
	block.Finalized = yesStake*3 >= totalStake*2 && totalStake > 0
	if !block.Finalized {
		return Block{}, ErrNoQuorum
	}

	c.accounts = workingState
	c.blocks = append(c.blocks, block)
	c.lastFinalizedAt = time.Now()
	c.finalizedBlocksTotal++
	c.includedTxTotal += uint64(len(included))
	c.totalFeesCollected += fees
	c.rebuildMempoolLocked(mergeIDSets(includedIDs, dropIDs))
	success = true

	return block, nil
}

func (c *Chain) SubmitTx(tx Transaction) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.validateTxBasic(tx); err != nil {
		c.rejectedTxTotal++
		return "", err
	}
	if tx.Fee < c.minTxFee {
		c.rejectedTxTotal++
		return "", fmt.Errorf("%w: got %d want >= %d", ErrTxFeeTooLow, tx.Fee, c.minTxFee)
	}
	txID := tx.ID()
	if _, exists := c.mempoolSet[txID]; exists {
		c.rejectedTxTotal++
		return "", fmt.Errorf("duplicate transaction %s", txID)
	}

	if len(c.mempool) >= c.maxMempoolSize {
		evictIndex, evictedFee, ok := c.findEvictionCandidateLocked(tx.Fee)
		if !ok {
			c.rejectedTxTotal++
			return "", fmt.Errorf("%w: tx fee %d cannot replace lowest compatible fee %d", ErrMempoolFull, tx.Fee, evictedFee)
		}
		evicted := c.mempool[evictIndex]
		c.mempool = append(c.mempool[:evictIndex], c.mempool[evictIndex+1:]...)
		delete(c.mempoolSet, evicted.ID())
		c.evictedTxTotal++
	}

	pendingState := c.cloneAccounts(c.accounts)
	for _, pending := range c.mempool {
		if err := applyTx(pendingState, pending); err != nil {
			c.rejectedTxTotal++
			return "", fmt.Errorf("%w: %v", ErrMempoolInvariantBroken, err)
		}
	}
	if err := applyTx(pendingState, tx); err != nil {
		c.rejectedTxTotal++
		return "", err
	}

	c.mempool = append(c.mempool, tx)
	c.mempoolSet[txID] = struct{}{}
	c.submittedTxTotal++
	if len(c.mempool) > c.mempoolPeak {
		c.mempoolPeak = len(c.mempool)
	}
	return txID, nil
}

func (c *Chain) NextNonce(address Address) (uint64, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	pendingState := c.cloneAccounts(c.accounts)
	for _, pending := range c.mempool {
		if err := applyTx(pendingState, pending); err != nil {
			return 0, fmt.Errorf("mempool invariant broken: %w", err)
		}
	}
	acc, ok := pendingState[address]
	if !ok {
		return 0, fmt.Errorf("unknown account %s", address)
	}
	return acc.Nonce + 1, nil
}

func (c *Chain) GetStatus() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()

	head := c.blocks[len(c.blocks)-1]
	return Status{
		Height:          head.Height,
		HeadHash:        head.Hash,
		MempoolSize:     len(c.mempool),
		LastFinalizedMs: c.lastFinalizedAt.UnixMilli(),
	}
}

func (c *Chain) GetMetrics() Metrics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	head := c.blocks[len(c.blocks)-1]
	return Metrics{
		Height:                head.Height,
		MempoolSize:           len(c.mempool),
		MempoolPeak:           c.mempoolPeak,
		SubmittedTxTotal:      c.submittedTxTotal,
		RejectedTxTotal:       c.rejectedTxTotal,
		EvictedTxTotal:        c.evictedTxTotal,
		IncludedTxTotal:       c.includedTxTotal,
		FinalizedBlocksTotal:  c.finalizedBlocksTotal,
		FailedProduceTotal:    c.failedProduceTotal,
		TotalFeesCollected:    c.totalFeesCollected,
		LastFinalizedMs:       c.lastFinalizedAt.UnixMilli(),
		ActiveValidatorsCount: c.activeValidatorCountLocked(),
	}
}

func (c *Chain) BlockInterval() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.blockInterval
}

func (c *Chain) GetAccount(address Address) (Account, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	acc, ok := c.accounts[address]
	if !ok {
		return Account{}, false
	}
	return *acc, true
}

func (c *Chain) GetValidators() []Validator {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Validator, 0, len(c.validators))
	for _, id := range c.validatorOrder {
		v := c.validators[id]
		out = append(out, *v)
	}
	return out
}

func (c *Chain) SetValidatorWorkWeight(id string, workWeight uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.validators[id]
	if !ok {
		return fmt.Errorf("validator %q not found", id)
	}
	v.WorkWeight = workWeight
	return nil
}

func (c *Chain) SetValidatorActive(id string, active bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.validators[id]
	if !ok {
		return fmt.Errorf("validator %q not found", id)
	}
	v.Active = active
	return nil
}

func (c *Chain) GetBlocks(from, limit int) []Block {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if from < 0 {
		from = 0
	}
	if limit <= 0 {
		limit = 20
	}
	if from >= len(c.blocks) {
		return nil
	}
	to := from + limit
	if to > len(c.blocks) {
		to = len(c.blocks)
	}

	result := make([]Block, 0, to-from)
	for _, b := range c.blocks[from:to] {
		copied := b
		if len(b.Transactions) > 0 {
			copied.Transactions = append([]Transaction(nil), b.Transactions...)
		}
		if len(b.Votes) > 0 {
			copied.Votes = append([]Vote(nil), b.Votes...)
		}
		result = append(result, copied)
	}
	return result
}

func (c *Chain) SetFinalizeHook(hook func(Block)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.finalizeHook = hook
}

func (c *Chain) validateTxBasic(tx Transaction) error {
	if tx.From == "" {
		return errors.New("missing from")
	}
	if tx.To == "" {
		return errors.New("missing to")
	}
	if tx.From == tx.To {
		return errors.New("from and to cannot be equal")
	}
	if tx.Amount == 0 {
		return errors.New("amount must be > 0")
	}
	if tx.Timestamp <= 0 {
		return errors.New("timestamp must be > 0")
	}
	if tx.Nonce == 0 {
		return errors.New("nonce must be > 0")
	}
	if err := VerifyTransactionSignature(tx); err != nil {
		return fmt.Errorf("invalid tx signature: %w", err)
	}
	return nil
}

func applyTx(state map[Address]*Account, tx Transaction) error {
	from, ok := state[tx.From]
	if !ok {
		return fmt.Errorf("sender account %s does not exist", tx.From)
	}
	if from.Nonce+1 != tx.Nonce {
		return fmt.Errorf("bad nonce for %s: expected %d got %d", tx.From, from.Nonce+1, tx.Nonce)
	}
	cost := tx.Amount + tx.Fee
	if from.Balance < cost {
		return fmt.Errorf("insufficient balance for %s", tx.From)
	}
	from.Balance -= cost
	from.Nonce++

	to := state[tx.To]
	if to == nil {
		to = &Account{}
		state[tx.To] = to
	}
	to.Balance += tx.Amount
	return nil
}

func (c *Chain) selectProposerLocked(height uint64, prevHash string) (string, error) {
	total := c.totalEffectiveStakeLocked()
	if total == 0 {
		return "", errors.New("no active effective stake")
	}

	seedInput := fmt.Sprintf("%s:%d", prevHash, height)
	seed := sha256.Sum256([]byte(seedInput))
	pick := binary.BigEndian.Uint64(seed[:8]) % total

	var cursor uint64
	for _, id := range c.validatorOrder {
		effective := c.effectiveStake(c.validators[id])
		if effective == 0 {
			continue
		}
		cursor += effective
		if pick < cursor {
			return id, nil
		}
	}
	return "", errors.New("proposer selection failed")
}

func (c *Chain) totalEffectiveStakeLocked() uint64 {
	var total uint64
	for _, id := range c.validatorOrder {
		total += c.effectiveStake(c.validators[id])
	}
	return total
}

func (c *Chain) effectiveStake(v *Validator) uint64 {
	if v == nil || !v.Active || v.Stake == 0 || v.WorkWeight == 0 {
		return 0
	}
	product := v.Stake * v.WorkWeight
	if v.WorkWeight != 0 && product/v.WorkWeight != v.Stake {
		product = ^uint64(0)
	}
	effective := product / 100
	if effective == 0 {
		return 1
	}
	return effective
}

func (c *Chain) collectVotesLocked(block Block) ([]Vote, uint64, uint64) {
	votes := make([]Vote, 0, len(c.validators))
	var yesStake uint64
	var totalStake uint64

	for _, id := range c.validatorOrder {
		validator := c.validators[id]
		effective := c.effectiveStake(validator)
		if effective == 0 {
			continue
		}
		totalStake += effective

		approved := c.validatorApprovesLocked(validator, block)
		if approved {
			yesStake += effective
		}
		votes = append(votes, Vote{
			ValidatorID:    validator.ID,
			EffectiveStake: effective,
			Approved:       approved,
		})
	}

	return votes, yesStake, totalStake
}

func (c *Chain) validatorApprovesLocked(v *Validator, block Block) bool {
	if v == nil || !v.Active {
		return false
	}
	if len(c.blocks) == 0 {
		return false
	}
	if block.Height != uint64(len(c.blocks)) {
		return false
	}
	if block.PrevHash != c.blocks[len(c.blocks)-1].Hash {
		return false
	}
	if block.Hash != c.hashBlock(block) {
		return false
	}

	working := c.cloneAccounts(c.accounts)
	var fees uint64
	for _, tx := range block.Transactions {
		if err := c.validateTxBasic(tx); err != nil {
			return false
		}
		if err := applyTx(working, tx); err != nil {
			return false
		}
		fees += tx.Fee
	}

	proposer, ok := c.validators[block.Proposer]
	if !ok {
		return false
	}
	if _, ok := working[proposer.Address]; !ok {
		working[proposer.Address] = &Account{}
	}
	working[proposer.Address].Balance += c.baseReward + fees

	return c.computeStateRoot(working) == block.StateRoot
}

func (c *Chain) hashBlock(block Block) string {
	txIDs := make([]string, 0, len(block.Transactions))
	for _, tx := range block.Transactions {
		txIDs = append(txIDs, tx.ID())
	}
	payload := fmt.Sprintf(
		"%d|%s|%d|%s|%s|%s",
		block.Height,
		block.PrevHash,
		block.Timestamp,
		block.Proposer,
		strings.Join(txIDs, ","),
		block.StateRoot,
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func (c *Chain) computeStateRoot(state map[Address]*Account) string {
	addrs := make([]string, 0, len(state))
	for addr := range state {
		addrs = append(addrs, string(addr))
	}
	sort.Strings(addrs)

	var b strings.Builder
	for _, raw := range addrs {
		addr := Address(raw)
		acc := state[addr]
		b.WriteString(raw)
		b.WriteString(":")
		b.WriteString(fmt.Sprintf("%d:%d;", acc.Balance, acc.Nonce))
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func (c *Chain) cloneAccounts(src map[Address]*Account) map[Address]*Account {
	cloned := make(map[Address]*Account, len(src))
	for addr, acc := range src {
		copied := *acc
		cloned[addr] = &copied
	}
	return cloned
}

func (c *Chain) rebuildMempoolLocked(excluded map[string]struct{}) {
	state := c.cloneAccounts(c.accounts)
	filtered := make([]Transaction, 0, len(c.mempool))
	nextSet := make(map[string]struct{}, len(c.mempool))

	for _, tx := range c.mempool {
		txID := tx.ID()
		if _, skip := excluded[txID]; skip {
			continue
		}
		if err := c.validateTxBasic(tx); err != nil {
			continue
		}
		if err := applyTx(state, tx); err != nil {
			continue
		}
		filtered = append(filtered, tx)
		nextSet[txID] = struct{}{}
	}
	c.mempool = filtered
	c.mempoolSet = nextSet
	if len(c.mempool) > c.mempoolPeak {
		c.mempoolPeak = len(c.mempool)
	}
}

func shortHash(h string) string {
	if len(h) <= 10 {
		return h
	}
	return h[:10]
}

func (c *Chain) getFinalizeHook() func(Block) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.finalizeHook
}

func (c *Chain) nextBlockTimestampLocked() int64 {
	if len(c.blocks) == 0 {
		return time.Now().UnixMilli()
	}
	stepMs := c.blockInterval.Milliseconds()
	if stepMs <= 0 {
		stepMs = 1
	}
	return c.blocks[len(c.blocks)-1].Timestamp + stepMs
}

func (c *Chain) sortedMempoolCandidatesLocked() []Transaction {
	candidates := append([]Transaction(nil), c.mempool...)
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Fee == candidates[j].Fee {
			return candidates[i].Timestamp < candidates[j].Timestamp
		}
		return candidates[i].Fee > candidates[j].Fee
	})
	return candidates
}

func (c *Chain) activeValidatorCountLocked() int {
	count := 0
	for _, id := range c.validatorOrder {
		if c.effectiveStake(c.validators[id]) > 0 {
			count++
		}
	}
	return count
}

func mergeIDSets(sets ...map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{})
	for _, s := range sets {
		for id := range s {
			out[id] = struct{}{}
		}
	}
	return out
}

func (c *Chain) findEvictionCandidateLocked(incomingFee uint64) (index int, fee uint64, ok bool) {
	if len(c.mempool) == 0 {
		return -1, 0, false
	}

	type candidate struct {
		index int
		fee   uint64
		ts    int64
	}
	candidates := make([]candidate, 0, len(c.mempool))
	lowestFee := c.mempool[0].Fee
	for i, tx := range c.mempool {
		if tx.Fee < lowestFee {
			lowestFee = tx.Fee
		}
		candidates = append(candidates, candidate{
			index: i,
			fee:   tx.Fee,
			ts:    tx.Timestamp,
		})
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].fee == candidates[j].fee {
			return candidates[i].ts < candidates[j].ts
		}
		return candidates[i].fee < candidates[j].fee
	})

	for _, cand := range candidates {
		if incomingFee <= cand.fee {
			continue
		}
		nextPool := make([]Transaction, 0, len(c.mempool)-1)
		nextPool = append(nextPool, c.mempool[:cand.index]...)
		nextPool = append(nextPool, c.mempool[cand.index+1:]...)
		if c.canApplyMempoolLocked(nextPool) {
			return cand.index, cand.fee, true
		}
	}

	return -1, lowestFee, false
}

func (c *Chain) canApplyMempoolLocked(pool []Transaction) bool {
	state := c.cloneAccounts(c.accounts)
	for _, tx := range pool {
		if err := c.validateTxBasic(tx); err != nil {
			return false
		}
		if err := applyTx(state, tx); err != nil {
			return false
		}
	}
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
