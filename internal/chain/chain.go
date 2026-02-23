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
	ErrNoValidators                    = errors.New("no validators configured")
	ErrNoQuorum                        = errors.New("quorum not reached")
	ErrTxFeeTooLow                     = errors.New("transaction fee below minimum")
	ErrMempoolFull                     = errors.New("mempool is full")
	ErrMempoolAccountLimit             = errors.New("account pending transaction limit reached")
	ErrMempoolInvariantBroken          = errors.New("mempool invariant broken")
	ErrDuplicateTransaction            = errors.New("duplicate transaction")
	ErrTransactionAlreadyFinalized     = errors.New("transaction already finalized")
	ErrInvalidProposer                 = errors.New("invalid proposer")
	ErrUnexpectedHeight                = errors.New("unexpected block height")
	ErrBlockAlreadyFinalized           = errors.New("block already finalized")
	ErrInvalidAmount                   = errors.New("invalid amount")
	ErrInvalidSlashBasis               = errors.New("invalid slash basis points")
	ErrValidatorStillJailed            = errors.New("validator is still jailed")
	ErrInvalidProductProofRef          = errors.New("invalid product proof reference")
	ErrUnknownProductProof             = errors.New("unknown product proof")
	ErrUnknownProductChallenge         = errors.New("unknown product challenge")
	ErrProductChallengeOpen            = errors.New("product challenge is already open")
	ErrProductChallengeClosed          = errors.New("product challenge is already resolved")
	ErrProductChallengeBondLow         = errors.New("product challenge bond below minimum")
	ErrProductTreasuryFunds            = errors.New("insufficient product treasury funds")
	ErrOracleUnauthorized              = errors.New("sender is not authorized as oracle")
	ErrProductAttestationDuplicateVote = errors.New("oracle already voted for product attestation")
	ErrProductProofAlreadyFinalized    = errors.New("product proof is already finalized")
	ErrProductChallengeTooEarly        = errors.New("product challenge cannot be resolved yet")
	ErrProductChallengeDuplicateVote   = errors.New("oracle already voted for product challenge resolution")
	ErrProductChallengeVoteMismatch    = errors.New("challenge resolution vote parameters do not match current approval proposal")
	ErrProductSettlementDuplicate      = errors.New("duplicate product settlement reference for payer")
)

const (
	defaultMinJailBlocks                      uint64 = 3
	defaultMaxPendingPerAccount                      = 64
	defaultMaxMempoolTxAgeBlocks              uint64 = 120
	defaultEpochLengthBlocks                  uint64 = 1
	defaultProductRewardBps                   uint64 = 2_000
	defaultProductChallengeBond               uint64 = 10
	defaultProductOracleQuorumBps             uint64 = 6_667
	defaultProductChallengeResolveDelayBlocks uint64 = 1
	defaultProductAttestationTTLBlocks        uint64 = 8
	defaultProductChallengeMaxOpenBlocks      uint64 = 64
)

type GenesisValidator struct {
	ID         string `json:"id"`
	PubKey     string `json:"pubKey"`
	Stake      uint64 `json:"stake"`
	WorkWeight uint64 `json:"workWeight"`
	Active     bool   `json:"active"`
	Jailed     bool   `json:"jailed"`
}

type Config struct {
	BlockInterval                      time.Duration
	GenesisTimestampMs                 int64
	BaseReward                         uint64
	MinJailBlocks                      uint64
	EpochLengthBlocks                  uint64
	MaxTxPerBlock                      int
	MaxMempoolSize                     int
	MaxPendingTxPerAccount             int
	MaxMempoolTxAgeBlocks              uint64
	MinTxFee                           uint64
	ProductRewardBps                   uint64
	ProductChallengeMinBond            uint64
	ProductOracleQuorumBps             uint64
	ProductChallengeResolveDelayBlocks uint64
	ProductAttestationTTLBlocks        uint64
	ProductChallengeMaxOpenBlocks      uint64
	GenesisAccounts                    map[Address]uint64
	GenesisValidators                  []GenesisValidator
	FinalizeHook                       func(Block)
}

type txIndexRecord struct {
	Location FinalizedTxLocation
	Tx       Transaction
}

type Chain struct {
	mu                                 sync.RWMutex
	accounts                           map[Address]*Account
	validators                         map[string]*Validator
	delegations                        map[string]*Delegation
	validatorOrder                     []string
	mempool                            []Transaction
	mempoolSet                         map[string]struct{}
	mempoolAddedHeight                 map[string]uint64
	blocks                             []Block
	txIndex                            map[string]txIndexRecord
	blockInterval                      time.Duration
	baseReward                         uint64
	minJailBlocks                      uint64
	epochLengthBlocks                  uint64
	currentEpoch                       uint64
	epochStartHeight                   uint64
	epochEffectiveStake                map[string]uint64
	maxTxPerBlock                      int
	maxMempoolSize                     int
	maxPendingTxPerAccount             int
	maxMempoolTxAgeBlocks              uint64
	minTxFee                           uint64
	productRewardBps                   uint64
	productChallengeMinBond            uint64
	productOracleQuorumBps             uint64
	productChallengeResolveDelayBlocks uint64
	productAttestationTTLBlocks        uint64
	productChallengeMaxOpenBlocks      uint64
	productTreasuryBalance             uint64
	productProofs                      map[string]*ProductProof
	productPendingAttestations         map[string]*ProductPendingAttestation
	productChallenges                  map[string]*ProductChallenge
	productOpenChallenges              map[string]string
	productSettlements                 map[string]*ProductSettlement
	productSettlementRefs              map[string]string
	productSignalScore                 map[string]uint64
	lastProductRewardEpoch             uint64
	lastProductRewards                 map[string]uint64
	finalizeHook                       func(Block)
	lastFinalizedAt                    time.Time
	startedAt                          time.Time

	submittedTxTotal     uint64
	rejectedTxTotal      uint64
	evictedTxTotal       uint64
	expiredTxTotal       uint64
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
	if cfg.MaxPendingTxPerAccount <= 0 {
		cfg.MaxPendingTxPerAccount = defaultMaxPendingPerAccount
	}
	if cfg.MaxMempoolTxAgeBlocks == 0 {
		cfg.MaxMempoolTxAgeBlocks = defaultMaxMempoolTxAgeBlocks
	}
	if cfg.MinTxFee == 0 {
		cfg.MinTxFee = 1
	}
	if cfg.MinJailBlocks == 0 {
		cfg.MinJailBlocks = defaultMinJailBlocks
	}
	if cfg.EpochLengthBlocks == 0 {
		cfg.EpochLengthBlocks = defaultEpochLengthBlocks
	}
	if cfg.ProductRewardBps > 10_000 {
		cfg.ProductRewardBps = 10_000
	}
	if cfg.ProductRewardBps == 0 {
		cfg.ProductRewardBps = defaultProductRewardBps
	}
	if cfg.ProductChallengeMinBond == 0 {
		cfg.ProductChallengeMinBond = defaultProductChallengeBond
	}
	if cfg.ProductOracleQuorumBps > 10_000 {
		cfg.ProductOracleQuorumBps = 10_000
	}
	if cfg.ProductOracleQuorumBps == 0 {
		cfg.ProductOracleQuorumBps = defaultProductOracleQuorumBps
	}
	if cfg.ProductOracleQuorumBps <= 5_000 {
		cfg.ProductOracleQuorumBps = 5_001
	}
	if cfg.ProductChallengeResolveDelayBlocks == 0 {
		cfg.ProductChallengeResolveDelayBlocks = defaultProductChallengeResolveDelayBlocks
	}
	if cfg.ProductAttestationTTLBlocks == 0 {
		cfg.ProductAttestationTTLBlocks = defaultProductAttestationTTLBlocks
	}
	if cfg.ProductChallengeMaxOpenBlocks == 0 {
		cfg.ProductChallengeMaxOpenBlocks = defaultProductChallengeMaxOpenBlocks
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

		jailedUntil := uint64(0)
		if gv.Jailed {
			jailedUntil = cfg.MinJailBlocks
		}
		validators[id] = &Validator{
			ID:                id,
			Address:           addr,
			PubKey:            gv.PubKey,
			Stake:             gv.Stake,
			WorkWeight:        workWeight,
			Active:            gv.Active,
			Jailed:            gv.Jailed,
			JailedUntilHeight: jailedUntil,
		}
		order = append(order, id)

		if _, ok := accounts[addr]; !ok {
			accounts[addr] = &Account{}
		}
	}
	sort.Strings(order)

	c := &Chain{
		accounts:                           accounts,
		validators:                         validators,
		delegations:                        make(map[string]*Delegation),
		validatorOrder:                     order,
		mempool:                            make([]Transaction, 0),
		mempoolSet:                         make(map[string]struct{}),
		mempoolAddedHeight:                 make(map[string]uint64),
		blocks:                             make([]Block, 0, 1024),
		txIndex:                            make(map[string]txIndexRecord),
		blockInterval:                      cfg.BlockInterval,
		baseReward:                         cfg.BaseReward,
		minJailBlocks:                      cfg.MinJailBlocks,
		epochLengthBlocks:                  cfg.EpochLengthBlocks,
		currentEpoch:                       0,
		epochStartHeight:                   1,
		epochEffectiveStake:                make(map[string]uint64, len(order)),
		maxTxPerBlock:                      cfg.MaxTxPerBlock,
		maxMempoolSize:                     cfg.MaxMempoolSize,
		maxPendingTxPerAccount:             cfg.MaxPendingTxPerAccount,
		maxMempoolTxAgeBlocks:              cfg.MaxMempoolTxAgeBlocks,
		minTxFee:                           cfg.MinTxFee,
		productRewardBps:                   cfg.ProductRewardBps,
		productChallengeMinBond:            cfg.ProductChallengeMinBond,
		productOracleQuorumBps:             cfg.ProductOracleQuorumBps,
		productChallengeResolveDelayBlocks: cfg.ProductChallengeResolveDelayBlocks,
		productAttestationTTLBlocks:        cfg.ProductAttestationTTLBlocks,
		productChallengeMaxOpenBlocks:      cfg.ProductChallengeMaxOpenBlocks,
		productTreasuryBalance:             0,
		productProofs:                      make(map[string]*ProductProof),
		productPendingAttestations:         make(map[string]*ProductPendingAttestation),
		productChallenges:                  make(map[string]*ProductChallenge),
		productOpenChallenges:              make(map[string]string),
		productSettlements:                 make(map[string]*ProductSettlement),
		productSettlementRefs:              make(map[string]string),
		productSignalScore:                 make(map[string]uint64),
		lastProductRewards:                 make(map[string]uint64),
		finalizeHook:                       cfg.FinalizeHook,
		lastFinalizedAt:                    time.Now(),
		startedAt:                          time.Now(),
	}
	c.epochEffectiveStake = c.buildEpochStakeSnapshotForState(c.validators, c.delegations)

	stateRoot := c.computeStateRoot(c.accounts, c.validators, c.delegations, c.cloneProductExecutionStateLocked(), c.currentEpoch)
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
	c.rebuildTxIndexLocked()

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
	proposerID, err := c.selectProposerLocked(height, prevHash, 0)
	if err != nil {
		return Block{}, err
	}
	c.pruneStaleMempoolLocked()

	workingState := c.cloneAccounts(c.accounts)
	workingValidators := c.cloneValidators(c.validators)
	workingDelegations := c.cloneDelegations(c.delegations)
	workingProduct := c.cloneProductExecutionStateLocked()
	workingEpoch := c.currentEpoch
	blockTimestamp := c.nextBlockTimestampLocked()
	expireProductStateAtHeight(workingProduct, height, blockTimestamp)
	candidates := c.sortedMempoolCandidatesLocked(height)
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
			if err := applyTx(workingState, workingValidators, workingDelegations, workingProduct, tx, height, c.minJailBlocks, workingEpoch, c.productChallengeMinBond, c.productOracleQuorumBps, c.productChallengeResolveDelayBlocks, c.productAttestationTTLBlocks, c.productChallengeMaxOpenBlocks); err != nil {
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
	if err := c.applyEpochTransitionIfNeededLocked(height, workingState, workingValidators, workingDelegations, workingProduct, &workingEpoch); err != nil {
		return Block{}, err
	}

	block := Block{
		Height:       height,
		Round:        0,
		PrevHash:     prevHash,
		Timestamp:    blockTimestamp,
		Proposer:     proposerID,
		Transactions: included,
		StateRoot:    c.computeStateRoot(workingState, workingValidators, workingDelegations, workingProduct, workingEpoch),
	}
	block.Hash = c.hashBlock(block)

	votes, yesStake, totalStake := c.collectVotesLocked(block)
	block.Votes = votes
	block.Finalized = yesStake*3 >= totalStake*2 && totalStake > 0
	if !block.Finalized {
		return Block{}, ErrNoQuorum
	}

	c.accounts = workingState
	c.validators = workingValidators
	c.delegations = workingDelegations
	c.productTreasuryBalance = workingProduct.TreasuryBalance
	c.productProofs = workingProduct.Proofs
	c.productPendingAttestations = workingProduct.PendingAttestations
	c.productChallenges = workingProduct.Challenges
	c.productOpenChallenges = workingProduct.OpenChallenges
	c.productSettlements = workingProduct.Settlements
	c.productSettlementRefs = workingProduct.SettlementRefs
	c.productSignalScore = workingProduct.SignalScore
	c.lastProductRewardEpoch = workingProduct.LastRewardEpoch
	c.lastProductRewards = workingProduct.LastRewards
	epochChanged := workingEpoch != c.currentEpoch
	c.currentEpoch = workingEpoch
	if epochChanged {
		if c.epochLengthBlocks > 0 {
			c.epochStartHeight = (workingEpoch * c.epochLengthBlocks) + 1
		}
		c.epochEffectiveStake = c.buildEpochStakeSnapshotForState(workingValidators, workingDelegations)
	}
	c.blocks = append(c.blocks, block)
	c.indexFinalizedBlockTxsLocked(block)
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
	c.pruneStaleMempoolLocked()

	txID := tx.ID()
	if _, exists := c.mempoolSet[txID]; exists {
		c.rejectedTxTotal++
		return "", fmt.Errorf("%w: %s", ErrDuplicateTransaction, txID)
	}
	if _, exists := c.txIndex[txID]; exists {
		c.rejectedTxTotal++
		return "", fmt.Errorf("%w: %s", ErrTransactionAlreadyFinalized, txID)
	}
	if c.maxPendingTxPerAccount > 0 {
		pendingForAccount := c.pendingCountForAccountLocked(tx.From)
		if pendingForAccount >= c.maxPendingTxPerAccount {
			c.rejectedTxTotal++
			return "", fmt.Errorf("%w: account=%s pending=%d limit=%d", ErrMempoolAccountLimit, tx.From, pendingForAccount, c.maxPendingTxPerAccount)
		}
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
		delete(c.mempoolAddedHeight, evicted.ID())
		c.evictedTxTotal++
	}

	pendingState := c.cloneAccounts(c.accounts)
	pendingValidators := c.cloneValidators(c.validators)
	pendingDelegations := c.cloneDelegations(c.delegations)
	pendingProduct := c.cloneProductExecutionStateLocked()
	nextHeight := uint64(len(c.blocks))
	for _, pending := range c.mempool {
		if err := applyTx(pendingState, pendingValidators, pendingDelegations, pendingProduct, pending, nextHeight, c.minJailBlocks, c.currentEpoch, c.productChallengeMinBond, c.productOracleQuorumBps, c.productChallengeResolveDelayBlocks, c.productAttestationTTLBlocks, c.productChallengeMaxOpenBlocks); err != nil {
			c.rejectedTxTotal++
			return "", fmt.Errorf("%w: %v", ErrMempoolInvariantBroken, err)
		}
	}
	if err := applyTx(pendingState, pendingValidators, pendingDelegations, pendingProduct, tx, nextHeight, c.minJailBlocks, c.currentEpoch, c.productChallengeMinBond, c.productOracleQuorumBps, c.productChallengeResolveDelayBlocks, c.productAttestationTTLBlocks, c.productChallengeMaxOpenBlocks); err != nil {
		c.rejectedTxTotal++
		return "", err
	}

	c.mempool = append(c.mempool, tx)
	c.mempoolSet[txID] = struct{}{}
	c.mempoolAddedHeight[txID] = nextHeight
	c.submittedTxTotal++
	if len(c.mempool) > c.mempoolPeak {
		c.mempoolPeak = len(c.mempool)
	}
	return txID, nil
}

func (c *Chain) NextNonce(address Address) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneStaleMempoolLocked()

	pendingState := c.cloneAccounts(c.accounts)
	pendingValidators := c.cloneValidators(c.validators)
	pendingDelegations := c.cloneDelegations(c.delegations)
	pendingProduct := c.cloneProductExecutionStateLocked()
	nextHeight := uint64(len(c.blocks))
	for _, pending := range c.mempool {
		if err := applyTx(pendingState, pendingValidators, pendingDelegations, pendingProduct, pending, nextHeight, c.minJailBlocks, c.currentEpoch, c.productChallengeMinBond, c.productOracleQuorumBps, c.productChallengeResolveDelayBlocks, c.productAttestationTTLBlocks, c.productChallengeMaxOpenBlocks); err != nil {
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
		Epoch:           c.currentEpoch,
	}
}

func (c *Chain) GetMetrics() Metrics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	head := c.blocks[len(c.blocks)-1]
	return Metrics{
		Height:                 head.Height,
		Epoch:                  c.currentEpoch,
		MempoolSize:            len(c.mempool),
		MempoolPeak:            c.mempoolPeak,
		SubmittedTxTotal:       c.submittedTxTotal,
		RejectedTxTotal:        c.rejectedTxTotal,
		EvictedTxTotal:         c.evictedTxTotal,
		ExpiredTxTotal:         c.expiredTxTotal,
		IncludedTxTotal:        c.includedTxTotal,
		FinalizedBlocksTotal:   c.finalizedBlocksTotal,
		FailedProduceTotal:     c.failedProduceTotal,
		TotalFeesCollected:     c.totalFeesCollected,
		ProductTreasuryBalance: c.productTreasuryBalance,
		LastFinalizedMs:        c.lastFinalizedAt.UnixMilli(),
		ActiveValidatorsCount:  c.activeValidatorCountLocked(),
	}
}

func (c *Chain) BlockInterval() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.blockInterval
}

func (c *Chain) MinJailBlocks() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.minJailBlocks
}

func (c *Chain) MinTxFee() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.minTxFee
}

func (c *Chain) NextExpectedProposer() (height uint64, proposerID string, err error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.blocks) == 0 {
		return 0, "", errors.New("chain has no genesis block")
	}
	height = uint64(len(c.blocks))
	prevHash := c.blocks[len(c.blocks)-1].Hash
	proposerID, err = c.selectProposerLocked(height, prevHash, 0)
	if err != nil {
		return 0, "", err
	}
	return height, proposerID, nil
}

func (c *Chain) ExpectedProposerForRound(height uint64, round uint64) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.blocks) == 0 {
		return "", errors.New("chain has no genesis block")
	}
	if height != uint64(len(c.blocks)) {
		return "", fmt.Errorf("unexpected height %d (current %d)", height, len(c.blocks))
	}
	prevHash := c.blocks[len(c.blocks)-1].Hash
	return c.selectProposerLocked(height, prevHash, round)
}

func (c *Chain) ProposerRoundForHeight(height uint64, proposerID string, startRound, maxLookahead uint64) (uint64, bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.blocks) == 0 {
		return 0, false, errors.New("chain has no genesis block")
	}
	if height != uint64(len(c.blocks)) {
		return 0, false, fmt.Errorf("unexpected height %d (current %d)", height, len(c.blocks))
	}
	if proposerID == "" {
		return 0, false, errors.New("proposer id is required")
	}
	prevHash := c.blocks[len(c.blocks)-1].Hash
	for r := startRound; r <= startRound+maxLookahead; r++ {
		p, err := c.selectProposerLocked(height, prevHash, r)
		if err != nil {
			return 0, false, err
		}
		if p == proposerID {
			return r, true, nil
		}
	}
	return 0, false, nil
}

func (c *Chain) BuildProposalForRound(round uint64, proposerID string) (Block, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.validators) == 0 {
		return Block{}, ErrNoValidators
	}
	if len(c.blocks) == 0 {
		return Block{}, errors.New("chain has no genesis block")
	}

	height := uint64(len(c.blocks))
	prevHash := c.blocks[len(c.blocks)-1].Hash
	expectedProposer, err := c.selectProposerLocked(height, prevHash, round)
	if err != nil {
		return Block{}, err
	}
	if proposerID != expectedProposer {
		return Block{}, fmt.Errorf("%w: got %s want %s", ErrInvalidProposer, proposerID, expectedProposer)
	}

	workingState := c.cloneAccounts(c.accounts)
	workingValidators := c.cloneValidators(c.validators)
	workingDelegations := c.cloneDelegations(c.delegations)
	workingProduct := c.cloneProductExecutionStateLocked()
	workingEpoch := c.currentEpoch
	blockTimestamp := c.nextBlockTimestampLocked()
	expireProductStateAtHeight(workingProduct, height, blockTimestamp)
	candidates := c.sortedMempoolCandidatesLocked(height)
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
			if err := applyTx(workingState, workingValidators, workingDelegations, workingProduct, tx, height, c.minJailBlocks, workingEpoch, c.productChallengeMinBond, c.productOracleQuorumBps, c.productChallengeResolveDelayBlocks, c.productAttestationTTLBlocks, c.productChallengeMaxOpenBlocks); err != nil {
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
	if err := c.applyEpochTransitionIfNeededLocked(height, workingState, workingValidators, workingDelegations, workingProduct, &workingEpoch); err != nil {
		return Block{}, err
	}

	block := Block{
		Height:       height,
		Round:        round,
		PrevHash:     prevHash,
		Timestamp:    blockTimestamp,
		Proposer:     proposerID,
		Transactions: included,
		StateRoot:    c.computeStateRoot(workingState, workingValidators, workingDelegations, workingProduct, workingEpoch),
	}
	block.Hash = c.hashBlock(block)
	return block, nil
}

func (c *Chain) BuildProposal(proposerID string) (Block, error) {
	return c.BuildProposalForRound(0, proposerID)
}

func (c *Chain) BuildVote(block Block, validatorID string) (Vote, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	validator, ok := c.validators[validatorID]
	if !ok {
		return Vote{}, fmt.Errorf("validator %q not found", validatorID)
	}
	effective := c.effectiveStakeByIDLocked(validatorID)
	if effective == 0 {
		return Vote{}, fmt.Errorf("validator %q has zero effective stake", validatorID)
	}
	approved := c.validatorApprovesLocked(validator, block)
	return Vote{
		ValidatorID:    validatorID,
		EffectiveStake: effective,
		Approved:       approved,
	}, nil
}

func (c *Chain) TotalEffectiveStake() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.totalEffectiveStakeLocked()
}

func (c *Chain) ValidatorEffectiveStake(id string) (uint64, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	validator, ok := c.validators[id]
	if !ok {
		return 0, fmt.Errorf("validator %q not found", id)
	}
	return c.effectiveStakeByIDLocked(validator.ID), nil
}

func (c *Chain) FinalizeExternalBlock(block Block) error {
	c.mu.Lock()
	hook := c.finalizeHook

	if len(c.blocks) == 0 {
		c.mu.Unlock()
		return errors.New("chain has no genesis block")
	}

	currentHeight := uint64(len(c.blocks))
	if block.Height < currentHeight {
		existing := c.blocks[block.Height]
		if existing.Hash == block.Hash {
			c.mu.Unlock()
			return ErrBlockAlreadyFinalized
		}
		c.mu.Unlock()
		return fmt.Errorf("%w: received height %d while current is %d", ErrUnexpectedHeight, block.Height, currentHeight)
	}
	if block.Height != currentHeight {
		c.mu.Unlock()
		return fmt.Errorf("%w: received height %d while current is %d", ErrUnexpectedHeight, block.Height, currentHeight)
	}

	expectedProposer, err := c.selectProposerLocked(block.Height, c.blocks[len(c.blocks)-1].Hash, block.Round)
	if err != nil {
		c.mu.Unlock()
		return err
	}
	if block.Proposer != expectedProposer {
		c.mu.Unlock()
		return fmt.Errorf("%w: got %s want %s", ErrInvalidProposer, block.Proposer, expectedProposer)
	}

	yesStake, totalStake, err := c.validateVotesLocked(block.Votes)
	if err != nil {
		c.mu.Unlock()
		return err
	}
	if totalStake == 0 || yesStake*3 < totalStake*2 {
		c.mu.Unlock()
		return fmt.Errorf("%w: yes=%d total=%d", ErrNoQuorum, yesStake, totalStake)
	}

	workingState, workingValidators, workingDelegations, workingProduct, workingEpoch, includedIDs, fees, err := c.applyBlockToStateLocked(block)
	if err != nil {
		c.mu.Unlock()
		return err
	}

	block.Finalized = true
	c.accounts = workingState
	c.validators = workingValidators
	c.delegations = workingDelegations
	c.productTreasuryBalance = workingProduct.TreasuryBalance
	c.productProofs = workingProduct.Proofs
	c.productPendingAttestations = workingProduct.PendingAttestations
	c.productChallenges = workingProduct.Challenges
	c.productOpenChallenges = workingProduct.OpenChallenges
	c.productSettlements = workingProduct.Settlements
	c.productSettlementRefs = workingProduct.SettlementRefs
	c.productSignalScore = workingProduct.SignalScore
	c.lastProductRewardEpoch = workingProduct.LastRewardEpoch
	c.lastProductRewards = workingProduct.LastRewards
	epochChanged := workingEpoch != c.currentEpoch
	c.currentEpoch = workingEpoch
	if epochChanged {
		if c.epochLengthBlocks > 0 {
			c.epochStartHeight = (workingEpoch * c.epochLengthBlocks) + 1
		}
		c.epochEffectiveStake = c.buildEpochStakeSnapshotForState(workingValidators, workingDelegations)
	}
	c.blocks = append(c.blocks, block)
	c.indexFinalizedBlockTxsLocked(block)
	c.lastFinalizedAt = time.Now()
	c.finalizedBlocksTotal++
	c.includedTxTotal += uint64(len(block.Transactions))
	c.totalFeesCollected += fees
	c.rebuildMempoolLocked(includedIDs)
	c.mu.Unlock()

	if hook != nil {
		hook(block)
	}
	return nil
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

func (c *Chain) GetValidator(id string) (Validator, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.validators[id]
	if !ok {
		return Validator{}, false
	}
	return *v, true
}

func (c *Chain) GetDelegations() []Delegation {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]Delegation, 0, len(c.delegations))
	for _, key := range c.sortedDelegationKeysLocked() {
		delegation := c.delegations[key]
		if delegation == nil || delegation.Amount == 0 {
			continue
		}
		out = append(out, *delegation)
	}
	return out
}

func (c *Chain) GetEpochInfo() EpochInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	validatorSet := make([]EpochValidatorStake, 0, len(c.epochEffectiveStake))
	for _, id := range c.validatorOrder {
		validatorSet = append(validatorSet, EpochValidatorStake{
			ValidatorID:    id,
			EffectiveStake: c.epochEffectiveStake[id],
		})
	}
	nextTransitionHeight := uint64(0)
	if c.epochLengthBlocks > 0 {
		nextTransitionHeight = addClampUint64(c.epochStartHeight, c.epochLengthBlocks-1)
	}
	return EpochInfo{
		Current:              c.currentEpoch,
		Length:               c.epochLengthBlocks,
		StartHeight:          c.epochStartHeight,
		NextTransitionHeight: nextTransitionHeight,
		ValidatorSet:         validatorSet,
	}
}

func (c *Chain) GetProductStatus() ProductStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()

	lastRewards := c.sortedProductRewardSliceLocked(c.lastProductRewards)
	pendingScore := c.sortedProductRewardSliceLocked(c.productSignalScore)
	openChallenges := 0
	for _, challenge := range c.productChallenges {
		if challenge != nil && challenge.Open {
			openChallenges++
		}
	}
	return ProductStatus{
		TreasuryBalance:             c.productTreasuryBalance,
		RewardBasisPoints:           c.productRewardBps,
		ChallengeMinBond:            c.productChallengeMinBond,
		OracleQuorumBps:             c.productOracleQuorumBps,
		ChallengeResolveDelayBlocks: c.productChallengeResolveDelayBlocks,
		AttestationTTLBlocks:        c.productAttestationTTLBlocks,
		ChallengeMaxOpenBlocks:      c.productChallengeMaxOpenBlocks,
		CurrentEpoch:                c.currentEpoch,
		LastRewardEpoch:             c.lastProductRewardEpoch,
		LastRewards:                 lastRewards,
		PendingSignalScore:          pendingScore,
		PendingAttestations:         len(c.productPendingAttestations),
		ProofCount:                  len(c.productProofs),
		OpenChallenges:              openChallenges,
		SettlementCount:             len(c.productSettlements),
	}
}

func (c *Chain) GetProductPendingAttestations() []ProductPendingAttestation {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]string, 0, len(c.productPendingAttestations))
	for id := range c.productPendingAttestations {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	out := make([]ProductPendingAttestation, 0, len(keys))
	for _, id := range keys {
		pending := c.productPendingAttestations[id]
		if pending == nil {
			continue
		}
		copied := *pending
		if len(pending.Votes) > 0 {
			copied.Votes = append([]ProductAttestationVote(nil), pending.Votes...)
		}
		out = append(out, copied)
	}
	return out
}

func (c *Chain) GetProductProofs() []ProductProof {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]string, 0, len(c.productProofs))
	for id := range c.productProofs {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	out := make([]ProductProof, 0, len(keys))
	for _, id := range keys {
		proof := c.productProofs[id]
		if proof == nil {
			continue
		}
		out = append(out, *proof)
	}
	return out
}

func (c *Chain) GetProductChallenges() []ProductChallenge {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]string, 0, len(c.productChallenges))
	for id := range c.productChallenges {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	out := make([]ProductChallenge, 0, len(keys))
	for _, id := range keys {
		challenge := c.productChallenges[id]
		if challenge == nil {
			continue
		}
		copied := *challenge
		if len(challenge.Votes) > 0 {
			copied.Votes = append([]ProductChallengeVote(nil), challenge.Votes...)
		}
		out = append(out, copied)
	}
	return out
}

func (c *Chain) GetProductSettlements() []ProductSettlement {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]string, 0, len(c.productSettlements))
	for id := range c.productSettlements {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	out := make([]ProductSettlement, 0, len(keys))
	for _, id := range keys {
		settlement := c.productSettlements[id]
		if settlement == nil {
			continue
		}
		out = append(out, *settlement)
	}
	return out
}

func (c *Chain) GetProductSettlementByPayerReference(payer Address, reference string) (ProductSettlement, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	refKey := settlementReferenceKey(payer, reference)
	settlementID, ok := c.productSettlementRefs[refKey]
	if !ok || settlementID == "" {
		return ProductSettlement{}, false
	}
	settlement := c.productSettlements[settlementID]
	if settlement == nil {
		return ProductSettlement{}, false
	}
	return *settlement, true
}

func (c *Chain) SetValidatorWorkWeight(id string, workWeight uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.validators[id]
	if !ok {
		return fmt.Errorf("validator %q not found", id)
	}
	v.WorkWeight = workWeight
	c.refreshEpochEffectiveStakeLocked()
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
	c.refreshEpochEffectiveStakeLocked()
	return nil
}

func (c *Chain) SetValidatorJailed(id string, jailed bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.validators[id]
	if !ok {
		return fmt.Errorf("validator %q not found", id)
	}
	v.Jailed = jailed
	if jailed {
		nextHeight := uint64(len(c.blocks))
		releaseHeight := addClampUint64(nextHeight, c.minJailBlocks)
		if releaseHeight > v.JailedUntilHeight {
			v.JailedUntilHeight = releaseHeight
		}
	} else {
		v.JailedUntilHeight = 0
	}
	c.refreshEpochEffectiveStakeLocked()
	return nil
}

func (c *Chain) BondValidatorStake(id string, amount uint64) error {
	if amount == 0 {
		return ErrInvalidAmount
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	v, ok := c.validators[id]
	if !ok {
		return fmt.Errorf("validator %q not found", id)
	}
	acc, ok := c.accounts[v.Address]
	if !ok {
		return fmt.Errorf("validator account %s not found", v.Address)
	}
	if acc.Balance < amount {
		return fmt.Errorf("insufficient validator balance: have=%d need=%d", acc.Balance, amount)
	}
	newStake := v.Stake + amount
	if newStake < v.Stake {
		return errors.New("stake overflow")
	}
	acc.Balance -= amount
	v.Stake = newStake
	c.refreshEpochEffectiveStakeLocked()
	return nil
}

func (c *Chain) UnbondValidatorStake(id string, amount uint64) error {
	if amount == 0 {
		return ErrInvalidAmount
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	v, ok := c.validators[id]
	if !ok {
		return fmt.Errorf("validator %q not found", id)
	}
	if v.Stake < amount {
		return fmt.Errorf("insufficient validator stake: have=%d need=%d", v.Stake, amount)
	}
	acc, ok := c.accounts[v.Address]
	if !ok {
		acc = &Account{}
		c.accounts[v.Address] = acc
	}
	newBalance := acc.Balance + amount
	if newBalance < acc.Balance {
		return errors.New("balance overflow")
	}
	v.Stake -= amount
	acc.Balance = newBalance
	c.refreshEpochEffectiveStakeLocked()
	return nil
}

func (c *Chain) SlashValidatorStake(id string, basisPoints uint64) (uint64, error) {
	if basisPoints == 0 || basisPoints > 10_000 {
		return 0, ErrInvalidSlashBasis
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	v, ok := c.validators[id]
	if !ok {
		return 0, fmt.Errorf("validator %q not found", id)
	}
	if v.Stake == 0 {
		return 0, nil
	}

	slashed := (v.Stake * basisPoints) / 10_000
	if slashed == 0 {
		slashed = 1
	}
	if slashed > v.Stake {
		slashed = v.Stake
	}
	v.Stake -= slashed
	c.refreshEpochEffectiveStakeLocked()
	return slashed, nil
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

func (c *Chain) GetTransaction(txID string) (TransactionLookup, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	target := strings.TrimSpace(txID)
	if target == "" {
		return TransactionLookup{}, false
	}

	for idx, tx := range c.mempool {
		if tx.ID() != target {
			continue
		}
		copied := tx
		mempoolIndex := idx
		return TransactionLookup{
			TxID:         target,
			State:        TxStatePending,
			Transaction:  copied,
			MempoolIndex: &mempoolIndex,
		}, true
	}

	record, ok := c.txIndex[target]
	if ok {
		copiedTx := record.Tx
		location := record.Location
		return TransactionLookup{
			TxID:        target,
			State:       TxStateFinalized,
			Transaction: copiedTx,
			Finalized:   &location,
		}, true
	}

	return TransactionLookup{}, false
}

func (c *Chain) GetFinalizedTransactions() []TransactionLookup {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]TransactionLookup, 0, len(c.txIndex))
	for txID, record := range c.txIndex {
		copiedTx := record.Tx
		location := record.Location
		out = append(out, TransactionLookup{
			TxID:        txID,
			State:       TxStateFinalized,
			Transaction: copiedTx,
			Finalized:   &location,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		left := out[i]
		right := out[j]
		if left.Finalized != nil && right.Finalized != nil {
			if left.Finalized.Height != right.Finalized.Height {
				return left.Finalized.Height < right.Finalized.Height
			}
			if left.Finalized.Round != right.Finalized.Round {
				return left.Finalized.Round < right.Finalized.Round
			}
			if left.Finalized.TxIndex != right.Finalized.TxIndex {
				return left.Finalized.TxIndex < right.Finalized.TxIndex
			}
		}
		return left.TxID < right.TxID
	})
	return out
}

func (c *Chain) GetPendingTransactions() []PendingTransaction {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]PendingTransaction, 0, len(c.mempool))
	for _, tx := range c.mempool {
		txID := tx.ID()
		copied := tx
		out = append(out, PendingTransaction{
			TxID:        txID,
			AddedHeight: c.mempoolAddedHeight[txID],
			Transaction: copied,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].AddedHeight != out[j].AddedHeight {
			return out[i].AddedHeight < out[j].AddedHeight
		}
		if out[i].Transaction.Timestamp != out[j].Transaction.Timestamp {
			return out[i].Transaction.Timestamp < out[j].Transaction.Timestamp
		}
		return out[i].TxID < out[j].TxID
	})
	return out
}

func (c *Chain) rebuildTxIndexLocked() {
	c.txIndex = make(map[string]txIndexRecord)
	for _, block := range c.blocks {
		c.indexFinalizedBlockTxsLocked(block)
	}
}

func (c *Chain) indexFinalizedBlockTxsLocked(block Block) {
	for idx, tx := range block.Transactions {
		txID := tx.ID()
		c.txIndex[txID] = txIndexRecord{
			Location: FinalizedTxLocation{
				Height:    block.Height,
				Round:     block.Round,
				BlockHash: block.Hash,
				Timestamp: block.Timestamp,
				TxIndex:   idx,
			},
			Tx: tx,
		}
	}
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
	if tx.Timestamp <= 0 {
		return errors.New("timestamp must be > 0")
	}
	if tx.Nonce == 0 {
		return errors.New("nonce must be > 0")
	}
	kind := tx.txKind()
	switch kind {
	case TxKindTransfer:
		if tx.To == "" {
			return errors.New("missing to")
		}
		if tx.From == tx.To {
			return errors.New("from and to cannot be equal")
		}
		if tx.Amount == 0 {
			return errors.New("amount must be > 0")
		}
	case TxKindValidatorBond, TxKindValidatorUnbond:
		if tx.ValidatorID == "" {
			return errors.New("missing validatorId")
		}
		if tx.Amount == 0 {
			return errors.New("amount must be > 0")
		}
		if tx.BasisPoints != 0 {
			return errors.New("basisPoints is not supported for this tx kind")
		}
	case TxKindValidatorSlash:
		if tx.ValidatorID == "" {
			return errors.New("missing validatorId")
		}
		if tx.BasisPoints == 0 || tx.BasisPoints > 10_000 {
			return ErrInvalidSlashBasis
		}
		if tx.Amount != 0 {
			return errors.New("amount is not supported for slash tx")
		}
	case TxKindValidatorJail:
		if tx.ValidatorID == "" {
			return errors.New("missing validatorId")
		}
		if tx.Amount != 0 {
			return errors.New("amount is not supported for jail tx")
		}
		if tx.BasisPoints != 0 {
			return errors.New("basisPoints is not supported for jail tx")
		}
	case TxKindValidatorUnjail:
		if tx.ValidatorID == "" {
			return errors.New("missing validatorId")
		}
		if tx.Amount != 0 {
			return errors.New("amount is not supported for unjail tx")
		}
		if tx.BasisPoints != 0 {
			return errors.New("basisPoints is not supported for unjail tx")
		}
	case TxKindDelegate, TxKindUndelegate:
		if tx.ValidatorID == "" {
			return errors.New("missing validatorId")
		}
		if tx.Amount == 0 {
			return errors.New("amount must be > 0")
		}
		if tx.BasisPoints != 0 {
			return errors.New("basisPoints is not supported for delegation tx")
		}
	case TxKindProductSettle:
		if tx.Amount == 0 {
			return errors.New("amount must be > 0")
		}
		if tx.To == "" {
			return ErrInvalidProductProofRef
		}
		if tx.BasisPoints != 0 {
			return errors.New("basisPoints is not supported for product settle tx")
		}
	case TxKindProductAttest:
		if tx.ValidatorID == "" {
			return errors.New("missing validatorId")
		}
		if tx.Amount == 0 {
			return errors.New("amount must be > 0")
		}
		if tx.To == "" {
			return ErrInvalidProductProofRef
		}
		if tx.BasisPoints == 0 || tx.BasisPoints > 10_000 {
			return ErrInvalidSlashBasis
		}
	case TxKindProductChallenge:
		if tx.Amount == 0 {
			return errors.New("amount must be > 0")
		}
		if tx.To == "" {
			return ErrInvalidProductProofRef
		}
		if tx.ValidatorID != "" {
			return errors.New("validatorId is not supported for product challenge tx")
		}
		if tx.BasisPoints != 0 {
			return errors.New("basisPoints is not supported for product challenge tx")
		}
	case TxKindProductResolveChallenge:
		if tx.To == "" {
			return errors.New("missing challenge id in to field")
		}
		if tx.BasisPoints > 10_000 {
			return ErrInvalidSlashBasis
		}
		if tx.BasisPoints == 0 && tx.Amount != 0 {
			return errors.New("amount must be 0 when basisPoints is 0 for product resolve tx")
		}
		if tx.ValidatorID != "" {
			return errors.New("validatorId is not supported for product resolve tx")
		}
	default:
		return fmt.Errorf("unsupported transaction kind %q", tx.Kind)
	}
	if err := VerifyTransactionSignature(tx); err != nil {
		return fmt.Errorf("invalid tx signature: %w", err)
	}
	return nil
}

func applyTx(
	state map[Address]*Account,
	validators map[string]*Validator,
	delegations map[string]*Delegation,
	product *productExecutionState,
	tx Transaction,
	evalHeight uint64,
	minJailBlocks uint64,
	currentEpoch uint64,
	productChallengeMinBond uint64,
	productOracleQuorumBps uint64,
	productChallengeResolveDelayBlocks uint64,
	productAttestationTTLBlocks uint64,
	productChallengeMaxOpenBlocks uint64,
) error {
	if product == nil {
		return errors.New("product execution state is required")
	}
	if product.SettlementRefs == nil {
		product.SettlementRefs = make(map[string]string)
	}
	from, ok := state[tx.From]
	if !ok {
		return fmt.Errorf("sender account %s does not exist", tx.From)
	}
	if from.Nonce+1 != tx.Nonce {
		return fmt.Errorf("bad nonce for %s: expected %d got %d", tx.From, from.Nonce+1, tx.Nonce)
	}
	expireProductStateAtHeight(product, evalHeight, tx.Timestamp)
	kind := tx.txKind()

	switch kind {
	case TxKindTransfer:
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
	case TxKindValidatorBond:
		validator, ok := validators[tx.ValidatorID]
		if !ok {
			return fmt.Errorf("validator %q not found", tx.ValidatorID)
		}
		if validator.Address != tx.From {
			return fmt.Errorf("bond tx signer %s does not match validator %s address %s", tx.From, tx.ValidatorID, validator.Address)
		}
		cost := tx.Amount + tx.Fee
		if from.Balance < cost {
			return fmt.Errorf("insufficient balance for %s", tx.From)
		}
		newStake := validator.Stake + tx.Amount
		if newStake < validator.Stake {
			return errors.New("stake overflow")
		}
		from.Balance -= cost
		from.Nonce++
		validator.Stake = newStake
		return nil
	case TxKindValidatorUnbond:
		validator, ok := validators[tx.ValidatorID]
		if !ok {
			return fmt.Errorf("validator %q not found", tx.ValidatorID)
		}
		if validator.Address != tx.From {
			return fmt.Errorf("unbond tx signer %s does not match validator %s address %s", tx.From, tx.ValidatorID, validator.Address)
		}
		if validator.Stake < tx.Amount {
			return fmt.Errorf("insufficient validator stake: have=%d need=%d", validator.Stake, tx.Amount)
		}
		if from.Balance < tx.Fee {
			return fmt.Errorf("insufficient balance for %s fee payment", tx.From)
		}
		newBalance := from.Balance - tx.Fee + tx.Amount
		if newBalance < from.Balance-tx.Fee {
			return errors.New("balance overflow")
		}
		validator.Stake -= tx.Amount
		from.Balance = newBalance
		from.Nonce++
		return nil
	case TxKindValidatorSlash:
		validator, ok := validators[tx.ValidatorID]
		if !ok {
			return fmt.Errorf("validator %q not found", tx.ValidatorID)
		}
		if validator.Address != tx.From {
			return fmt.Errorf("slash tx signer %s does not match validator %s address %s", tx.From, tx.ValidatorID, validator.Address)
		}
		if from.Balance < tx.Fee {
			return fmt.Errorf("insufficient balance for %s fee payment", tx.From)
		}
		slashed := (validator.Stake * tx.BasisPoints) / 10_000
		if slashed == 0 && validator.Stake > 0 {
			slashed = 1
		}
		if slashed > validator.Stake {
			slashed = validator.Stake
		}
		validator.Stake -= slashed
		from.Balance -= tx.Fee
		from.Nonce++
		return nil
	case TxKindValidatorJail:
		validator, ok := validators[tx.ValidatorID]
		if !ok {
			return fmt.Errorf("validator %q not found", tx.ValidatorID)
		}
		if validator.Address != tx.From {
			return fmt.Errorf("jail tx signer %s does not match validator %s address %s", tx.From, tx.ValidatorID, validator.Address)
		}
		if from.Balance < tx.Fee {
			return fmt.Errorf("insufficient balance for %s fee payment", tx.From)
		}
		validator.Jailed = true
		releaseHeight := addClampUint64(evalHeight, minJailBlocks)
		if releaseHeight > validator.JailedUntilHeight {
			validator.JailedUntilHeight = releaseHeight
		}
		from.Balance -= tx.Fee
		from.Nonce++
		return nil
	case TxKindValidatorUnjail:
		validator, ok := validators[tx.ValidatorID]
		if !ok {
			return fmt.Errorf("validator %q not found", tx.ValidatorID)
		}
		if validator.Address != tx.From {
			return fmt.Errorf("unjail tx signer %s does not match validator %s address %s", tx.From, tx.ValidatorID, validator.Address)
		}
		if from.Balance < tx.Fee {
			return fmt.Errorf("insufficient balance for %s fee payment", tx.From)
		}
		if !validator.Jailed {
			return fmt.Errorf("validator %q is not jailed", tx.ValidatorID)
		}
		if evalHeight < validator.JailedUntilHeight {
			return fmt.Errorf("%w: validator=%s releaseHeight=%d currentHeight=%d", ErrValidatorStillJailed, tx.ValidatorID, validator.JailedUntilHeight, evalHeight)
		}
		validator.Jailed = false
		validator.JailedUntilHeight = 0
		from.Balance -= tx.Fee
		from.Nonce++
		return nil
	case TxKindDelegate:
		if _, ok := validators[tx.ValidatorID]; !ok {
			return fmt.Errorf("validator %q not found", tx.ValidatorID)
		}
		cost := tx.Amount + tx.Fee
		if from.Balance < cost {
			return fmt.Errorf("insufficient balance for %s", tx.From)
		}
		key := delegationKey(tx.From, tx.ValidatorID)
		existing := delegations[key]
		if existing == nil {
			existing = &Delegation{
				Delegator:   tx.From,
				ValidatorID: tx.ValidatorID,
			}
			delegations[key] = existing
		}
		newAmount := existing.Amount + tx.Amount
		if newAmount < existing.Amount {
			return errors.New("delegation overflow")
		}
		existing.Amount = newAmount
		from.Balance -= cost
		from.Nonce++
		return nil
	case TxKindUndelegate:
		if _, ok := validators[tx.ValidatorID]; !ok {
			return fmt.Errorf("validator %q not found", tx.ValidatorID)
		}
		if from.Balance < tx.Fee {
			return fmt.Errorf("insufficient balance for %s fee payment", tx.From)
		}
		key := delegationKey(tx.From, tx.ValidatorID)
		existing := delegations[key]
		if existing == nil || existing.Amount < tx.Amount {
			have := uint64(0)
			if existing != nil {
				have = existing.Amount
			}
			return fmt.Errorf("insufficient delegated stake: have=%d need=%d", have, tx.Amount)
		}
		newBalance := from.Balance - tx.Fee + tx.Amount
		if newBalance < from.Balance-tx.Fee {
			return errors.New("balance overflow")
		}
		existing.Amount -= tx.Amount
		if existing.Amount == 0 {
			delete(delegations, key)
		}
		from.Balance = newBalance
		from.Nonce++
		return nil
	case TxKindProductSettle:
		if tx.Amount == 0 {
			return ErrInvalidAmount
		}
		if tx.To == "" {
			return ErrInvalidProductProofRef
		}
		if tx.ValidatorID != "" {
			if _, ok := validators[tx.ValidatorID]; !ok {
				return fmt.Errorf("validator %q not found", tx.ValidatorID)
			}
		}
		cost := tx.Amount + tx.Fee
		if from.Balance < cost {
			return fmt.Errorf("insufficient balance for %s", tx.From)
		}
		settlementRefKey := settlementReferenceKey(tx.From, string(tx.To))
		if existingSettlementID, exists := product.SettlementRefs[settlementRefKey]; exists && existingSettlementID != "" {
			return fmt.Errorf("%w: payer=%s reference=%s settlementId=%s", ErrProductSettlementDuplicate, tx.From, tx.To, existingSettlementID)
		}
		nextTreasury := product.TreasuryBalance + tx.Amount
		if nextTreasury < product.TreasuryBalance {
			return errors.New("product treasury overflow")
		}
		from.Balance -= cost
		from.Nonce++
		product.TreasuryBalance = nextTreasury
		settlementID := tx.ID()
		product.Settlements[settlementID] = &ProductSettlement{
			ID:          settlementID,
			Payer:       tx.From,
			Reference:   string(tx.To),
			ValidatorID: tx.ValidatorID,
			Amount:      tx.Amount,
			Epoch:       currentEpoch,
			Timestamp:   tx.Timestamp,
		}
		product.SettlementRefs[settlementRefKey] = settlementID
		return nil
	case TxKindProductAttest:
		oracleValidatorID, oracleStake, authorized := oracleEffectiveStakeByAddress(validators, delegations, tx.From)
		if !authorized || oracleStake == 0 {
			return ErrOracleUnauthorized
		}
		validator, ok := validators[tx.ValidatorID]
		if !ok {
			return fmt.Errorf("validator %q not found", tx.ValidatorID)
		}
		if tx.BasisPoints == 0 || tx.BasisPoints > 10_000 {
			return ErrInvalidSlashBasis
		}
		if tx.To == "" {
			return ErrInvalidProductProofRef
		}
		if from.Balance < tx.Fee {
			return fmt.Errorf("insufficient balance for %s fee payment", tx.From)
		}
		score := productSignalScore(tx.Amount, tx.BasisPoints)
		if score == 0 {
			score = 1
		}
		proofID := productProofID(string(tx.To), tx.ValidatorID, tx.Amount, tx.BasisPoints, currentEpoch)
		if _, exists := product.Proofs[proofID]; exists {
			return fmt.Errorf("%w: %s", ErrProductProofAlreadyFinalized, proofID)
		}
		pending := product.PendingAttestations[proofID]
		if pending == nil {
			requiredStake, _ := oracleQuorumStake(validators, delegations, productOracleQuorumBps)
			if requiredStake == 0 {
				return ErrOracleUnauthorized
			}
			pending = &ProductPendingAttestation{
				ID:             proofID,
				ProofRef:       string(tx.To),
				ValidatorID:    tx.ValidatorID,
				Units:          tx.Amount,
				QualityBps:     tx.BasisPoints,
				Score:          score,
				Epoch:          currentEpoch,
				RequiredStake:  requiredStake,
				CollectedStake: 0,
				CreatedHeight:  evalHeight,
				ExpiresHeight:  addClampUint64(evalHeight, productAttestationTTLBlocks),
				CreatedMs:      tx.Timestamp,
				LastUpdatedMs:  tx.Timestamp,
			}
		}
		if pending.ProofRef != string(tx.To) ||
			pending.ValidatorID != tx.ValidatorID ||
			pending.Units != tx.Amount ||
			pending.QualityBps != tx.BasisPoints ||
			pending.Epoch != currentEpoch {
			return fmt.Errorf("%w: pending attestation mismatch for proof %s", ErrInvalidProductProofRef, proofID)
		}
		for _, vote := range pending.Votes {
			if vote.Oracle == tx.From {
				return fmt.Errorf("%w: proof=%s oracle=%s", ErrProductAttestationDuplicateVote, proofID, tx.From)
			}
		}

		pending.Votes = append(pending.Votes, ProductAttestationVote{
			Oracle:            tx.From,
			OracleValidatorID: oracleValidatorID,
			Stake:             oracleStake,
			Timestamp:         tx.Timestamp,
		})
		pending.CollectedStake = addClampUint64(pending.CollectedStake, oracleStake)
		pending.LastUpdatedMs = tx.Timestamp
		product.PendingAttestations[proofID] = pending

		from.Balance -= tx.Fee
		from.Nonce++

		if pending.CollectedStake < pending.RequiredStake {
			return nil
		}
		product.Proofs[proofID] = &ProductProof{
			ID:            proofID,
			ProofRef:      pending.ProofRef,
			Reporter:      tx.From,
			ValidatorID:   tx.ValidatorID,
			Units:         tx.Amount,
			QualityBps:    tx.BasisPoints,
			Score:         score,
			Epoch:         currentEpoch,
			Timestamp:     tx.Timestamp,
			Attestations:  uint64(len(pending.Votes)),
			AttestedStake: pending.CollectedStake,
		}
		delete(product.PendingAttestations, proofID)
		product.SignalScore[tx.ValidatorID] = addClampUint64(product.SignalScore[tx.ValidatorID], score)

		targetWeight := uint64(50 + (tx.BasisPoints*150)/10_000)
		if targetWeight == 0 {
			targetWeight = 1
		}
		currentWeight := validator.WorkWeight
		if currentWeight == 0 {
			currentWeight = 100
		}
		validator.WorkWeight = (currentWeight*3 + targetWeight) / 4
		if validator.WorkWeight == 0 {
			validator.WorkWeight = 1
		}
		return nil
	case TxKindProductChallenge:
		if tx.To == "" {
			return ErrInvalidProductProofRef
		}
		if tx.Amount < productChallengeMinBond {
			return fmt.Errorf("%w: got %d want >= %d", ErrProductChallengeBondLow, tx.Amount, productChallengeMinBond)
		}
		if from.Balance < tx.Amount+tx.Fee {
			return fmt.Errorf("insufficient balance for %s", tx.From)
		}
		proofID := string(tx.To)
		proof, ok := product.Proofs[proofID]
		if !ok {
			return fmt.Errorf("%w: %s", ErrUnknownProductProof, proofID)
		}
		if proof.Invalidated {
			return fmt.Errorf("%w: proof %s is already invalidated", ErrProductChallengeClosed, proofID)
		}
		if existingChallengeID, exists := product.OpenChallenges[proofID]; exists && existingChallengeID != "" {
			return fmt.Errorf("%w: proof %s already has open challenge %s", ErrProductChallengeOpen, proofID, existingChallengeID)
		}
		requiredStake, _ := oracleQuorumStake(validators, delegations, productOracleQuorumBps)
		if requiredStake == 0 {
			return ErrOracleUnauthorized
		}
		challengeID := tx.ID()
		proof.Challenged = true
		proof.ChallengeID = challengeID
		product.Proofs[proofID] = proof
		product.Challenges[challengeID] = &ProductChallenge{
			ID:                 challengeID,
			ProofID:            proofID,
			Challenger:         tx.From,
			Bond:               tx.Amount,
			CreatedHeight:      evalHeight,
			ResolveAfterHeight: addClampUint64(evalHeight, productChallengeResolveDelayBlocks),
			MaxOpenHeight:      addClampUint64(evalHeight, productChallengeMaxOpenBlocks),
			RequiredStake:      requiredStake,
			Open:               true,
			CreatedMs:          tx.Timestamp,
		}
		product.OpenChallenges[proofID] = challengeID
		nextTreasury := product.TreasuryBalance + tx.Amount
		if nextTreasury < product.TreasuryBalance {
			return errors.New("product treasury overflow")
		}
		product.TreasuryBalance = nextTreasury
		from.Balance -= tx.Amount + tx.Fee
		from.Nonce++
		return nil
	case TxKindProductResolveChallenge:
		oracleValidatorID, oracleStake, authorized := oracleEffectiveStakeByAddress(validators, delegations, tx.From)
		if !authorized || oracleStake == 0 {
			return ErrOracleUnauthorized
		}
		if tx.To == "" {
			return errors.New("missing challenge id in to field")
		}
		challengeID := string(tx.To)
		challenge, ok := product.Challenges[challengeID]
		if !ok {
			return fmt.Errorf("%w: %s", ErrUnknownProductChallenge, challengeID)
		}
		if !challenge.Open {
			return fmt.Errorf("%w: %s", ErrProductChallengeClosed, challengeID)
		}
		if challenge.ResolveAfterHeight > 0 && evalHeight < challenge.ResolveAfterHeight {
			return fmt.Errorf("%w: challenge=%s resolveAfterHeight=%d currentHeight=%d", ErrProductChallengeTooEarly, challengeID, challenge.ResolveAfterHeight, evalHeight)
		}
		if from.Balance < tx.Fee {
			return fmt.Errorf("insufficient balance for %s fee payment", tx.From)
		}
		proof, ok := product.Proofs[challenge.ProofID]
		if !ok {
			return fmt.Errorf("%w: %s", ErrUnknownProductProof, challenge.ProofID)
		}
		updatedChallenge := *challenge
		if len(challenge.Votes) > 0 {
			updatedChallenge.Votes = append([]ProductChallengeVote(nil), challenge.Votes...)
		}
		for _, vote := range updatedChallenge.Votes {
			if vote.Oracle == tx.From {
				return fmt.Errorf("%w: challenge=%s oracle=%s", ErrProductChallengeDuplicateVote, challengeID, tx.From)
			}
		}
		if updatedChallenge.RequiredStake == 0 {
			requiredStake, _ := oracleQuorumStake(validators, delegations, productOracleQuorumBps)
			if requiredStake == 0 {
				return ErrOracleUnauthorized
			}
			updatedChallenge.RequiredStake = requiredStake
		}

		approve := tx.BasisPoints > 0
		if approve {
			if updatedChallenge.SlashBasisPoints == 0 {
				updatedChallenge.SlashBasisPoints = tx.BasisPoints
				updatedChallenge.BonusPayout = tx.Amount
			} else if updatedChallenge.SlashBasisPoints != tx.BasisPoints || updatedChallenge.BonusPayout != tx.Amount {
				return fmt.Errorf("%w: expected slashBasisPoints=%d bonus=%d got slashBasisPoints=%d bonus=%d", ErrProductChallengeVoteMismatch, updatedChallenge.SlashBasisPoints, updatedChallenge.BonusPayout, tx.BasisPoints, tx.Amount)
			}
			updatedChallenge.AcceptedStake = addClampUint64(updatedChallenge.AcceptedStake, oracleStake)
		} else {
			updatedChallenge.RejectedStake = addClampUint64(updatedChallenge.RejectedStake, oracleStake)
		}
		updatedChallenge.Votes = append(updatedChallenge.Votes, ProductChallengeVote{
			Oracle:            tx.From,
			OracleValidatorID: oracleValidatorID,
			Approve:           approve,
			Stake:             oracleStake,
			Timestamp:         tx.Timestamp,
			SlashBasisPoints:  tx.BasisPoints,
			BonusPayout:       tx.Amount,
		})

		finalizeAccept := updatedChallenge.AcceptedStake >= updatedChallenge.RequiredStake
		finalizeReject := updatedChallenge.RejectedStake >= updatedChallenge.RequiredStake
		if finalizeAccept {
			validator, ok := validators[proof.ValidatorID]
			if !ok {
				return fmt.Errorf("validator %q not found", proof.ValidatorID)
			}
			bonus := updatedChallenge.BonusPayout
			payout := addClampUint64(updatedChallenge.Bond, bonus)
			if product.TreasuryBalance < payout {
				return fmt.Errorf("%w: treasury=%d payout=%d", ErrProductTreasuryFunds, product.TreasuryBalance, payout)
			}
			slashed := (validator.Stake * updatedChallenge.SlashBasisPoints) / 10_000
			if slashed == 0 && validator.Stake > 0 {
				slashed = 1
			}
			if slashed > validator.Stake {
				slashed = validator.Stake
			}
			validator.Stake -= slashed
			validator.Jailed = true
			releaseHeight := addClampUint64(evalHeight, minJailBlocks)
			if releaseHeight > validator.JailedUntilHeight {
				validator.JailedUntilHeight = releaseHeight
			}
			if !proof.Invalidated {
				proof.Invalidated = true
				product.Proofs[updatedChallenge.ProofID] = proof
				if proof.Epoch == currentEpoch {
					currentScore := product.SignalScore[proof.ValidatorID]
					if currentScore <= proof.Score {
						delete(product.SignalScore, proof.ValidatorID)
					} else {
						product.SignalScore[proof.ValidatorID] = currentScore - proof.Score
					}
				}
			}
			challengerAccount, ok := state[updatedChallenge.Challenger]
			if !ok {
				challengerAccount = &Account{}
				state[updatedChallenge.Challenger] = challengerAccount
			}
			nextBalance := challengerAccount.Balance + payout
			if nextBalance < challengerAccount.Balance {
				return errors.New("challenger balance overflow")
			}
			challengerAccount.Balance = nextBalance
			product.TreasuryBalance -= payout
			updatedChallenge.Open = false
			updatedChallenge.Successful = true
			updatedChallenge.Resolver = tx.From
			updatedChallenge.ResolvedMs = tx.Timestamp
		} else if finalizeReject {
			updatedChallenge.Open = false
			updatedChallenge.Successful = false
			updatedChallenge.Resolver = tx.From
			updatedChallenge.ResolvedMs = tx.Timestamp
			updatedChallenge.SlashBasisPoints = 0
			updatedChallenge.BonusPayout = 0
		}

		product.Challenges[challengeID] = &updatedChallenge
		if !updatedChallenge.Open {
			delete(product.OpenChallenges, updatedChallenge.ProofID)
		}
		from.Balance -= tx.Fee
		from.Nonce++
		return nil
	default:
		return fmt.Errorf("unsupported transaction kind %q", tx.Kind)
	}
}

func (c *Chain) selectProposerLocked(height uint64, prevHash string, round uint64) (string, error) {
	total := c.totalEffectiveStakeLocked()
	if total == 0 {
		return "", errors.New("no active effective stake")
	}

	seedInput := fmt.Sprintf("%s:%d", prevHash, height)
	if round > 0 {
		seedInput = fmt.Sprintf("%s:%d:%d", prevHash, height, round)
	}
	seed := sha256.Sum256([]byte(seedInput))
	pick := binary.BigEndian.Uint64(seed[:8]) % total

	var cursor uint64
	for _, id := range c.validatorOrder {
		effective := c.effectiveStakeByIDLocked(id)
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
		total = addClampUint64(total, c.epochEffectiveStake[id])
	}
	return total
}

func (c *Chain) effectiveStake(v *Validator, delegated uint64) uint64 {
	if v == nil || !v.Active || v.Jailed || v.WorkWeight == 0 {
		return 0
	}
	totalStake := addClampUint64(v.Stake, delegated)
	if totalStake == 0 {
		return 0
	}
	product := totalStake * v.WorkWeight
	if v.WorkWeight != 0 && product/v.WorkWeight != totalStake {
		product = ^uint64(0)
	}
	effective := product / 100
	if effective == 0 {
		return 1
	}
	return effective
}

func (c *Chain) effectiveStakeByIDLocked(validatorID string) uint64 {
	return c.epochEffectiveStake[validatorID]
}

func (c *Chain) delegatedStakeForValidatorLocked(validatorID string) uint64 {
	var delegated uint64
	for _, delegation := range c.delegations {
		if delegation == nil || delegation.ValidatorID != validatorID || delegation.Amount == 0 {
			continue
		}
		delegated = addClampUint64(delegated, delegation.Amount)
	}
	return delegated
}

func (c *Chain) sortedDelegationKeysLocked() []string {
	keys := make([]string, 0, len(c.delegations))
	for key := range c.delegations {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (c *Chain) collectVotesLocked(block Block) ([]Vote, uint64, uint64) {
	votes := make([]Vote, 0, len(c.validators))
	var yesStake uint64
	var totalStake uint64

	for _, id := range c.validatorOrder {
		validator := c.validators[id]
		effective := c.effectiveStakeByIDLocked(id)
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
	if v == nil || !v.Active || v.Jailed {
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
	expectedProposer, err := c.selectProposerLocked(block.Height, block.PrevHash, block.Round)
	if err != nil || block.Proposer != expectedProposer {
		return false
	}
	if block.Hash != c.hashBlock(block) {
		return false
	}

	working := c.cloneAccounts(c.accounts)
	workingValidators := c.cloneValidators(c.validators)
	workingDelegations := c.cloneDelegations(c.delegations)
	workingProduct := c.cloneProductExecutionStateLocked()
	workingEpoch := c.currentEpoch
	expireProductStateAtHeight(workingProduct, block.Height, block.Timestamp)
	var fees uint64
	for _, tx := range block.Transactions {
		if err := c.validateTxBasic(tx); err != nil {
			return false
		}
		if err := applyTx(working, workingValidators, workingDelegations, workingProduct, tx, block.Height, c.minJailBlocks, workingEpoch, c.productChallengeMinBond, c.productOracleQuorumBps, c.productChallengeResolveDelayBlocks, c.productAttestationTTLBlocks, c.productChallengeMaxOpenBlocks); err != nil {
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
	if err := c.applyEpochTransitionIfNeededLocked(block.Height, working, workingValidators, workingDelegations, workingProduct, &workingEpoch); err != nil {
		return false
	}

	return c.computeStateRoot(working, workingValidators, workingDelegations, workingProduct, workingEpoch) == block.StateRoot
}

func (c *Chain) validateVotesLocked(votes []Vote) (yesStake uint64, totalStake uint64, err error) {
	totalStake = c.totalEffectiveStakeLocked()
	if totalStake == 0 {
		return 0, 0, ErrNoValidators
	}
	if len(votes) == 0 {
		return 0, totalStake, nil
	}

	seen := make(map[string]struct{}, len(votes))
	for _, vote := range votes {
		if vote.ValidatorID == "" {
			return 0, 0, errors.New("vote has empty validator id")
		}
		if _, dup := seen[vote.ValidatorID]; dup {
			return 0, 0, fmt.Errorf("duplicate vote from validator %s", vote.ValidatorID)
		}
		seen[vote.ValidatorID] = struct{}{}

		_, ok := c.validators[vote.ValidatorID]
		if !ok {
			return 0, 0, fmt.Errorf("vote from unknown validator %s", vote.ValidatorID)
		}
		effective := c.effectiveStakeByIDLocked(vote.ValidatorID)
		if effective == 0 {
			return 0, 0, fmt.Errorf("vote from validator %s with zero effective stake", vote.ValidatorID)
		}
		if vote.EffectiveStake != effective {
			return 0, 0, fmt.Errorf("vote effective stake mismatch for %s: got %d want %d", vote.ValidatorID, vote.EffectiveStake, effective)
		}
		if vote.Approved {
			yesStake += effective
		}
	}
	return yesStake, totalStake, nil
}

func (c *Chain) applyBlockToStateLocked(block Block) (map[Address]*Account, map[string]*Validator, map[string]*Delegation, *productExecutionState, uint64, map[string]struct{}, uint64, error) {
	if len(c.blocks) == 0 {
		return nil, nil, nil, nil, 0, nil, 0, errors.New("chain has no genesis block")
	}
	if block.Height != uint64(len(c.blocks)) {
		return nil, nil, nil, nil, 0, nil, 0, fmt.Errorf("%w: block height %d current %d", ErrUnexpectedHeight, block.Height, len(c.blocks))
	}
	expectedPrevHash := c.blocks[len(c.blocks)-1].Hash
	if block.PrevHash != expectedPrevHash {
		return nil, nil, nil, nil, 0, nil, 0, fmt.Errorf("invalid prev hash: got %s want %s", block.PrevHash, expectedPrevHash)
	}
	expectedTimestamp := c.nextBlockTimestampLocked()
	if block.Timestamp != expectedTimestamp {
		return nil, nil, nil, nil, 0, nil, 0, fmt.Errorf("invalid block timestamp: got %d want %d", block.Timestamp, expectedTimestamp)
	}
	if block.Hash != c.hashBlock(block) {
		return nil, nil, nil, nil, 0, nil, 0, errors.New("invalid block hash")
	}

	working := c.cloneAccounts(c.accounts)
	workingValidators := c.cloneValidators(c.validators)
	workingDelegations := c.cloneDelegations(c.delegations)
	workingProduct := c.cloneProductExecutionStateLocked()
	workingEpoch := c.currentEpoch
	expireProductStateAtHeight(workingProduct, block.Height, block.Timestamp)
	includedIDs := make(map[string]struct{}, len(block.Transactions))
	var fees uint64

	for _, tx := range block.Transactions {
		if err := c.validateTxBasic(tx); err != nil {
			return nil, nil, nil, nil, 0, nil, 0, fmt.Errorf("invalid block transaction: %w", err)
		}
		if err := applyTx(working, workingValidators, workingDelegations, workingProduct, tx, block.Height, c.minJailBlocks, workingEpoch, c.productChallengeMinBond, c.productOracleQuorumBps, c.productChallengeResolveDelayBlocks, c.productAttestationTTLBlocks, c.productChallengeMaxOpenBlocks); err != nil {
			return nil, nil, nil, nil, 0, nil, 0, fmt.Errorf("apply block transaction: %w", err)
		}
		includedIDs[tx.ID()] = struct{}{}
		fees += tx.Fee
	}

	proposer, ok := c.validators[block.Proposer]
	if !ok {
		return nil, nil, nil, nil, 0, nil, 0, fmt.Errorf("unknown proposer %q", block.Proposer)
	}
	if _, ok := working[proposer.Address]; !ok {
		working[proposer.Address] = &Account{}
	}
	working[proposer.Address].Balance += c.baseReward + fees

	if err := c.applyEpochTransitionIfNeededLocked(block.Height, working, workingValidators, workingDelegations, workingProduct, &workingEpoch); err != nil {
		return nil, nil, nil, nil, 0, nil, 0, err
	}

	computedStateRoot := c.computeStateRoot(working, workingValidators, workingDelegations, workingProduct, workingEpoch)
	if block.StateRoot != computedStateRoot {
		return nil, nil, nil, nil, 0, nil, 0, fmt.Errorf("state root mismatch: got %s want %s", block.StateRoot, computedStateRoot)
	}

	return working, workingValidators, workingDelegations, workingProduct, workingEpoch, includedIDs, fees, nil
}

func (c *Chain) hashBlock(block Block) string {
	txIDs := make([]string, 0, len(block.Transactions))
	for _, tx := range block.Transactions {
		txIDs = append(txIDs, tx.ID())
	}
	var payload string
	if block.Round == 0 {
		payload = fmt.Sprintf(
			"%d|%s|%d|%s|%s|%s",
			block.Height,
			block.PrevHash,
			block.Timestamp,
			block.Proposer,
			strings.Join(txIDs, ","),
			block.StateRoot,
		)
	} else {
		payload = fmt.Sprintf(
			"%d|%d|%s|%d|%s|%s|%s",
			block.Height,
			block.Round,
			block.PrevHash,
			block.Timestamp,
			block.Proposer,
			strings.Join(txIDs, ","),
			block.StateRoot,
		)
	}
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func (c *Chain) computeStateRoot(state map[Address]*Account, validators map[string]*Validator, delegations map[string]*Delegation, product *productExecutionState, currentEpoch uint64) string {
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

	validatorIDs := make([]string, 0, len(validators))
	for id := range validators {
		validatorIDs = append(validatorIDs, id)
	}
	sort.Strings(validatorIDs)
	b.WriteString("|validators|")
	for _, id := range validatorIDs {
		v := validators[id]
		if v == nil {
			continue
		}
		b.WriteString(id)
		b.WriteString(":")
		b.WriteString(fmt.Sprintf("%s:%d:%d:%t:%t:%d;", v.Address, v.Stake, v.WorkWeight, v.Active, v.Jailed, v.JailedUntilHeight))
	}
	b.WriteString("|delegations|")
	delegationKeys := make([]string, 0, len(delegations))
	for key := range delegations {
		delegationKeys = append(delegationKeys, key)
	}
	sort.Strings(delegationKeys)
	for _, key := range delegationKeys {
		delegation := delegations[key]
		if delegation == nil {
			continue
		}
		b.WriteString(string(delegation.Delegator))
		b.WriteString(":")
		b.WriteString(delegation.ValidatorID)
		b.WriteString(":")
		b.WriteString(fmt.Sprintf("%d;", delegation.Amount))
	}
	b.WriteString("|epoch|")
	b.WriteString(fmt.Sprintf("%d;", currentEpoch))
	b.WriteString("|product|")
	if product != nil {
		b.WriteString(fmt.Sprintf(
			"treasury:%d;rewardBps:%d;challengeMinBond:%d;oracleQuorumBps:%d;challengeResolveDelay:%d;attestationTTL:%d;challengeMaxOpen:%d;lastRewardEpoch:%d;",
			product.TreasuryBalance,
			c.productRewardBps,
			c.productChallengeMinBond,
			c.productOracleQuorumBps,
			c.productChallengeResolveDelayBlocks,
			c.productAttestationTTLBlocks,
			c.productChallengeMaxOpenBlocks,
			product.LastRewardEpoch,
		))
		rewardIDs := make([]string, 0, len(product.LastRewards))
		for validatorID := range product.LastRewards {
			rewardIDs = append(rewardIDs, validatorID)
		}
		sort.Strings(rewardIDs)
		b.WriteString("lastRewards:")
		for _, validatorID := range rewardIDs {
			b.WriteString(fmt.Sprintf("%s=%d,", validatorID, product.LastRewards[validatorID]))
		}

		scoreIDs := make([]string, 0, len(product.SignalScore))
		for validatorID := range product.SignalScore {
			scoreIDs = append(scoreIDs, validatorID)
		}
		sort.Strings(scoreIDs)
		b.WriteString(";signal:")
		for _, validatorID := range scoreIDs {
			b.WriteString(fmt.Sprintf("%s=%d,", validatorID, product.SignalScore[validatorID]))
		}

		proofIDs := make([]string, 0, len(product.Proofs))
		for id := range product.Proofs {
			proofIDs = append(proofIDs, id)
		}
		sort.Strings(proofIDs)
		b.WriteString(";proofs:")
		for _, id := range proofIDs {
			proof := product.Proofs[id]
			if proof == nil {
				continue
			}
			b.WriteString(fmt.Sprintf(
				"%s:%s:%s:%d:%d:%d:%d:%d:%d:%t:%t:%s;",
				proof.ID,
				proof.Reporter,
				proof.ValidatorID,
				proof.Units,
				proof.QualityBps,
				proof.Score,
				proof.Epoch,
				proof.Attestations,
				proof.AttestedStake,
				proof.Challenged,
				proof.Invalidated,
				proof.ChallengeID,
			))
		}

		pendingIDs := make([]string, 0, len(product.PendingAttestations))
		for id := range product.PendingAttestations {
			pendingIDs = append(pendingIDs, id)
		}
		sort.Strings(pendingIDs)
		b.WriteString(";pendingAttestations:")
		for _, id := range pendingIDs {
			pending := product.PendingAttestations[id]
			if pending == nil {
				continue
			}
			b.WriteString(fmt.Sprintf(
				"%s:%s:%s:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:",
				pending.ID,
				pending.ProofRef,
				pending.ValidatorID,
				pending.Units,
				pending.QualityBps,
				pending.Score,
				pending.Epoch,
				pending.RequiredStake,
				pending.CollectedStake,
				pending.CreatedHeight,
				pending.ExpiresHeight,
				pending.CreatedMs,
				pending.LastUpdatedMs,
			))
			for _, vote := range pending.Votes {
				b.WriteString(fmt.Sprintf("%s:%s:%d:%d,", vote.Oracle, vote.OracleValidatorID, vote.Stake, vote.Timestamp))
			}
			b.WriteString(";")
		}

		challengeIDs := make([]string, 0, len(product.Challenges))
		for id := range product.Challenges {
			challengeIDs = append(challengeIDs, id)
		}
		sort.Strings(challengeIDs)
		b.WriteString(";challenges:")
		for _, id := range challengeIDs {
			challenge := product.Challenges[id]
			if challenge == nil {
				continue
			}
			b.WriteString(fmt.Sprintf(
				"%s:%s:%s:%d:%d:%d:%d:%d:%d:%d:%t:%t:%s:%d:%d:%d:%d:",
				challenge.ID,
				challenge.ProofID,
				challenge.Challenger,
				challenge.Bond,
				challenge.CreatedHeight,
				challenge.ResolveAfterHeight,
				challenge.MaxOpenHeight,
				challenge.RequiredStake,
				challenge.AcceptedStake,
				challenge.RejectedStake,
				challenge.Open,
				challenge.Successful,
				challenge.Resolver,
				challenge.SlashBasisPoints,
				challenge.BonusPayout,
				challenge.CreatedMs,
				challenge.ResolvedMs,
			))
			for _, vote := range challenge.Votes {
				approveFlag := 0
				if vote.Approve {
					approveFlag = 1
				}
				b.WriteString(fmt.Sprintf(
					"%s:%s:%d:%d:%d:%d:%d,",
					vote.Oracle,
					vote.OracleValidatorID,
					approveFlag,
					vote.Stake,
					vote.Timestamp,
					vote.SlashBasisPoints,
					vote.BonusPayout,
				))
			}
			b.WriteString(";")
		}

		settlementIDs := make([]string, 0, len(product.Settlements))
		for id := range product.Settlements {
			settlementIDs = append(settlementIDs, id)
		}
		sort.Strings(settlementIDs)
		b.WriteString(";settlements:")
		for _, id := range settlementIDs {
			settlement := product.Settlements[id]
			if settlement == nil {
				continue
			}
			b.WriteString(fmt.Sprintf("%s:%s:%s:%s:%d:%d:%d;", settlement.ID, settlement.Payer, settlement.Reference, settlement.ValidatorID, settlement.Amount, settlement.Epoch, settlement.Timestamp))
		}
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

func (c *Chain) cloneValidators(src map[string]*Validator) map[string]*Validator {
	cloned := make(map[string]*Validator, len(src))
	for id, v := range src {
		copied := *v
		cloned[id] = &copied
	}
	return cloned
}

func (c *Chain) cloneDelegations(src map[string]*Delegation) map[string]*Delegation {
	cloned := make(map[string]*Delegation, len(src))
	for key, delegation := range src {
		if delegation == nil {
			continue
		}
		copied := *delegation
		cloned[key] = &copied
	}
	return cloned
}

type productExecutionState struct {
	TreasuryBalance     uint64
	Proofs              map[string]*ProductProof
	PendingAttestations map[string]*ProductPendingAttestation
	Challenges          map[string]*ProductChallenge
	OpenChallenges      map[string]string
	Settlements         map[string]*ProductSettlement
	SettlementRefs      map[string]string
	SignalScore         map[string]uint64
	LastRewardEpoch     uint64
	LastRewards         map[string]uint64
}

func (c *Chain) cloneProductExecutionStateLocked() *productExecutionState {
	cloned := &productExecutionState{
		TreasuryBalance:     c.productTreasuryBalance,
		Proofs:              make(map[string]*ProductProof, len(c.productProofs)),
		PendingAttestations: make(map[string]*ProductPendingAttestation, len(c.productPendingAttestations)),
		Challenges:          make(map[string]*ProductChallenge, len(c.productChallenges)),
		OpenChallenges:      make(map[string]string, len(c.productOpenChallenges)),
		Settlements:         make(map[string]*ProductSettlement, len(c.productSettlements)),
		SettlementRefs:      make(map[string]string, len(c.productSettlementRefs)),
		SignalScore:         make(map[string]uint64, len(c.productSignalScore)),
		LastRewardEpoch:     c.lastProductRewardEpoch,
		LastRewards:         make(map[string]uint64, len(c.lastProductRewards)),
	}
	for id, proof := range c.productProofs {
		if proof == nil {
			continue
		}
		copied := *proof
		cloned.Proofs[id] = &copied
	}
	for id, pending := range c.productPendingAttestations {
		if pending == nil {
			continue
		}
		copied := *pending
		if len(pending.Votes) > 0 {
			copied.Votes = append([]ProductAttestationVote(nil), pending.Votes...)
		}
		cloned.PendingAttestations[id] = &copied
	}
	for id, challenge := range c.productChallenges {
		if challenge == nil {
			continue
		}
		copied := *challenge
		if len(challenge.Votes) > 0 {
			copied.Votes = append([]ProductChallengeVote(nil), challenge.Votes...)
		}
		cloned.Challenges[id] = &copied
	}
	for proofID, challengeID := range c.productOpenChallenges {
		cloned.OpenChallenges[proofID] = challengeID
	}
	for id, settlement := range c.productSettlements {
		if settlement == nil {
			continue
		}
		copied := *settlement
		cloned.Settlements[id] = &copied
	}
	for key, settlementID := range c.productSettlementRefs {
		cloned.SettlementRefs[key] = settlementID
	}
	for validatorID, score := range c.productSignalScore {
		cloned.SignalScore[validatorID] = score
	}
	for validatorID, reward := range c.lastProductRewards {
		cloned.LastRewards[validatorID] = reward
	}
	return cloned
}

func (c *Chain) sortedProductRewardSliceLocked(values map[string]uint64) []ProductReward {
	validatorIDs := make([]string, 0, len(values))
	for validatorID := range values {
		validatorIDs = append(validatorIDs, validatorID)
	}
	sort.Strings(validatorIDs)
	out := make([]ProductReward, 0, len(validatorIDs))
	for _, validatorID := range validatorIDs {
		out = append(out, ProductReward{
			ValidatorID: validatorID,
			Amount:      values[validatorID],
		})
	}
	return out
}

func (c *Chain) buildEpochStakeSnapshotForState(validators map[string]*Validator, delegations map[string]*Delegation) map[string]uint64 {
	delegatedByValidator := make(map[string]uint64, len(validators))
	for _, delegation := range delegations {
		if delegation == nil || delegation.Amount == 0 {
			continue
		}
		delegatedByValidator[delegation.ValidatorID] = addClampUint64(delegatedByValidator[delegation.ValidatorID], delegation.Amount)
	}
	out := make(map[string]uint64, len(validators))
	for _, id := range c.validatorOrder {
		validator := validators[id]
		out[id] = c.effectiveStake(validator, delegatedByValidator[id])
	}
	return out
}

func (c *Chain) refreshEpochEffectiveStakeLocked() {
	c.epochEffectiveStake = c.buildEpochStakeSnapshotForState(c.validators, c.delegations)
}

func (c *Chain) applyEpochTransitionIfNeededLocked(
	height uint64,
	state map[Address]*Account,
	validators map[string]*Validator,
	delegations map[string]*Delegation,
	product *productExecutionState,
	currentEpoch *uint64,
) error {
	if currentEpoch == nil {
		return errors.New("current epoch pointer is required")
	}
	if c.epochLengthBlocks == 0 {
		return nil
	}
	if height == 0 || height%c.epochLengthBlocks != 0 {
		return nil
	}

	if err := c.distributeProductRewardsAtEpochTransitionLocked(state, validators, product, *currentEpoch); err != nil {
		return err
	}
	c.prunePendingAttestationsAtEpochLocked(product, *currentEpoch)

	*currentEpoch = addClampUint64(*currentEpoch, 1)
	_ = delegations
	return nil
}

func (c *Chain) distributeProductRewardsAtEpochTransitionLocked(
	state map[Address]*Account,
	validators map[string]*Validator,
	product *productExecutionState,
	epoch uint64,
) error {
	if product == nil {
		return errors.New("product execution state is required")
	}
	product.LastRewardEpoch = epoch
	product.LastRewards = make(map[string]uint64)

	totalScore := uint64(0)
	for validatorID, score := range product.SignalScore {
		if score == 0 {
			continue
		}
		if _, ok := validators[validatorID]; !ok {
			continue
		}
		totalScore = addClampUint64(totalScore, score)
	}
	if totalScore == 0 || product.TreasuryBalance == 0 || c.productRewardBps == 0 {
		product.SignalScore = make(map[string]uint64)
		return nil
	}

	payoutPool := (product.TreasuryBalance * c.productRewardBps) / 10_000
	if payoutPool == 0 {
		product.SignalScore = make(map[string]uint64)
		return nil
	}

	remaining := payoutPool
	activeIDs := make([]string, 0, len(product.SignalScore))
	for _, validatorID := range c.validatorOrder {
		score := product.SignalScore[validatorID]
		if score == 0 {
			continue
		}
		if _, ok := validators[validatorID]; !ok {
			continue
		}
		activeIDs = append(activeIDs, validatorID)
	}
	for idx, validatorID := range activeIDs {
		score := product.SignalScore[validatorID]
		reward := (payoutPool * score) / totalScore
		if idx == len(activeIDs)-1 {
			reward = remaining
		}
		if reward == 0 {
			continue
		}
		validator := validators[validatorID]
		if validator == nil {
			continue
		}
		account := state[validator.Address]
		if account == nil {
			account = &Account{}
			state[validator.Address] = account
		}
		nextBalance := account.Balance + reward
		if nextBalance < account.Balance {
			return errors.New("product reward payout overflow")
		}
		account.Balance = nextBalance
		product.LastRewards[validatorID] = reward
		if reward > remaining {
			remaining = 0
		} else {
			remaining -= reward
		}
	}
	distributed := payoutPool - remaining
	if distributed > product.TreasuryBalance {
		distributed = product.TreasuryBalance
	}
	product.TreasuryBalance -= distributed
	product.SignalScore = make(map[string]uint64)
	return nil
}

func (c *Chain) prunePendingAttestationsAtEpochLocked(product *productExecutionState, epoch uint64) {
	if product == nil || len(product.PendingAttestations) == 0 {
		return
	}
	for proofID, pending := range product.PendingAttestations {
		if pending == nil {
			delete(product.PendingAttestations, proofID)
			continue
		}
		if pending.Epoch <= epoch {
			delete(product.PendingAttestations, proofID)
		}
	}
}

func expireProductStateAtHeight(product *productExecutionState, evalHeight uint64, nowMs int64) {
	if product == nil {
		return
	}
	if len(product.PendingAttestations) > 0 {
		for proofID, pending := range product.PendingAttestations {
			if pending == nil {
				delete(product.PendingAttestations, proofID)
				continue
			}
			if pending.ExpiresHeight > 0 && evalHeight >= pending.ExpiresHeight {
				delete(product.PendingAttestations, proofID)
			}
		}
	}
	if len(product.Challenges) > 0 {
		for challengeID, challenge := range product.Challenges {
			if challenge == nil {
				delete(product.Challenges, challengeID)
				continue
			}
			if !challenge.Open {
				continue
			}
			if challenge.MaxOpenHeight == 0 || evalHeight < challenge.MaxOpenHeight {
				continue
			}
			challenge.Open = false
			challenge.Successful = false
			challenge.Resolver = Address("system-timeout")
			if nowMs > 0 {
				challenge.ResolvedMs = nowMs
			} else {
				challenge.ResolvedMs = challenge.CreatedMs
			}
			product.Challenges[challengeID] = challenge
			delete(product.OpenChallenges, challenge.ProofID)
		}
	}
}

func (c *Chain) rebuildMempoolLocked(excluded map[string]struct{}) {
	state := c.cloneAccounts(c.accounts)
	validators := c.cloneValidators(c.validators)
	delegations := c.cloneDelegations(c.delegations)
	product := c.cloneProductExecutionStateLocked()
	nextHeight := uint64(len(c.blocks))
	filtered := make([]Transaction, 0, len(c.mempool))
	nextSet := make(map[string]struct{}, len(c.mempool))
	nextAdded := make(map[string]uint64, len(c.mempool))

	for _, tx := range c.mempool {
		txID := tx.ID()
		if _, skip := excluded[txID]; skip {
			continue
		}
		if c.isTxStaleLocked(txID, nextHeight) {
			c.expiredTxTotal++
			continue
		}
		if err := c.validateTxBasic(tx); err != nil {
			continue
		}
		if err := applyTx(state, validators, delegations, product, tx, nextHeight, c.minJailBlocks, c.currentEpoch, c.productChallengeMinBond, c.productOracleQuorumBps, c.productChallengeResolveDelayBlocks, c.productAttestationTTLBlocks, c.productChallengeMaxOpenBlocks); err != nil {
			continue
		}
		filtered = append(filtered, tx)
		nextSet[txID] = struct{}{}
		added := c.mempoolAddedHeight[txID]
		if added == 0 {
			added = nextHeight
		}
		nextAdded[txID] = added
	}
	c.mempool = filtered
	c.mempoolSet = nextSet
	c.mempoolAddedHeight = nextAdded
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

func (c *Chain) sortedMempoolCandidatesLocked(nextHeight uint64) []Transaction {
	candidates := make([]Transaction, 0, len(c.mempool))
	for _, tx := range c.mempool {
		if c.isTxStaleLocked(tx.ID(), nextHeight) {
			continue
		}
		candidates = append(candidates, tx)
	}
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
		if c.effectiveStakeByIDLocked(id) > 0 {
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
	validators := c.cloneValidators(c.validators)
	delegations := c.cloneDelegations(c.delegations)
	product := c.cloneProductExecutionStateLocked()
	nextHeight := uint64(len(c.blocks))
	for _, tx := range pool {
		if err := c.validateTxBasic(tx); err != nil {
			return false
		}
		if err := applyTx(state, validators, delegations, product, tx, nextHeight, c.minJailBlocks, c.currentEpoch, c.productChallengeMinBond, c.productOracleQuorumBps, c.productChallengeResolveDelayBlocks, c.productAttestationTTLBlocks, c.productChallengeMaxOpenBlocks); err != nil {
			return false
		}
	}
	return true
}

func (c *Chain) pendingCountForAccountLocked(address Address) int {
	nextHeight := uint64(len(c.blocks))
	count := 0
	for _, tx := range c.mempool {
		if tx.From != address {
			continue
		}
		if c.isTxStaleLocked(tx.ID(), nextHeight) {
			continue
		}
		count++
	}
	return count
}

func (c *Chain) pruneStaleMempoolLocked() {
	if c.maxMempoolTxAgeBlocks == 0 {
		return
	}
	if len(c.mempool) == 0 {
		return
	}
	nextHeight := uint64(len(c.blocks))
	filtered := make([]Transaction, 0, len(c.mempool))
	nextSet := make(map[string]struct{}, len(c.mempool))
	nextAdded := make(map[string]uint64, len(c.mempool))
	for _, tx := range c.mempool {
		txID := tx.ID()
		added, ok := c.mempoolAddedHeight[txID]
		if !ok {
			added = nextHeight
		}
		if c.isTxStaleLocked(txID, nextHeight) {
			c.expiredTxTotal++
			continue
		}
		filtered = append(filtered, tx)
		nextSet[txID] = struct{}{}
		nextAdded[txID] = added
	}
	c.mempool = filtered
	c.mempoolSet = nextSet
	c.mempoolAddedHeight = nextAdded
}

func (c *Chain) isTxStaleLocked(txID string, currentHeight uint64) bool {
	if c.maxMempoolTxAgeBlocks == 0 {
		return false
	}
	addedHeight, ok := c.mempoolAddedHeight[txID]
	if !ok {
		return false
	}
	if currentHeight < addedHeight {
		return false
	}
	expireHeight := addClampUint64(addedHeight, c.maxMempoolTxAgeBlocks)
	return currentHeight >= expireHeight
}

func delegationKey(delegator Address, validatorID string) string {
	return fmt.Sprintf("%s|%s", delegator, validatorID)
}

func validatorIDByAddress(validators map[string]*Validator, addr Address) (string, bool) {
	for id, validator := range validators {
		if validator == nil {
			continue
		}
		if validator.Address != addr {
			continue
		}
		if !validator.Active || validator.Jailed {
			return "", false
		}
		return id, true
	}
	return "", false
}

func productProofID(proofRef string, validatorID string, units uint64, qualityBps uint64, epoch uint64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%d|%d", proofRef, validatorID, units, qualityBps, epoch)))
	return hex.EncodeToString(sum[:])
}

func settlementReferenceKey(payer Address, reference string) string {
	return fmt.Sprintf("%s|%s", payer, reference)
}

func delegationTotalsByValidator(delegations map[string]*Delegation) map[string]uint64 {
	totals := make(map[string]uint64)
	for _, delegation := range delegations {
		if delegation == nil || delegation.Amount == 0 {
			continue
		}
		totals[delegation.ValidatorID] = addClampUint64(totals[delegation.ValidatorID], delegation.Amount)
	}
	return totals
}

func effectiveStakeForValidator(v *Validator, delegated uint64) uint64 {
	if v == nil || !v.Active || v.Jailed || v.WorkWeight == 0 {
		return 0
	}
	totalStake := addClampUint64(v.Stake, delegated)
	if totalStake == 0 {
		return 0
	}
	product := totalStake * v.WorkWeight
	if v.WorkWeight != 0 && product/v.WorkWeight != totalStake {
		product = ^uint64(0)
	}
	effective := product / 100
	if effective == 0 {
		return 1
	}
	return effective
}

func quorumStakeRequired(totalStake uint64, quorumBps uint64) uint64 {
	if totalStake == 0 {
		return 0
	}
	if quorumBps == 0 {
		quorumBps = defaultProductOracleQuorumBps
	}
	if quorumBps > 10_000 {
		quorumBps = 10_000
	}
	whole := (totalStake / 10_000) * quorumBps
	rem := (totalStake % 10_000) * quorumBps
	if rem == 0 {
		if whole == 0 {
			return 1
		}
		return whole
	}
	required := addClampUint64(whole, (rem+9_999)/10_000)
	if required == 0 {
		return 1
	}
	return required
}

func oracleQuorumStake(validators map[string]*Validator, delegations map[string]*Delegation, quorumBps uint64) (required uint64, total uint64) {
	delegated := delegationTotalsByValidator(delegations)
	for _, validator := range validators {
		total = addClampUint64(total, effectiveStakeForValidator(validator, delegated[validator.ID]))
	}
	required = quorumStakeRequired(total, quorumBps)
	return required, total
}

func oracleEffectiveStakeByAddress(validators map[string]*Validator, delegations map[string]*Delegation, addr Address) (validatorID string, stake uint64, ok bool) {
	delegated := delegationTotalsByValidator(delegations)
	for id, validator := range validators {
		if validator == nil || validator.Address != addr {
			continue
		}
		stake = effectiveStakeForValidator(validator, delegated[id])
		if stake == 0 {
			return "", 0, false
		}
		return id, stake, true
	}
	return "", 0, false
}

func productSignalScore(units uint64, qualityBps uint64) uint64 {
	if units == 0 || qualityBps == 0 {
		return 0
	}
	score := (units * qualityBps) / 10_000
	if score == 0 {
		return 1
	}
	return score
}

func addClampUint64(a, b uint64) uint64 {
	sum := a + b
	if sum < a {
		return ^uint64(0)
	}
	return sum
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
