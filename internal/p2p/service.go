package p2p

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"fastpos/internal/chain"
)

var (
	ErrP2PDisabled        = errors.New("p2p service is disabled")
	ErrUnknownSender      = errors.New("unknown sender")
	ErrUnsupportedType    = errors.New("unsupported message type")
	ErrDuplicateMessage   = errors.New("duplicate message")
	ErrOutdatedMessage    = errors.New("outdated message")
	ErrConflictingMessage = errors.New("conflicting message")
	ErrInvalidMessage     = errors.New("invalid message")
	ErrInvalidPeer        = errors.New("invalid peer")
	ErrEvidenceNotFound   = errors.New("equivocation evidence not found")
	ErrEvidenceApplied    = errors.New("equivocation evidence penalty already applied")
)

type Config struct {
	Enabled               bool
	NodeID                string
	ValidatorPrivateKey   string
	ValidatorPubKeys      map[string]string
	Peers                 []string
	PeerDiscoveryInterval time.Duration
	ClientTimeout         time.Duration
	ProposerTimeoutTicks  uint64
	MaxRoundLookahead     uint64
	PeerBackoffInitial    time.Duration
	PeerBackoffMax        time.Duration
	InboundRateLimit      uint64
	InboundRateWindow     time.Duration
	Logf                  func(format string, args ...any)
}

type Stats struct {
	Enabled               bool   `json:"enabled"`
	NodeID                string `json:"nodeId"`
	PeerCount             int    `json:"peerCount"`
	KnownValidators       int    `json:"knownValidators"`
	ReceivedTotal         uint64 `json:"receivedTotal"`
	AcceptedTotal         uint64 `json:"acceptedTotal"`
	RejectedTotal         uint64 `json:"rejectedTotal"`
	DuplicateTotal        uint64 `json:"duplicateTotal"`
	OutdatedTotal         uint64 `json:"outdatedTotal"`
	BroadcastSentTotal    uint64 `json:"broadcastSentTotal"`
	BroadcastErrorTotal   uint64 `json:"broadcastErrorTotal"`
	BroadcastBackoffTotal uint64 `json:"broadcastBackoffTotal"`
	RateLimitedTotal      uint64 `json:"rateLimitedTotal"`
	PeerDiscoveryRuns     uint64 `json:"peerDiscoveryRuns"`
	PeerDiscoveryAdded    uint64 `json:"peerDiscoveryAdded"`
	PeerDiscoveryErrors   uint64 `json:"peerDiscoveryErrors"`
	EquivocationTotal     uint64 `json:"equivocationTotal"`
	EquivocationApplied   uint64 `json:"equivocationApplied"`
	LastAcceptedType      string `json:"lastAcceptedType"`
	LastAcceptedHeight    uint64 `json:"lastAcceptedHeight"`
	LastAcceptedBlockHash string `json:"lastAcceptedBlockHash"`
	LastError             string `json:"lastError"`
}

type EquivocationEvidence struct {
	ID                 string   `json:"id"`
	OffenderID         string   `json:"offenderId"`
	MessageType        string   `json:"messageType"`
	Height             uint64   `json:"height"`
	Round              uint64   `json:"round"`
	FirstHash          string   `json:"firstHash"`
	SecondHash         string   `json:"secondHash"`
	First              Envelope `json:"first"`
	Second             Envelope `json:"second"`
	DetectedMs         int64    `json:"detectedMs"`
	PenaltyApplied     bool     `json:"penaltyApplied"`
	PenaltyBasisPoints uint64   `json:"penaltyBasisPoints,omitempty"`
	PenaltySlashed     uint64   `json:"penaltySlashed,omitempty"`
	PenaltyAppliedMs   int64    `json:"penaltyAppliedMs,omitempty"`
}

type pendingProposal struct {
	block chain.Block
	votes map[string]chain.Vote
}

type pendingHeight struct {
	proposals map[string]*pendingProposal
}

type heightRoundState struct {
	round     uint64
	idleTicks uint64
}

type peerBackoffState struct {
	failures    uint64
	nextAttempt time.Time
}

type peerRateState struct {
	windowStart time.Time
	count       uint64
}

type Service struct {
	mu sync.Mutex

	enabled          bool
	nodeID           string
	privateKey       string
	validatorPubKeys map[string]string
	peers            []string
	client           *http.Client
	logf             func(format string, args ...any)

	chain                 *chain.Chain
	consensusStarted      bool
	pending               map[uint64]*pendingHeight
	roundState            map[uint64]*heightRoundState
	proposerTimeout       uint64
	maxRoundLookahead     uint64
	peerBackoff           map[string]peerBackoffState
	peerRateState         map[string]peerRateState
	backoffInitial        time.Duration
	backoffMax            time.Duration
	peerDiscoveryInterval time.Duration
	lastPeerDiscovery     time.Time
	inboundRateLimit      uint64
	inboundRateWindow     time.Duration

	seenMessages     map[string]struct{}
	latestByType     map[string]messagePosition
	latestEnvByType  map[string]Envelope
	evidenceByID     map[string]EquivocationEvidence
	evidenceApplying map[string]struct{}
	evidenceOrder    []string
	stats            Stats
}

type messagePosition struct {
	height uint64
	round  uint64
	hash   string
}

type messageMeta struct {
	height uint64
	round  uint64
	hash   string
}

func NewService(cfg Config) (*Service, error) {
	timeout := cfg.ClientTimeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	proposerTimeout := cfg.ProposerTimeoutTicks
	if proposerTimeout == 0 {
		proposerTimeout = 2
	}
	maxRoundLookahead := cfg.MaxRoundLookahead
	if maxRoundLookahead == 0 {
		maxRoundLookahead = 16
	}
	backoffInitial := cfg.PeerBackoffInitial
	if backoffInitial <= 0 {
		backoffInitial = 500 * time.Millisecond
	}
	backoffMax := cfg.PeerBackoffMax
	if backoffMax <= 0 {
		backoffMax = 15 * time.Second
	}
	if backoffMax < backoffInitial {
		backoffMax = backoffInitial
	}
	peerDiscoveryInterval := cfg.PeerDiscoveryInterval
	if peerDiscoveryInterval == 0 {
		peerDiscoveryInterval = 30 * time.Second
	}
	inboundRateLimit := cfg.InboundRateLimit
	if inboundRateLimit == 0 {
		inboundRateLimit = 120
	}
	inboundRateWindow := cfg.InboundRateWindow
	if inboundRateWindow <= 0 {
		inboundRateWindow = time.Second
	}

	validatorPubKeys := make(map[string]string, len(cfg.ValidatorPubKeys))
	for id, pub := range cfg.ValidatorPubKeys {
		id = strings.TrimSpace(id)
		pub = strings.TrimSpace(pub)
		if id == "" || pub == "" {
			continue
		}
		validatorPubKeys[id] = pub
	}
	if cfg.Enabled && len(validatorPubKeys) == 0 {
		return nil, errors.New("p2p enabled but validator registry is empty")
	}

	rawPeers := normalizePeers(cfg.Peers)
	peers := make([]string, 0, len(rawPeers))
	for _, peer := range rawPeers {
		normalized, err := normalizePeerURL(peer)
		if err != nil {
			return nil, fmt.Errorf("invalid peer %q: %w", peer, err)
		}
		peers = append(peers, normalized)
	}
	peers = normalizePeers(peers)
	nodeID := strings.TrimSpace(cfg.NodeID)
	privateKey := strings.TrimSpace(cfg.ValidatorPrivateKey)

	if cfg.Enabled && nodeID != "" {
		if _, ok := validatorPubKeys[nodeID]; !ok {
			return nil, fmt.Errorf("node id %q is not in validator registry", nodeID)
		}
	}
	if privateKey != "" {
		if nodeID == "" {
			return nil, errors.New("validator private key provided but node id is empty")
		}
		priv, err := parsePrivateKeyHex(privateKey)
		if err != nil {
			return nil, fmt.Errorf("parse validator private key: %w", err)
		}
		derivedPubHex := fmt.Sprintf("%x", priv.Public())
		expectedPub := validatorPubKeys[nodeID]
		if expectedPub != "" && !strings.EqualFold(derivedPubHex, expectedPub) {
			return nil, fmt.Errorf("validator private key does not match registry for node %q", nodeID)
		}
	}

	svc := &Service{
		enabled:          cfg.Enabled,
		nodeID:           nodeID,
		privateKey:       privateKey,
		validatorPubKeys: validatorPubKeys,
		peers:            peers,
		client: &http.Client{
			Timeout: timeout,
		},
		logf:                  cfg.Logf,
		pending:               make(map[uint64]*pendingHeight),
		roundState:            make(map[uint64]*heightRoundState),
		proposerTimeout:       proposerTimeout,
		maxRoundLookahead:     maxRoundLookahead,
		peerBackoff:           make(map[string]peerBackoffState),
		peerRateState:         make(map[string]peerRateState),
		backoffInitial:        backoffInitial,
		backoffMax:            backoffMax,
		peerDiscoveryInterval: peerDiscoveryInterval,
		inboundRateLimit:      inboundRateLimit,
		inboundRateWindow:     inboundRateWindow,
		seenMessages:          make(map[string]struct{}),
		latestByType:          make(map[string]messagePosition),
		latestEnvByType:       make(map[string]Envelope),
		evidenceByID:          make(map[string]EquivocationEvidence),
		evidenceApplying:      make(map[string]struct{}),
		evidenceOrder:         make([]string, 0),
		stats: Stats{
			Enabled:         cfg.Enabled,
			NodeID:          nodeID,
			PeerCount:       len(peers),
			KnownValidators: len(validatorPubKeys),
		},
	}

	return svc, nil
}

func (s *Service) Enabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enabled
}

func (s *Service) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.stats
	out.PeerCount = len(s.peers)
	out.KnownValidators = len(s.validatorPubKeys)
	return out
}

func (s *Service) Peers() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.peers...)
}

func (s *Service) Evidence() []EquivocationEvidence {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]EquivocationEvidence, 0, len(s.evidenceOrder))
	for _, id := range s.evidenceOrder {
		ev, ok := s.evidenceByID[id]
		if !ok {
			continue
		}
		out = append(out, cloneEvidence(ev))
	}
	return out
}

func (s *Service) ApplyEvidencePenalty(evidenceID string, basisPoints uint64) (EquivocationEvidence, error) {
	evidenceID = strings.TrimSpace(evidenceID)
	if evidenceID == "" {
		return EquivocationEvidence{}, errors.New("evidence id is required")
	}
	if basisPoints == 0 || basisPoints > 10_000 {
		return EquivocationEvidence{}, chain.ErrInvalidSlashBasis
	}

	s.mu.Lock()
	ev, ok := s.evidenceByID[evidenceID]
	if !ok {
		s.mu.Unlock()
		return EquivocationEvidence{}, ErrEvidenceNotFound
	}
	if _, applying := s.evidenceApplying[evidenceID]; applying {
		s.mu.Unlock()
		return cloneEvidence(ev), ErrEvidenceApplied
	}
	if ev.PenaltyApplied {
		s.mu.Unlock()
		return cloneEvidence(ev), ErrEvidenceApplied
	}
	s.evidenceApplying[evidenceID] = struct{}{}
	chainRef := s.chain
	offenderID := ev.OffenderID
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.evidenceApplying, evidenceID)
		s.mu.Unlock()
	}()

	if chainRef == nil {
		return EquivocationEvidence{}, errors.New("p2p service has no chain attached")
	}
	if _, exists := chainRef.GetValidator(offenderID); !exists {
		return EquivocationEvidence{}, fmt.Errorf("validator %s not found", offenderID)
	}

	slashed, err := chainRef.SlashValidatorStake(offenderID, basisPoints)
	if err != nil {
		return EquivocationEvidence{}, err
	}
	if err := chainRef.SetValidatorJailed(offenderID, true); err != nil {
		return EquivocationEvidence{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ev, ok = s.evidenceByID[evidenceID]
	if !ok {
		return EquivocationEvidence{}, ErrEvidenceNotFound
	}
	if ev.PenaltyApplied {
		return cloneEvidence(ev), ErrEvidenceApplied
	}
	ev.PenaltyApplied = true
	ev.PenaltyBasisPoints = basisPoints
	ev.PenaltySlashed = slashed
	ev.PenaltyAppliedMs = time.Now().UnixMilli()
	s.evidenceByID[evidenceID] = ev
	s.stats.EquivocationApplied++
	return cloneEvidence(ev), nil
}

func (s *Service) AddPeer(peer string) (bool, error) {
	normalized, err := normalizePeerURL(peer)
	if err != nil {
		return false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.peers {
		if existing == normalized {
			return false, nil
		}
	}
	s.peers = append(s.peers, normalized)
	sort.Strings(s.peers)
	s.stats.PeerCount = len(s.peers)
	return true, nil
}

func (s *Service) RemovePeer(peer string) (bool, error) {
	normalized, err := normalizePeerURL(peer)
	if err != nil {
		return false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.peers {
		if existing != normalized {
			continue
		}
		s.peers = append(s.peers[:i], s.peers[i+1:]...)
		s.stats.PeerCount = len(s.peers)
		return true, nil
	}
	return false, nil
}

func (s *Service) AttachChain(c *chain.Chain) {
	if c == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.chain = c
}

func (s *Service) StartConsensus(ctx context.Context, c *chain.Chain) {
	s.AttachChain(c)

	s.mu.Lock()
	if !s.enabled || s.consensusStarted {
		s.mu.Unlock()
		return
	}
	s.consensusStarted = true
	interval := c.BlockInterval()
	if interval <= 0 {
		interval = 2 * time.Second
	}
	s.mu.Unlock()

	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.consensusTick()
			}
		}
	}()
}

func (s *Service) AllowInboundPeer(peer string) bool {
	now := time.Now()
	peer = strings.TrimSpace(strings.ToLower(peer))
	if peer == "" {
		peer = "unknown"
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inboundRateLimit == 0 {
		return true
	}
	if len(s.peerRateState) > 2048 {
		s.prunePeerRateStateLocked(now)
	}

	state := s.peerRateState[peer]
	if state.windowStart.IsZero() || now.Sub(state.windowStart) >= s.inboundRateWindow {
		s.peerRateState[peer] = peerRateState{
			windowStart: now,
			count:       1,
		}
		return true
	}
	if state.count >= s.inboundRateLimit {
		s.stats.RateLimitedTotal++
		s.stats.LastError = fmt.Sprintf("inbound rate limit exceeded for peer %s", peer)
		return false
	}
	state.count++
	s.peerRateState[peer] = state
	return true
}

func (s *Service) prunePeerRateStateLocked(now time.Time) {
	cutoff := now.Add(-2 * s.inboundRateWindow)
	for peer, state := range s.peerRateState {
		if state.windowStart.Before(cutoff) {
			delete(s.peerRateState, peer)
		}
	}
	// Keep memory bounded even if peers constantly churn.
	for len(s.peerRateState) > 2048 {
		for peer := range s.peerRateState {
			delete(s.peerRateState, peer)
			break
		}
	}
}

func (s *Service) RunConsensusStep() {
	s.consensusTick()
}

func (s *Service) HandleEnvelope(env Envelope) error {
	meta, err := s.validateAndRecordEnvelope(env)
	if err != nil {
		return err
	}

	switch env.Type {
	case MessageTypeBlockProposal:
		payload, err := decodeStrict[BlockProposal](env.Payload)
		if err != nil {
			err = fmt.Errorf("%w: decode proposal payload: %v", ErrInvalidMessage, err)
			s.recordReject(err, false, false)
			return err
		}
		if err := s.handleProposal(payload.Block, env.SenderID); err != nil {
			s.recordReject(err, errors.Is(err, ErrDuplicateMessage), errors.Is(err, ErrOutdatedMessage))
			return err
		}
	case MessageTypeBlockVote:
		payload, err := decodeStrict[BlockVote](env.Payload)
		if err != nil {
			err = fmt.Errorf("%w: decode vote payload: %v", ErrInvalidMessage, err)
			s.recordReject(err, false, false)
			return err
		}
		if err := s.handleVote(payload); err != nil {
			s.recordReject(err, errors.Is(err, ErrDuplicateMessage), errors.Is(err, ErrOutdatedMessage))
			return err
		}
	case MessageTypeBlockFinalize:
		payload, err := decodeStrict[BlockFinalize](env.Payload)
		if err != nil {
			err = fmt.Errorf("%w: decode finalize payload: %v", ErrInvalidMessage, err)
			s.recordReject(err, false, false)
			return err
		}
		if err := s.handleFinalize(payload); err != nil {
			s.recordReject(err, errors.Is(err, ErrDuplicateMessage), errors.Is(err, ErrOutdatedMessage))
			return err
		}
	default:
		err := fmt.Errorf("%w: %s", ErrUnsupportedType, env.Type)
		s.recordReject(err, false, false)
		return err
	}

	if s.logf != nil {
		s.logf("p2p accepted message type=%s sender=%s height=%d hash=%s", env.Type, env.SenderID, meta.height, shortHash(meta.hash))
	}
	return nil
}

func (s *Service) consensusTick() {
	s.runPeerDiscoveryTick(time.Now())

	chainRef, nodeID, privKey := s.runtimePointers()
	if chainRef == nil || nodeID == "" || privKey == "" {
		return
	}

	height, _, err := chainRef.NextExpectedProposer()
	if err != nil {
		s.logfSafe("p2p tick failed to get proposer: %v", err)
		return
	}
	round := s.advanceRoundOnTick(height)
	proposerID, err := chainRef.ExpectedProposerForRound(height, round)
	if err != nil {
		s.logfSafe("p2p tick failed to get round proposer: %v", err)
		return
	}
	if proposerID != nodeID {
		return
	}

	if s.hasProposalForRound(height, round) {
		return
	}

	block, err := chainRef.BuildProposalForRound(round, nodeID)
	if err != nil {
		s.logfSafe("p2p proposer failed to build proposal: %v", err)
		return
	}

	s.observeProgress(height)
	s.addPendingIfMissing(block)
	proposal := BlockProposal{Block: block}
	if err := s.broadcastSigned(MessageTypeBlockProposal, proposal); err != nil {
		s.logfSafe("p2p proposal broadcast failed: %v", err)
	}

	vote, err := chainRef.BuildVote(block, nodeID)
	if err != nil {
		s.logfSafe("p2p proposer failed to build self-vote: %v", err)
		return
	}
	_, _ = s.storeVote(block.Height, block.Hash, vote)
	votePayload := BlockVote{
		Height:    block.Height,
		BlockHash: block.Hash,
		VoterID:   nodeID,
		Approve:   vote.Approved,
		Timestamp: block.Timestamp,
	}
	if err := s.broadcastSigned(MessageTypeBlockVote, votePayload); err != nil {
		s.logfSafe("p2p vote broadcast failed: %v", err)
	}

	if err := s.tryFinalize(block.Height); err != nil {
		s.logfSafe("p2p finalize attempt failed: %v", err)
	}
}

func (s *Service) handleProposal(block chain.Block, senderID string) error {
	chainRef, nodeID, privKey := s.runtimePointers()
	if chainRef == nil {
		return errors.New("p2p service has no chain attached")
	}

	height, _, err := chainRef.NextExpectedProposer()
	if err != nil {
		return err
	}
	if block.Height < height {
		return ErrOutdatedMessage
	}
	if block.Height > height {
		return fmt.Errorf("%w: proposal height %d is ahead of local height %d", ErrOutdatedMessage, block.Height, height)
	}

	currentRound := s.roundForHeight(height)
	if block.Round+1 < currentRound {
		return ErrOutdatedMessage
	}
	if block.Round > currentRound+s.maxRoundLookahead {
		return fmt.Errorf("%w: proposal round %d is too far ahead of local round %d", ErrOutdatedMessage, block.Round, currentRound)
	}

	expectedProposer, err := chainRef.ExpectedProposerForRound(height, block.Round)
	if err != nil {
		return err
	}
	if senderID != expectedProposer {
		return fmt.Errorf("%w: proposal sender %s expected %s for round %d", ErrInvalidMessage, senderID, expectedProposer, block.Round)
	}
	if block.Proposer != senderID {
		return fmt.Errorf("%w: proposal block proposer %s does not match sender %s", ErrInvalidMessage, block.Proposer, senderID)
	}

	s.adoptRound(height, block.Round)
	s.observeProgress(height)
	s.addPendingIfMissing(block)

	if nodeID == "" || nodeID == senderID {
		return nil
	}

	vote, err := chainRef.BuildVote(block, nodeID)
	if err != nil {
		return err
	}
	newVote, err := s.storeVote(block.Height, block.Hash, vote)
	if err != nil {
		return err
	}
	if !newVote {
		return nil
	}

	if privKey == "" {
		return nil
	}
	votePayload := BlockVote{
		Height:    block.Height,
		BlockHash: block.Hash,
		VoterID:   nodeID,
		Approve:   vote.Approved,
		Timestamp: block.Timestamp,
	}
	if err := s.broadcastSigned(MessageTypeBlockVote, votePayload); err != nil {
		s.logfSafe("p2p vote broadcast failed: %v", err)
	}
	return nil
}

func (s *Service) handleVote(payload BlockVote) error {
	chainRef, _, _ := s.runtimePointers()
	if chainRef == nil {
		return errors.New("p2p service has no chain attached")
	}
	stake, err := chainRef.ValidatorEffectiveStake(payload.VoterID)
	if err != nil {
		return err
	}
	if stake == 0 {
		return fmt.Errorf("validator %s has zero effective stake", payload.VoterID)
	}

	vote := chain.Vote{
		ValidatorID:    payload.VoterID,
		EffectiveStake: stake,
		Approved:       payload.Approve,
	}
	_, err = s.storeVote(payload.Height, payload.BlockHash, vote)
	if err != nil {
		return err
	}

	s.observeProgress(payload.Height)
	return s.tryFinalize(payload.Height)
}

func (s *Service) handleFinalize(payload BlockFinalize) error {
	chainRef, _, _ := s.runtimePointers()
	if chainRef == nil {
		return errors.New("p2p service has no chain attached")
	}
	if len(payload.Block.Votes) == 0 {
		return fmt.Errorf("%w: finalize payload missing block votes", ErrInvalidMessage)
	}

	err := chainRef.FinalizeExternalBlock(payload.Block)
	if err != nil {
		if errors.Is(err, chain.ErrBlockAlreadyFinalized) {
			return ErrDuplicateMessage
		}
		if errors.Is(err, chain.ErrUnexpectedHeight) {
			return ErrOutdatedMessage
		}
		return err
	}
	s.removePendingUpTo(payload.Block.Height)
	s.removeRoundStateUpTo(payload.Block.Height)
	return nil
}

func (s *Service) tryFinalize(height uint64) error {
	chainRef, nodeID, privKey := s.runtimePointers()
	if chainRef == nil || nodeID == "" || privKey == "" {
		return nil
	}

	snapshots, ok := s.pendingSnapshots(height)
	if !ok {
		return nil
	}

	forkChoice, ok := chooseForkChoiceSnapshot(snapshots)
	if !ok {
		return nil
	}
	if forkChoice.block.Proposer != nodeID {
		return nil
	}

	yesStake, totalStake := aggregateVotes(forkChoice.votes, chainRef.TotalEffectiveStake())
	if totalStake == 0 || yesStake*3 < totalStake*2 {
		return nil
	}

	finalBlock := forkChoice.block
	finalBlock.Votes = append([]chain.Vote(nil), forkChoice.votes...)
	sort.SliceStable(finalBlock.Votes, func(i, j int) bool {
		return finalBlock.Votes[i].ValidatorID < finalBlock.Votes[j].ValidatorID
	})
	finalBlock.Finalized = true

	err := chainRef.FinalizeExternalBlock(finalBlock)
	if err != nil {
		if errors.Is(err, chain.ErrBlockAlreadyFinalized) {
			s.removePending(height)
			return nil
		}
		if errors.Is(err, chain.ErrUnexpectedHeight) {
			s.removePending(height)
			return nil
		}
		return err
	}
	s.removePending(height)
	s.removeRoundStateUpTo(height)

	finalize := BlockFinalize{
		Block:      finalBlock,
		YesStake:   yesStake,
		TotalStake: totalStake,
		Timestamp:  finalBlock.Timestamp,
	}
	if err := s.broadcastSigned(MessageTypeBlockFinalize, finalize); err != nil {
		return err
	}
	return nil
}

func (s *Service) broadcastSigned(messageType string, payload any) error {
	nodeID, privKey := s.signingIdentity()
	if nodeID == "" || privKey == "" {
		return nil
	}
	env, err := NewEnvelope(messageType, nodeID, payload, privKey)
	if err != nil {
		return err
	}
	return s.broadcastEnvelope(env)
}

func (s *Service) broadcastEnvelope(env Envelope) error {
	s.mu.Lock()
	peers := append([]string(nil), s.peers...)
	s.mu.Unlock()

	if len(peers) == 0 {
		return nil
	}

	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("encode envelope: %w", err)
	}

	var errs []string
	for _, peer := range peers {
		now := time.Now()
		if !s.allowBroadcastToPeer(peer, now) {
			continue
		}

		url := peer + "/p2p/message"
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			err = fmt.Errorf("build request to %s: %w", url, err)
			s.recordPeerBroadcastFailure(peer, now)
			s.recordBroadcastResult(false, err)
			errs = append(errs, err.Error())
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.client.Do(req)
		if err != nil {
			err = fmt.Errorf("send envelope to %s: %w", url, err)
			s.recordPeerBroadcastFailure(peer, now)
			s.recordBroadcastResult(false, err)
			errs = append(errs, err.Error())
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		_ = resp.Body.Close()
		if resp.StatusCode >= 300 && resp.StatusCode != http.StatusConflict {
			err = fmt.Errorf("peer %s returned %d: %s", url, resp.StatusCode, strings.TrimSpace(string(respBody)))
			s.recordPeerBroadcastFailure(peer, now)
			s.recordBroadcastResult(false, err)
			errs = append(errs, err.Error())
			continue
		}
		s.recordPeerBroadcastSuccess(peer)
		s.recordBroadcastResult(true, nil)
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (s *Service) allowBroadcastToPeer(peer string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.peerBackoff[peer]
	if !ok || state.nextAttempt.IsZero() || !now.Before(state.nextAttempt) {
		return true
	}
	s.stats.BroadcastBackoffTotal++
	return false
}

func (s *Service) recordPeerBroadcastFailure(peer string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.peerBackoff[peer]
	state.failures++
	backoff := computeBackoff(s.backoffInitial, s.backoffMax, state.failures)
	state.nextAttempt = now.Add(backoff)
	s.peerBackoff[peer] = state
}

func (s *Service) recordPeerBroadcastSuccess(peer string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.peerBackoff, peer)
}

func (s *Service) runPeerDiscoveryTick(now time.Time) {
	s.mu.Lock()
	interval := s.peerDiscoveryInterval
	if interval <= 0 {
		s.mu.Unlock()
		return
	}
	if !s.lastPeerDiscovery.IsZero() && now.Sub(s.lastPeerDiscovery) < interval {
		s.mu.Unlock()
		return
	}
	s.lastPeerDiscovery = now
	peers := append([]string(nil), s.peers...)
	client := s.client
	s.mu.Unlock()

	if len(peers) == 0 {
		s.mu.Lock()
		s.stats.PeerDiscoveryRuns++
		s.mu.Unlock()
		return
	}

	discovered := make([]string, 0, len(peers))
	var errs uint64
	for _, peer := range peers {
		peerList, err := fetchPeerList(client, peer)
		if err != nil {
			errs++
			continue
		}
		discovered = append(discovered, peerList...)
	}

	var added uint64
	for _, peer := range discovered {
		newlyAdded, err := s.AddPeer(peer)
		if err != nil {
			errs++
			continue
		}
		if newlyAdded {
			added++
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.PeerDiscoveryRuns++
	s.stats.PeerDiscoveryAdded += added
	s.stats.PeerDiscoveryErrors += errs
	if errs > 0 {
		s.stats.LastError = fmt.Sprintf("peer discovery errors=%d", errs)
	}
}

func computeBackoff(initial, max time.Duration, failures uint64) time.Duration {
	if initial <= 0 {
		return 0
	}
	if max < initial {
		max = initial
	}
	backoff := initial
	for i := uint64(1); i < failures; i++ {
		if backoff >= max/2 {
			return max
		}
		backoff *= 2
		if backoff >= max {
			return max
		}
	}
	return backoff
}

func (s *Service) validateAndRecordEnvelope(env Envelope) (messageMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.enabled {
		return messageMeta{}, ErrP2PDisabled
	}
	s.stats.ReceivedTotal++

	senderPubKey, ok := s.validatorPubKeys[env.SenderID]
	if !ok {
		err := fmt.Errorf("%w: %s", ErrUnknownSender, env.SenderID)
		s.recordRejectLocked(err, false, false)
		return messageMeta{}, err
	}
	if err := VerifyEnvelope(env, senderPubKey, env.SenderID); err != nil {
		err := fmt.Errorf("%w: verify envelope: %v", ErrInvalidMessage, err)
		s.recordRejectLocked(err, false, false)
		return messageMeta{}, err
	}

	meta, err := extractMessageMeta(env)
	if err != nil {
		s.recordRejectLocked(err, false, false)
		return messageMeta{}, err
	}

	msgKey := fmt.Sprintf("%s|%s|%d|%s", env.Type, env.SenderID, meta.height, meta.hash)
	if _, exists := s.seenMessages[msgKey]; exists {
		s.recordRejectLocked(ErrDuplicateMessage, true, false)
		return messageMeta{}, ErrDuplicateMessage
	}

	senderTypeKey := fmt.Sprintf("%s|%s", env.Type, env.SenderID)
	lastEnv, hasLastEnv := s.latestEnvByType[senderTypeKey]
	if last, exists := s.latestByType[senderTypeKey]; exists {
		if meta.height < last.height {
			s.recordRejectLocked(ErrOutdatedMessage, false, true)
			return messageMeta{}, ErrOutdatedMessage
		}
		if meta.height == last.height {
			switch env.Type {
			case MessageTypeBlockProposal, MessageTypeBlockFinalize:
				if meta.round < last.round {
					s.recordRejectLocked(ErrOutdatedMessage, false, true)
					return messageMeta{}, ErrOutdatedMessage
				}
				if meta.round == last.round {
					if meta.hash == last.hash {
						s.recordRejectLocked(ErrDuplicateMessage, true, false)
						return messageMeta{}, ErrDuplicateMessage
					}
					err := fmt.Errorf("%w: sender=%s type=%s height=%d round=%d", ErrConflictingMessage, env.SenderID, env.Type, meta.height, meta.round)
					if hasLastEnv {
						s.recordEquivocationLocked(env, meta, lastEnv, last)
					}
					s.recordRejectLocked(err, false, false)
					return messageMeta{}, err
				}
			case MessageTypeBlockVote:
				if meta.hash == last.hash {
					s.recordRejectLocked(ErrDuplicateMessage, true, false)
					return messageMeta{}, ErrDuplicateMessage
				}
				err := fmt.Errorf("%w: sender=%s type=%s height=%d", ErrConflictingMessage, env.SenderID, env.Type, meta.height)
				if hasLastEnv {
					s.recordEquivocationLocked(env, meta, lastEnv, last)
				}
				s.recordRejectLocked(err, false, false)
				return messageMeta{}, err
			default:
				if meta.hash == last.hash {
					s.recordRejectLocked(ErrDuplicateMessage, true, false)
					return messageMeta{}, ErrDuplicateMessage
				}
				err := fmt.Errorf("%w: sender=%s type=%s height=%d", ErrConflictingMessage, env.SenderID, env.Type, meta.height)
				if hasLastEnv {
					s.recordEquivocationLocked(env, meta, lastEnv, last)
				}
				s.recordRejectLocked(err, false, false)
				return messageMeta{}, err
			}
		}
	}

	s.seenMessages[msgKey] = struct{}{}
	s.latestByType[senderTypeKey] = messagePosition{height: meta.height, round: meta.round, hash: meta.hash}
	s.latestEnvByType[senderTypeKey] = cloneEnvelope(env)
	s.stats.AcceptedTotal++
	s.stats.LastAcceptedType = env.Type
	s.stats.LastAcceptedHeight = meta.height
	s.stats.LastAcceptedBlockHash = meta.hash

	return meta, nil
}

func (s *Service) recordBroadcastResult(success bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if success {
		s.stats.BroadcastSentTotal++
		return
	}
	s.stats.BroadcastErrorTotal++
	if err != nil {
		s.stats.LastError = err.Error()
	}
}

func (s *Service) recordReject(err error, duplicate, outdated bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recordRejectLocked(err, duplicate, outdated)
}

func (s *Service) recordRejectLocked(err error, duplicate, outdated bool) {
	s.stats.RejectedTotal++
	if duplicate {
		s.stats.DuplicateTotal++
	}
	if outdated {
		s.stats.OutdatedTotal++
	}
	if err != nil {
		s.stats.LastError = err.Error()
	}
	if s.logf != nil && err != nil {
		s.logf("p2p rejected message: %v", err)
	}
}

func (s *Service) recordEquivocationLocked(current Envelope, currentMeta messageMeta, previous Envelope, previousPos messagePosition) {
	firstEnv := cloneEnvelope(previous)
	secondEnv := cloneEnvelope(current)
	firstHash := previousPos.hash
	secondHash := currentMeta.hash

	if compareEvidenceOrder(secondHash, secondEnv, firstHash, firstEnv) < 0 {
		firstEnv, secondEnv = secondEnv, firstEnv
		firstHash, secondHash = secondHash, firstHash
	}

	evidence := EquivocationEvidence{
		OffenderID:  current.SenderID,
		MessageType: current.Type,
		Height:      currentMeta.height,
		Round:       currentMeta.round,
		FirstHash:   firstHash,
		SecondHash:  secondHash,
		First:       firstEnv,
		Second:      secondEnv,
		DetectedMs:  time.Now().UnixMilli(),
	}
	evidence.ID = computeEvidenceID(evidence)
	if _, exists := s.evidenceByID[evidence.ID]; exists {
		return
	}
	s.evidenceByID[evidence.ID] = evidence
	s.evidenceOrder = append(s.evidenceOrder, evidence.ID)
	s.stats.EquivocationTotal++
}

func (s *Service) runtimePointers() (chainRef *chain.Chain, nodeID string, privKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.chain, s.nodeID, s.privateKey
}

func (s *Service) signingIdentity() (nodeID string, privKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nodeID, s.privateKey
}

func (s *Service) hasPending(height uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.pending[height]
	return ok
}

func (s *Service) hasProposalForRound(height uint64, round uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.pending[height]
	if !ok {
		return false
	}
	for _, candidate := range h.proposals {
		if candidate.block.Round == round {
			return true
		}
	}
	return false
}

func (s *Service) roundForHeight(height uint64) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.roundState[height]
	if !ok {
		state = &heightRoundState{}
		s.roundState[height] = state
	}
	return state.round
}

func (s *Service) advanceRoundOnTick(height uint64) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.roundState[height]
	if !ok {
		state = &heightRoundState{}
		s.roundState[height] = state
	}

	state.idleTicks++
	if state.idleTicks >= s.proposerTimeout {
		state.round++
		state.idleTicks = 0
		if s.logf != nil {
			s.logf("p2p view-change height=%d round=%d", height, state.round)
		}
	}
	return state.round
}

func (s *Service) observeProgress(height uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.roundState[height]
	if !ok {
		state = &heightRoundState{}
		s.roundState[height] = state
	}
	state.idleTicks = 0
}

func (s *Service) adoptRound(height uint64, round uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.roundState[height]
	if !ok {
		state = &heightRoundState{}
		s.roundState[height] = state
	}
	if round > state.round {
		state.round = round
	}
	state.idleTicks = 0
}

func (s *Service) addPendingIfMissing(block chain.Block) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	heightPending, ok := s.pending[block.Height]
	if !ok {
		heightPending = &pendingHeight{
			proposals: make(map[string]*pendingProposal),
		}
		s.pending[block.Height] = heightPending
	}
	if _, exists := heightPending.proposals[block.Hash]; exists {
		return false
	}
	heightPending.proposals[block.Hash] = &pendingProposal{
		block: block,
		votes: make(map[string]chain.Vote),
	}
	return true
}

func (s *Service) storeVote(height uint64, blockHash string, vote chain.Vote) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	heightPending, ok := s.pending[height]
	if !ok {
		return false, ErrOutdatedMessage
	}
	candidate, ok := heightPending.proposals[blockHash]
	if !ok {
		return false, ErrConflictingMessage
	}
	if _, exists := candidate.votes[vote.ValidatorID]; exists {
		return false, ErrDuplicateMessage
	}
	candidate.votes[vote.ValidatorID] = vote
	return true, nil
}

type proposalSnapshot struct {
	block chain.Block
	votes []chain.Vote
}

func (s *Service) pendingSnapshots(height uint64) ([]proposalSnapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	heightPending, ok := s.pending[height]
	if !ok {
		return nil, false
	}

	snapshots := make([]proposalSnapshot, 0, len(heightPending.proposals))
	for _, candidate := range heightPending.proposals {
		votes := make([]chain.Vote, 0, len(candidate.votes))
		for _, vote := range candidate.votes {
			votes = append(votes, vote)
		}
		snapshots = append(snapshots, proposalSnapshot{
			block: candidate.block,
			votes: votes,
		})
	}
	return snapshots, true
}

func chooseForkChoiceSnapshot(candidates []proposalSnapshot) (proposalSnapshot, bool) {
	if len(candidates) == 0 {
		return proposalSnapshot{}, false
	}
	best := candidates[0]
	for i := 1; i < len(candidates); i++ {
		if betterForkChoiceBlock(candidates[i].block, best.block) {
			best = candidates[i]
		}
	}
	return best, true
}

func betterForkChoiceBlock(candidate, current chain.Block) bool {
	if candidate.Round != current.Round {
		return candidate.Round > current.Round
	}
	if candidate.Proposer != current.Proposer {
		return candidate.Proposer < current.Proposer
	}
	if candidate.Hash != current.Hash {
		return candidate.Hash < current.Hash
	}
	return false
}

func (s *Service) removePending(height uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, height)
}

func (s *Service) removePendingUpTo(height uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h := range s.pending {
		if h <= height {
			delete(s.pending, h)
		}
	}
}

func (s *Service) removeRoundStateUpTo(height uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h := range s.roundState {
		if h <= height {
			delete(s.roundState, h)
		}
	}
}

func (s *Service) logfSafe(format string, args ...any) {
	s.mu.Lock()
	logf := s.logf
	s.mu.Unlock()
	if logf != nil {
		logf(format, args...)
	}
}

func extractMessageMeta(env Envelope) (messageMeta, error) {
	switch env.Type {
	case MessageTypeBlockProposal:
		payload, err := decodeStrict[BlockProposal](env.Payload)
		if err != nil {
			return messageMeta{}, fmt.Errorf("%w: proposal payload: %v", ErrInvalidMessage, err)
		}
		block := payload.Block
		if block.Height == 0 || block.Timestamp <= 0 || block.PrevHash == "" || block.Hash == "" || block.StateRoot == "" || block.Proposer == "" {
			return messageMeta{}, fmt.Errorf("%w: incomplete proposal payload", ErrInvalidMessage)
		}
		if block.Proposer != env.SenderID {
			return messageMeta{}, fmt.Errorf("%w: proposal proposer %q does not match sender %q", ErrInvalidMessage, block.Proposer, env.SenderID)
		}
		return messageMeta{height: block.Height, round: block.Round, hash: block.Hash}, nil
	case MessageTypeBlockVote:
		payload, err := decodeStrict[BlockVote](env.Payload)
		if err != nil {
			return messageMeta{}, fmt.Errorf("%w: vote payload: %v", ErrInvalidMessage, err)
		}
		if payload.Height == 0 || payload.Timestamp <= 0 || payload.BlockHash == "" || payload.VoterID == "" {
			return messageMeta{}, fmt.Errorf("%w: incomplete vote payload", ErrInvalidMessage)
		}
		if payload.VoterID != env.SenderID {
			return messageMeta{}, fmt.Errorf("%w: vote voterId %q does not match sender %q", ErrInvalidMessage, payload.VoterID, env.SenderID)
		}
		voteHash := payload.BlockHash
		if payload.Approve {
			voteHash += "|yes"
		} else {
			voteHash += "|no"
		}
		return messageMeta{height: payload.Height, round: 0, hash: voteHash}, nil
	case MessageTypeBlockFinalize:
		payload, err := decodeStrict[BlockFinalize](env.Payload)
		if err != nil {
			return messageMeta{}, fmt.Errorf("%w: finalize payload: %v", ErrInvalidMessage, err)
		}
		block := payload.Block
		if block.Height == 0 || block.Timestamp <= 0 || block.Hash == "" || block.Proposer == "" {
			return messageMeta{}, fmt.Errorf("%w: incomplete finalize payload", ErrInvalidMessage)
		}
		if payload.TotalStake > 0 && payload.YesStake > payload.TotalStake {
			return messageMeta{}, fmt.Errorf("%w: invalid finalize stake values", ErrInvalidMessage)
		}
		return messageMeta{height: block.Height, round: block.Round, hash: block.Hash}, nil
	default:
		return messageMeta{}, fmt.Errorf("%w: %s", ErrUnsupportedType, env.Type)
	}
}

func normalizePeers(in []string) []string {
	set := map[string]struct{}{}
	for _, peer := range in {
		peer = strings.TrimSpace(peer)
		if peer == "" {
			continue
		}
		peer = strings.TrimSuffix(peer, "/")
		set[peer] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for peer := range set {
		out = append(out, peer)
	}
	sort.Strings(out)
	return out
}

func normalizePeerURL(rawPeer string) (string, error) {
	peer := strings.TrimSpace(rawPeer)
	peer = strings.TrimSuffix(peer, "/")
	if peer == "" {
		return "", fmt.Errorf("%w: empty peer URL", ErrInvalidPeer)
	}

	parsed, err := url.Parse(peer)
	if err != nil {
		return "", fmt.Errorf("%w: parse peer URL: %v", ErrInvalidPeer, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("%w: peer URL must include scheme and host", ErrInvalidPeer)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("%w: peer URL must not include path", ErrInvalidPeer)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: peer URL must not include query or fragment", ErrInvalidPeer)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("%w: unsupported scheme %q", ErrInvalidPeer, parsed.Scheme)
	}
	host := strings.ToLower(parsed.Host)
	if host == "" {
		return "", fmt.Errorf("%w: missing host", ErrInvalidPeer)
	}

	return scheme + "://" + host, nil
}

func aggregateVotes(votes []chain.Vote, totalStake uint64) (yesStake uint64, computedTotal uint64) {
	for _, vote := range votes {
		if vote.Approved {
			yesStake += vote.EffectiveStake
		}
	}
	return yesStake, totalStake
}

func fetchPeerList(client *http.Client, peer string) ([]string, error) {
	if client == nil {
		return nil, errors.New("http client is nil")
	}
	req, err := http.NewRequest(http.MethodGet, peer+"/p2p/peers", nil)
	if err != nil {
		return nil, fmt.Errorf("build peer discovery request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("peer discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("peer discovery status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload struct {
		Enabled bool     `json:"enabled"`
		Peers   []string `json:"peers"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 64*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode peer discovery response: %w", err)
	}
	return payload.Peers, nil
}

func cloneEnvelope(env Envelope) Envelope {
	cloned := env
	if len(env.Payload) > 0 {
		cloned.Payload = append(json.RawMessage(nil), env.Payload...)
	}
	return cloned
}

func cloneEvidence(ev EquivocationEvidence) EquivocationEvidence {
	cloned := ev
	cloned.First = cloneEnvelope(ev.First)
	cloned.Second = cloneEnvelope(ev.Second)
	return cloned
}

func compareEvidenceOrder(hashA string, envA Envelope, hashB string, envB Envelope) int {
	if hashA != hashB {
		if hashA < hashB {
			return -1
		}
		return 1
	}
	digestA := envelopeDigest(envA)
	digestB := envelopeDigest(envB)
	if digestA == digestB {
		return 0
	}
	if digestA < digestB {
		return -1
	}
	return 1
}

func envelopeDigest(env Envelope) string {
	sum := sha256.Sum256(signingBytes(env.Type, env.SenderID, env.Payload))
	return hex.EncodeToString(sum[:])
}

func computeEvidenceID(ev EquivocationEvidence) string {
	raw := fmt.Sprintf(
		"%s|%s|%d|%d|%s|%s|%s|%s",
		ev.OffenderID,
		ev.MessageType,
		ev.Height,
		ev.Round,
		ev.FirstHash,
		ev.SecondHash,
		ev.First.Signature,
		ev.Second.Signature,
	)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func decodeStrict[T any](raw []byte) (T, error) {
	var out T
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, err
	}
	if dec.More() {
		return out, errors.New("extra content in payload")
	}
	return out, nil
}

func shortHash(h string) string {
	if len(h) <= 10 {
		return h
	}
	return h[:10]
}
