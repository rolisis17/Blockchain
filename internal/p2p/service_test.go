package p2p

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"fastpos/internal/chain"
)

func testValidatorKeys(t *testing.T) (map[string]string, map[string]string, []chain.GenesisValidator) {
	t.Helper()
	pubByID := make(map[string]string)
	privByID := make(map[string]string)
	validators := make([]chain.GenesisValidator, 0, 3)
	for i, label := range []string{"p2p-v1", "p2p-v2", "p2p-v3"} {
		pub, priv, _, err := chain.DeterministicKeypair(label)
		if err != nil {
			t.Fatalf("deterministic keypair: %v", err)
		}
		id := fmt.Sprintf("v%d", i+1)
		pubByID[id] = pub
		privByID[id] = priv
		validators = append(validators, chain.GenesisValidator{
			ID:         id,
			PubKey:     pub,
			Stake:      1_000,
			WorkWeight: 100,
			Active:     true,
		})
	}
	return pubByID, privByID, validators
}

func testConsensusChain(t *testing.T, validators []chain.GenesisValidator) *chain.Chain {
	t.Helper()
	c, err := chain.New(chain.Config{
		BlockInterval:      2 * time.Second,
		GenesisTimestampMs: 1_700_000_000_000,
		BaseReward:         1,
		MaxTxPerBlock:      100,
		MaxMempoolSize:     10_000,
		MinTxFee:           1,
		GenesisAccounts:    map[chain.Address]uint64{},
		GenesisValidators:  validators,
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("seed first block: %v", err)
	}
	return c
}

func TestHandleEnvelopeValidation(t *testing.T) {
	pubByID, privByID, validators := testValidatorKeys(t)
	c := testConsensusChain(t, validators)

	svc, err := NewService(Config{
		Enabled:             true,
		NodeID:              "v1",
		ValidatorPrivateKey: privByID["v1"],
		ValidatorPubKeys:    pubByID,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	svc.AttachChain(c)

	_, proposerID, err := c.NextExpectedProposer()
	if err != nil {
		t.Fatalf("next proposer: %v", err)
	}
	block, err := c.BuildProposal(proposerID)
	if err != nil {
		t.Fatalf("build proposal: %v", err)
	}

	proposal := BlockProposal{Block: block}
	env, err := NewEnvelope(MessageTypeBlockProposal, proposerID, proposal, privByID[proposerID])
	if err != nil {
		t.Fatalf("new envelope: %v", err)
	}
	if err := svc.HandleEnvelope(env); err != nil {
		t.Fatalf("handle envelope: %v", err)
	}

	if err := svc.HandleEnvelope(env); !errors.Is(err, ErrDuplicateMessage) {
		t.Fatalf("expected duplicate error, got %v", err)
	}

	oldBlock := block
	oldBlock.Height = block.Height - 1
	oldBlock.Hash = "old-hash"
	oldBlock.Timestamp = block.Timestamp - c.BlockInterval().Milliseconds()
	proposalOld := BlockProposal{Block: oldBlock}

	envOld, err := NewEnvelope(MessageTypeBlockProposal, proposerID, proposalOld, privByID[proposerID])
	if err != nil {
		t.Fatalf("new old envelope: %v", err)
	}
	if err := svc.HandleEnvelope(envOld); !errors.Is(err, ErrOutdatedMessage) {
		t.Fatalf("expected outdated error, got %v", err)
	}

	stats := svc.Stats()
	if stats.AcceptedTotal != 1 {
		t.Fatalf("expected accepted total 1, got %d", stats.AcceptedTotal)
	}
	if stats.DuplicateTotal != 1 {
		t.Fatalf("expected duplicate total 1, got %d", stats.DuplicateTotal)
	}
	if stats.OutdatedTotal != 1 {
		t.Fatalf("expected outdated total 1, got %d", stats.OutdatedTotal)
	}
}

func TestHandleEnvelopeUnknownSender(t *testing.T) {
	pubByID, privByID, _ := testValidatorKeys(t)
	svc, err := NewService(Config{
		Enabled:             true,
		NodeID:              "v1",
		ValidatorPrivateKey: privByID["v1"],
		ValidatorPubKeys:    map[string]string{"v1": pubByID["v1"]},
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	vote := BlockVote{Height: 1, BlockHash: "h1", VoterID: "v2", Approve: true, Timestamp: 1700000002000}
	env, err := NewEnvelope(MessageTypeBlockVote, "v2", vote, privByID["v2"])
	if err != nil {
		t.Fatalf("new envelope: %v", err)
	}

	if err := svc.HandleEnvelope(env); !errors.Is(err, ErrUnknownSender) {
		t.Fatalf("expected unknown sender error, got %v", err)
	}
}

func TestHandleEnvelopeBadSignature(t *testing.T) {
	pubByID, privByID, _ := testValidatorKeys(t)
	svc, err := NewService(Config{
		Enabled:             true,
		NodeID:              "v1",
		ValidatorPrivateKey: privByID["v1"],
		ValidatorPubKeys:    pubByID,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	finalize := BlockFinalize{
		Block: chain.Block{
			Height:    2,
			PrevHash:  "h1",
			Timestamp: 1700000003000,
			Proposer:  "v2",
			StateRoot: "root-2",
			Hash:      "h2",
		},
		YesStake:   800,
		TotalStake: 1000,
		Timestamp:  1700000003000,
	}
	env, err := NewEnvelope(MessageTypeBlockFinalize, "v2", finalize, privByID["v2"])
	if err != nil {
		t.Fatalf("new envelope: %v", err)
	}
	env.Payload = json.RawMessage(`{"block":{"height":2,"prevHash":"h1","timestamp":1700000003000,"proposer":"v2","transactions":[],"stateRoot":"root-2","hash":"tampered","votes":[],"finalized":false},"yesStake":800,"totalStake":1000,"timestamp":1700000003000}`)

	if err := svc.HandleEnvelope(env); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("expected invalid message error, got %v", err)
	}
}

func TestBroadcastSignedMessage(t *testing.T) {
	pubByID, privByID, _ := testValidatorKeys(t)
	var received int64

	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/p2p/message" {
			atomic.AddInt64(&received, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer receiver.Close()

	svc, err := NewService(Config{
		Enabled:             true,
		NodeID:              "v1",
		ValidatorPrivateKey: privByID["v1"],
		ValidatorPubKeys:    pubByID,
		Peers:               []string{receiver.URL},
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	vote := BlockVote{
		Height:    5,
		BlockHash: "hash5",
		VoterID:   "v1",
		Approve:   true,
		Timestamp: 1700000005000,
	}
	if err := svc.broadcastSigned(MessageTypeBlockVote, vote); err != nil {
		t.Fatalf("broadcast signed message: %v", err)
	}

	if got := atomic.LoadInt64(&received); got != 1 {
		t.Fatalf("expected 1 broadcast message, got %d", got)
	}

	stats := svc.Stats()
	if stats.BroadcastSentTotal != 1 {
		t.Fatalf("expected broadcast sent total 1, got %d", stats.BroadcastSentTotal)
	}
}

func TestBroadcastSignedMessagePeerBackoff(t *testing.T) {
	pubByID, privByID, _ := testValidatorKeys(t)
	var attempts int64

	failingPeer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/p2p/message" {
			atomic.AddInt64(&attempts, 1)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("boom"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer failingPeer.Close()

	svc, err := NewService(Config{
		Enabled:             true,
		NodeID:              "v1",
		ValidatorPrivateKey: privByID["v1"],
		ValidatorPubKeys:    pubByID,
		Peers:               []string{failingPeer.URL},
		PeerBackoffInitial:  time.Hour,
		PeerBackoffMax:      time.Hour,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	vote := BlockVote{
		Height:    10,
		BlockHash: "hash10",
		VoterID:   "v1",
		Approve:   true,
		Timestamp: 1700000005000,
	}
	if err := svc.broadcastSigned(MessageTypeBlockVote, vote); err == nil {
		t.Fatalf("expected first broadcast to fail")
	}
	if err := svc.broadcastSigned(MessageTypeBlockVote, vote); err != nil {
		t.Fatalf("expected second broadcast to be skipped during backoff, got %v", err)
	}
	if got := atomic.LoadInt64(&attempts); got != 1 {
		t.Fatalf("expected exactly one peer attempt due to backoff, got %d", got)
	}

	stats := svc.Stats()
	if stats.BroadcastErrorTotal != 1 {
		t.Fatalf("expected broadcast error total 1, got %d", stats.BroadcastErrorTotal)
	}
	if stats.BroadcastBackoffTotal != 1 {
		t.Fatalf("expected broadcast backoff total 1, got %d", stats.BroadcastBackoffTotal)
	}
}

func TestPeerManagement(t *testing.T) {
	pubByID, privByID, _ := testValidatorKeys(t)
	svc, err := NewService(Config{
		Enabled:             true,
		NodeID:              "v1",
		ValidatorPrivateKey: privByID["v1"],
		ValidatorPubKeys:    pubByID,
		Peers:               []string{"http://127.0.0.1:18082/"},
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	peers := svc.Peers()
	if len(peers) != 1 || peers[0] != "http://127.0.0.1:18082" {
		t.Fatalf("expected normalized initial peer list, got %+v", peers)
	}

	added, err := svc.AddPeer("https://EXAMPLE.com:443/")
	if err != nil {
		t.Fatalf("add peer: %v", err)
	}
	if !added {
		t.Fatalf("expected new peer to be added")
	}
	added, err = svc.AddPeer("https://example.com:443")
	if err != nil {
		t.Fatalf("add duplicate peer: %v", err)
	}
	if added {
		t.Fatalf("expected duplicate peer add to return added=false")
	}

	if _, err := svc.AddPeer("ftp://example.com"); !errors.Is(err, ErrInvalidPeer) {
		t.Fatalf("expected ErrInvalidPeer for unsupported scheme, got %v", err)
	}
	if _, err := svc.AddPeer("http://example.com/path"); !errors.Is(err, ErrInvalidPeer) {
		t.Fatalf("expected ErrInvalidPeer for URL with path, got %v", err)
	}

	removed, err := svc.RemovePeer("https://example.com:443/")
	if err != nil {
		t.Fatalf("remove peer: %v", err)
	}
	if !removed {
		t.Fatalf("expected peer to be removed")
	}
	removed, err = svc.RemovePeer("https://example.com:443")
	if err != nil {
		t.Fatalf("remove missing peer: %v", err)
	}
	if removed {
		t.Fatalf("expected removing missing peer to return removed=false")
	}
}

func TestPeerDiscoveryAddsNewPeerFromKnownPeer(t *testing.T) {
	pubByID, privByID, _ := testValidatorKeys(t)

	peerC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/p2p/peers" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"enabled":true,"peers":[]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer peerC.Close()

	peerB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/p2p/peers" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"enabled":true,"peers":["%s"]}`, peerC.URL)))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer peerB.Close()

	svc, err := NewService(Config{
		Enabled:               true,
		NodeID:                "v1",
		ValidatorPrivateKey:   privByID["v1"],
		ValidatorPubKeys:      pubByID,
		Peers:                 []string{peerB.URL},
		PeerDiscoveryInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	svc.runPeerDiscoveryTick(time.Now())
	peers := svc.Peers()
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers after discovery, got %d (%v)", len(peers), peers)
	}
	containsC := false
	for _, peer := range peers {
		if peer == peerC.URL {
			containsC = true
			break
		}
	}
	if !containsC {
		t.Fatalf("expected discovered peer %s in peer set: %v", peerC.URL, peers)
	}

	stats := svc.Stats()
	if stats.PeerDiscoveryRuns == 0 {
		t.Fatalf("expected peer discovery runs > 0")
	}
	if stats.PeerDiscoveryAdded == 0 {
		t.Fatalf("expected peer discovery added > 0")
	}
}

func TestHandleEnvelope_AllowsSameSenderHigherRoundProposal(t *testing.T) {
	pubByID, privByID, validators := testValidatorKeys(t)
	c := testConsensusChain(t, validators)

	svc, err := NewService(Config{
		Enabled:             true,
		NodeID:              "v1",
		ValidatorPrivateKey: privByID["v1"],
		ValidatorPubKeys:    pubByID,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	svc.AttachChain(c)

	height, proposerID, err := c.NextExpectedProposer()
	if err != nil {
		t.Fatalf("next proposer: %v", err)
	}
	higherRound, found, err := c.ProposerRoundForHeight(height, proposerID, 1, 16)
	if err != nil {
		t.Fatalf("find higher round for proposer %s: %v", proposerID, err)
	}
	if !found {
		t.Fatalf("expected proposer %s to recur in higher rounds", proposerID)
	}

	blockRound0, err := c.BuildProposalForRound(0, proposerID)
	if err != nil {
		t.Fatalf("build round0 proposal: %v", err)
	}
	blockHigher, err := c.BuildProposalForRound(higherRound, proposerID)
	if err != nil {
		t.Fatalf("build higher-round proposal: %v", err)
	}
	if blockHigher.Round <= blockRound0.Round {
		t.Fatalf("expected higher-round proposal, got %d", blockHigher.Round)
	}

	env0, err := NewEnvelope(MessageTypeBlockProposal, proposerID, BlockProposal{Block: blockRound0}, privByID[proposerID])
	if err != nil {
		t.Fatalf("new round0 envelope: %v", err)
	}
	if err := svc.HandleEnvelope(env0); err != nil {
		t.Fatalf("handle round0 envelope: %v", err)
	}

	envHigher, err := NewEnvelope(MessageTypeBlockProposal, proposerID, BlockProposal{Block: blockHigher}, privByID[proposerID])
	if err != nil {
		t.Fatalf("new higher-round envelope: %v", err)
	}
	if err := svc.HandleEnvelope(envHigher); err != nil {
		t.Fatalf("handle higher-round envelope: %v", err)
	}
}

func TestForkChoicePrefersHigherRoundProposal(t *testing.T) {
	pubByID, privByID, validators := testValidatorKeys(t)
	c := testConsensusChain(t, validators)

	height, proposerRound0, err := c.NextExpectedProposer()
	if err != nil {
		t.Fatalf("next proposer: %v", err)
	}
	var chosenRound uint64
	var chosenProposer string
	for r := uint64(1); r <= 16; r++ {
		p, err := c.ExpectedProposerForRound(height, r)
		if err != nil {
			t.Fatalf("expected proposer for round %d: %v", r, err)
		}
		if p != proposerRound0 {
			chosenRound = r
			chosenProposer = p
			break
		}
	}
	if chosenRound == 0 {
		t.Fatalf("failed to find competing proposer within lookahead")
	}

	svc, err := NewService(Config{
		Enabled:             true,
		NodeID:              chosenProposer,
		ValidatorPrivateKey: privByID[chosenProposer],
		ValidatorPubKeys:    pubByID,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	svc.AttachChain(c)

	blockRound0, err := c.BuildProposalForRound(0, proposerRound0)
	if err != nil {
		t.Fatalf("build round0 proposal: %v", err)
	}
	blockChosen, err := c.BuildProposalForRound(chosenRound, chosenProposer)
	if err != nil {
		t.Fatalf("build chosen-round proposal: %v", err)
	}

	envRound0, err := NewEnvelope(MessageTypeBlockProposal, proposerRound0, BlockProposal{Block: blockRound0}, privByID[proposerRound0])
	if err != nil {
		t.Fatalf("new round0 envelope: %v", err)
	}
	if err := svc.HandleEnvelope(envRound0); err != nil {
		t.Fatalf("handle round0 envelope: %v", err)
	}

	envChosen, err := NewEnvelope(MessageTypeBlockProposal, chosenProposer, BlockProposal{Block: blockChosen}, privByID[chosenProposer])
	if err != nil {
		t.Fatalf("new chosen-round envelope: %v", err)
	}
	if err := svc.HandleEnvelope(envChosen); err != nil {
		t.Fatalf("handle chosen-round envelope: %v", err)
	}

	validatorIDs := make([]string, 0, len(privByID))
	for validatorID := range privByID {
		validatorIDs = append(validatorIDs, validatorID)
	}
	sort.Strings(validatorIDs)

	finalized := false
	for _, validatorID := range validatorIDs {
		validatorPriv := privByID[validatorID]
		votePayload := BlockVote{
			Height:    blockChosen.Height,
			BlockHash: blockChosen.Hash,
			VoterID:   validatorID,
			Approve:   true,
			Timestamp: blockChosen.Timestamp,
		}
		envVote, err := NewEnvelope(MessageTypeBlockVote, validatorID, votePayload, validatorPriv)
		if err != nil {
			t.Fatalf("new vote envelope (%s): %v", validatorID, err)
		}
		if err := svc.HandleEnvelope(envVote); err != nil {
			if errors.Is(err, ErrOutdatedMessage) {
				status := c.GetStatus()
				if status.Height == blockChosen.Height && status.HeadHash == blockChosen.Hash {
					finalized = true
					break
				}
			}
			t.Fatalf("handle vote envelope (%s): %v", validatorID, err)
		}
		status := c.GetStatus()
		if status.Height == blockChosen.Height && status.HeadHash == blockChosen.Hash {
			finalized = true
			break
		}
	}
	if !finalized {
		t.Fatalf("expected block %d (%s) to finalize", blockChosen.Height, blockChosen.Hash)
	}

	status := c.GetStatus()
	if status.Height != blockChosen.Height {
		t.Fatalf("expected finalized height %d, got %d", blockChosen.Height, status.Height)
	}
	if status.HeadHash != blockChosen.Hash {
		t.Fatalf("expected higher-round block hash %s, got %s", blockChosen.Hash, status.HeadHash)
	}
}

func TestHandleEnvelopeConflictingVoteRecordsEvidence(t *testing.T) {
	pubByID, privByID, validators := testValidatorKeys(t)
	c := testConsensusChain(t, validators)

	svc, err := NewService(Config{
		Enabled:             true,
		NodeID:              "v1",
		ValidatorPrivateKey: privByID["v1"],
		ValidatorPubKeys:    pubByID,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	svc.AttachChain(c)

	_, proposerID, err := c.NextExpectedProposer()
	if err != nil {
		t.Fatalf("next proposer: %v", err)
	}
	block, err := c.BuildProposal(proposerID)
	if err != nil {
		t.Fatalf("build proposal: %v", err)
	}
	proposalEnv, err := NewEnvelope(MessageTypeBlockProposal, proposerID, BlockProposal{Block: block}, privByID[proposerID])
	if err != nil {
		t.Fatalf("new proposal envelope: %v", err)
	}
	if err := svc.HandleEnvelope(proposalEnv); err != nil {
		t.Fatalf("handle proposal envelope: %v", err)
	}

	vote1 := BlockVote{
		Height:    block.Height,
		BlockHash: block.Hash,
		VoterID:   "v2",
		Approve:   true,
		Timestamp: block.Timestamp,
	}
	voteEnv1, err := NewEnvelope(MessageTypeBlockVote, "v2", vote1, privByID["v2"])
	if err != nil {
		t.Fatalf("new vote envelope 1: %v", err)
	}
	if err := svc.HandleEnvelope(voteEnv1); err != nil {
		t.Fatalf("handle vote envelope 1: %v", err)
	}

	vote2 := vote1
	vote2.BlockHash = "conflicting-hash"
	voteEnv2, err := NewEnvelope(MessageTypeBlockVote, "v2", vote2, privByID["v2"])
	if err != nil {
		t.Fatalf("new vote envelope 2: %v", err)
	}
	if err := svc.HandleEnvelope(voteEnv2); !errors.Is(err, ErrConflictingMessage) {
		t.Fatalf("expected ErrConflictingMessage for double vote, got %v", err)
	}

	evidence := svc.Evidence()
	if len(evidence) != 1 {
		t.Fatalf("expected exactly 1 evidence entry, got %d", len(evidence))
	}
	ev := evidence[0]
	if ev.OffenderID != "v2" {
		t.Fatalf("expected offender v2, got %s", ev.OffenderID)
	}
	if ev.MessageType != MessageTypeBlockVote {
		t.Fatalf("expected evidence type %s, got %s", MessageTypeBlockVote, ev.MessageType)
	}
	if ev.Height != block.Height {
		t.Fatalf("expected evidence height %d, got %d", block.Height, ev.Height)
	}

	stats := svc.Stats()
	if stats.EquivocationTotal != 1 {
		t.Fatalf("expected equivocation total 1, got %d", stats.EquivocationTotal)
	}
}

func TestApplyEvidencePenalty(t *testing.T) {
	pubByID, privByID, validators := testValidatorKeys(t)
	c := testConsensusChain(t, validators)

	svc, err := NewService(Config{
		Enabled:             true,
		NodeID:              "v1",
		ValidatorPrivateKey: privByID["v1"],
		ValidatorPubKeys:    pubByID,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	svc.AttachChain(c)

	_, proposerID, err := c.NextExpectedProposer()
	if err != nil {
		t.Fatalf("next proposer: %v", err)
	}
	block, err := c.BuildProposal(proposerID)
	if err != nil {
		t.Fatalf("build proposal: %v", err)
	}
	proposalEnv, err := NewEnvelope(MessageTypeBlockProposal, proposerID, BlockProposal{Block: block}, privByID[proposerID])
	if err != nil {
		t.Fatalf("new proposal envelope: %v", err)
	}
	if err := svc.HandleEnvelope(proposalEnv); err != nil {
		t.Fatalf("handle proposal envelope: %v", err)
	}

	vote1 := BlockVote{
		Height:    block.Height,
		BlockHash: block.Hash,
		VoterID:   "v2",
		Approve:   true,
		Timestamp: block.Timestamp,
	}
	voteEnv1, err := NewEnvelope(MessageTypeBlockVote, "v2", vote1, privByID["v2"])
	if err != nil {
		t.Fatalf("new vote envelope 1: %v", err)
	}
	if err := svc.HandleEnvelope(voteEnv1); err != nil {
		t.Fatalf("handle vote envelope 1: %v", err)
	}
	vote2 := vote1
	vote2.BlockHash = "conflicting-hash"
	voteEnv2, err := NewEnvelope(MessageTypeBlockVote, "v2", vote2, privByID["v2"])
	if err != nil {
		t.Fatalf("new vote envelope 2: %v", err)
	}
	if err := svc.HandleEnvelope(voteEnv2); !errors.Is(err, ErrConflictingMessage) {
		t.Fatalf("expected ErrConflictingMessage for double vote, got %v", err)
	}

	evidence := svc.Evidence()
	if len(evidence) != 1 {
		t.Fatalf("expected exactly 1 evidence entry, got %d", len(evidence))
	}
	ev, err := svc.ApplyEvidencePenalty(evidence[0].ID, 1_000)
	if err != nil {
		t.Fatalf("apply evidence penalty: %v", err)
	}
	if !ev.PenaltyApplied {
		t.Fatalf("expected evidence penalty to be marked as applied")
	}
	if ev.PenaltySlashed != 100 {
		t.Fatalf("expected slashed amount 100, got %d", ev.PenaltySlashed)
	}

	v, ok := c.GetValidator("v2")
	if !ok {
		t.Fatalf("validator v2 missing")
	}
	if v.Stake != 900 {
		t.Fatalf("expected stake 900 after penalty, got %d", v.Stake)
	}
	if !v.Jailed {
		t.Fatalf("expected validator v2 to be jailed after penalty")
	}

	if _, err := svc.ApplyEvidencePenalty(evidence[0].ID, 1_000); !errors.Is(err, ErrEvidenceApplied) {
		t.Fatalf("expected ErrEvidenceApplied on second apply, got %v", err)
	}

	stats := svc.Stats()
	if stats.EquivocationApplied != 1 {
		t.Fatalf("expected equivocation applied total 1, got %d", stats.EquivocationApplied)
	}
}
