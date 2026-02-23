package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"fastpos/internal/chain"
	"fastpos/internal/node"
	"fastpos/internal/p2p"
)

func TestThreeNodeConsensusDeterministic(t *testing.T) {
	const nodeCount = 3
	const rounds = 4

	validatorPubByID, validatorPrivByID, validators, ids := buildDeterministicValidators(t, nodeCount, map[string]uint64{})

	chains := make(map[string]*chain.Chain, nodeCount)
	for _, id := range ids {
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
			t.Fatalf("new chain %s: %v", id, err)
		}
		chains[id] = c
	}

	nodeHTTP := make(map[string]*node.Server, nodeCount)
	httpServers := make(map[string]*httptest.Server, nodeCount)
	for _, id := range ids {
		nodeID := id
		httpServers[nodeID] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			srv := nodeHTTP[nodeID]
			if srv == nil {
				http.Error(w, "server not initialized", http.StatusServiceUnavailable)
				return
			}
			srv.ServeHTTP(w, r)
		}))
		defer httpServers[nodeID].Close()
	}

	p2pByID := make(map[string]*p2p.Service, nodeCount)
	for _, id := range ids {
		peers := make([]string, 0, nodeCount-1)
		for _, peerID := range ids {
			if peerID == id {
				continue
			}
			peers = append(peers, httpServers[peerID].URL)
		}

		svc, err := p2p.NewService(p2p.Config{
			Enabled:             true,
			NodeID:              id,
			ValidatorPrivateKey: validatorPrivByID[id],
			ValidatorPubKeys:    validatorPubByID,
			Peers:               peers,
		})
		if err != nil {
			t.Fatalf("new p2p service %s: %v", id, err)
		}
		svc.AttachChain(chains[id])
		p2pByID[id] = svc
		nodeHTTP[id] = node.NewServer(chains[id], node.Config{P2PService: svc})
	}

	for targetHeight := uint64(1); targetHeight <= rounds; targetHeight++ {
		_, proposerID, err := chains["v1"].NextExpectedProposer()
		if err != nil {
			t.Fatalf("next proposer for height %d: %v", targetHeight, err)
		}
		p2pByID[proposerID].RunConsensusStep()

		waitUntil(t, 2*time.Second, func() bool {
			for _, id := range ids {
				if chains[id].GetStatus().Height < targetHeight {
					return false
				}
			}
			return true
		}, "all nodes finalized height %d", targetHeight)
	}

	refStatus := chains["v1"].GetStatus()
	if refStatus.Height != rounds {
		t.Fatalf("reference node expected height %d, got %d", rounds, refStatus.Height)
	}
	for _, id := range ids[1:] {
		status := chains[id].GetStatus()
		if status.Height != refStatus.Height {
			t.Fatalf("node %s height mismatch: got %d want %d", id, status.Height, refStatus.Height)
		}
		if status.HeadHash != refStatus.HeadHash {
			t.Fatalf("node %s head mismatch: got %s want %s", id, status.HeadHash, refStatus.HeadHash)
		}
	}
}

func TestFiveNodeConsensusWithOneOfflineValidator(t *testing.T) {
	const nodeCount = 5
	const minRounds = 3
	const maxPlanRounds = 12

	stakeByID := map[string]uint64{
		"v5": 1,
	}
	validatorPubByID, validatorPrivByID, validators, ids := buildDeterministicValidators(t, nodeCount, stakeByID)
	offlineID := "v5"

	rounds := planSafeRoundsBeforeOfflineProposer(t, validators, offlineID, maxPlanRounds)
	if rounds < minRounds {
		t.Fatalf("planned rounds too small with offline validator %s: got %d want >= %d", offlineID, rounds, minRounds)
	}

	onlineIDs := make([]string, 0, len(ids)-1)
	for _, id := range ids {
		if id != offlineID {
			onlineIDs = append(onlineIDs, id)
		}
	}

	chains := make(map[string]*chain.Chain, len(onlineIDs))
	for _, id := range onlineIDs {
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
			t.Fatalf("new chain %s: %v", id, err)
		}
		chains[id] = c
	}

	nodeHTTP := make(map[string]*node.Server, len(onlineIDs))
	httpServers := make(map[string]*httptest.Server, len(onlineIDs))
	for _, id := range onlineIDs {
		nodeID := id
		httpServers[nodeID] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			srv := nodeHTTP[nodeID]
			if srv == nil {
				http.Error(w, "server not initialized", http.StatusServiceUnavailable)
				return
			}
			srv.ServeHTTP(w, r)
		}))
		defer httpServers[nodeID].Close()
	}

	p2pByID := make(map[string]*p2p.Service, len(onlineIDs))
	for _, id := range onlineIDs {
		peers := make([]string, 0, len(onlineIDs)-1)
		for _, peerID := range onlineIDs {
			if peerID == id {
				continue
			}
			peers = append(peers, httpServers[peerID].URL)
		}

		svc, err := p2p.NewService(p2p.Config{
			Enabled:             true,
			NodeID:              id,
			ValidatorPrivateKey: validatorPrivByID[id],
			ValidatorPubKeys:    validatorPubByID,
			Peers:               peers,
		})
		if err != nil {
			t.Fatalf("new p2p service %s: %v", id, err)
		}
		svc.AttachChain(chains[id])
		p2pByID[id] = svc
		nodeHTTP[id] = node.NewServer(chains[id], node.Config{P2PService: svc})
	}

	for targetHeight := uint64(1); targetHeight <= uint64(rounds); targetHeight++ {
		_, proposerID, err := chains[onlineIDs[0]].NextExpectedProposer()
		if err != nil {
			t.Fatalf("next proposer for height %d: %v", targetHeight, err)
		}
		if proposerID == offlineID {
			t.Fatalf("offline validator %s unexpectedly selected at height %d", offlineID, targetHeight)
		}
		stepper := p2pByID[proposerID]
		if stepper == nil {
			t.Fatalf("missing online proposer service for %s at height %d", proposerID, targetHeight)
		}
		stepper.RunConsensusStep()

		waitUntil(t, 2*time.Second, func() bool {
			for _, id := range onlineIDs {
				if chains[id].GetStatus().Height < targetHeight {
					return false
				}
			}
			return true
		}, "all online nodes finalized height %d", targetHeight)
	}

	refStatus := chains[onlineIDs[0]].GetStatus()
	if refStatus.Height != uint64(rounds) {
		t.Fatalf("reference node expected height %d, got %d", rounds, refStatus.Height)
	}
	for _, id := range onlineIDs[1:] {
		status := chains[id].GetStatus()
		if status.Height != refStatus.Height {
			t.Fatalf("node %s height mismatch: got %d want %d", id, status.Height, refStatus.Height)
		}
		if status.HeadHash != refStatus.HeadHash {
			t.Fatalf("node %s head mismatch: got %s want %s", id, status.HeadHash, refStatus.HeadHash)
		}
	}

	headBlock := chains[onlineIDs[0]].GetBlocks(int(refStatus.Height), 1)
	if len(headBlock) != 1 {
		t.Fatalf("expected 1 head block, got %d", len(headBlock))
	}
	votes := headBlock[0].Votes
	if len(votes) < 3 {
		t.Fatalf("expected at least 3 votes for quorum, got %d", len(votes))
	}

	var yesStake uint64
	voters := map[string]struct{}{}
	for _, vote := range votes {
		if _, exists := voters[vote.ValidatorID]; exists {
			t.Fatalf("duplicate vote in finalized block from validator %s", vote.ValidatorID)
		}
		voters[vote.ValidatorID] = struct{}{}
		if vote.ValidatorID == offlineID {
			t.Fatalf("offline validator vote unexpectedly included in finalized block")
		}
		if _, ok := chains[vote.ValidatorID]; !ok {
			t.Fatalf("vote from non-online validator %s unexpectedly included", vote.ValidatorID)
		}
		if vote.Approved {
			yesStake += vote.EffectiveStake
		}
	}
	totalStake := chains[onlineIDs[0]].TotalEffectiveStake()
	if yesStake*3 < totalStake*2 {
		t.Fatalf("quorum not reached with one offline validator: yes=%d total=%d", yesStake, totalStake)
	}
	if yesStake >= totalStake {
		t.Fatalf("expected partial participation with one offline validator: yes=%d total=%d", yesStake, totalStake)
	}
}

func TestFiveNodeViewChangeWhenScheduledProposerOffline(t *testing.T) {
	const nodeCount = 5
	const maxPlanHeights = 40

	validatorPubByID, validatorPrivByID, validators, ids := buildDeterministicValidators(t, nodeCount, map[string]uint64{})
	offlineID := "v5"

	onlineIDs := make([]string, 0, len(ids)-1)
	for _, id := range ids {
		if id != offlineID {
			onlineIDs = append(onlineIDs, id)
		}
	}

	chains := make(map[string]*chain.Chain, len(onlineIDs))
	for _, id := range onlineIDs {
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
			t.Fatalf("new chain %s: %v", id, err)
		}
		chains[id] = c
	}

	nodeHTTP := make(map[string]*node.Server, len(onlineIDs))
	httpServers := make(map[string]*httptest.Server, len(onlineIDs))
	for _, id := range onlineIDs {
		nodeID := id
		httpServers[nodeID] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			srv := nodeHTTP[nodeID]
			if srv == nil {
				http.Error(w, "server not initialized", http.StatusServiceUnavailable)
				return
			}
			srv.ServeHTTP(w, r)
		}))
		defer httpServers[nodeID].Close()
	}

	p2pByID := make(map[string]*p2p.Service, len(onlineIDs))
	for _, id := range onlineIDs {
		peers := make([]string, 0, len(onlineIDs)-1)
		for _, peerID := range onlineIDs {
			if peerID == id {
				continue
			}
			peers = append(peers, httpServers[peerID].URL)
		}

		svc, err := p2p.NewService(p2p.Config{
			Enabled:             true,
			NodeID:              id,
			ValidatorPrivateKey: validatorPrivByID[id],
			ValidatorPubKeys:    validatorPubByID,
			Peers:               peers,
		})
		if err != nil {
			t.Fatalf("new p2p service %s: %v", id, err)
		}
		svc.AttachChain(chains[id])
		p2pByID[id] = svc
		nodeHTTP[id] = node.NewServer(chains[id], node.Config{P2PService: svc})
	}

	var targetHeight uint64
	for height := uint64(1); height <= maxPlanHeights; height++ {
		_, proposerID, err := chains[onlineIDs[0]].NextExpectedProposer()
		if err != nil {
			t.Fatalf("next proposer for height %d: %v", height, err)
		}
		if proposerID == offlineID {
			targetHeight = height
			break
		}

		stepper := p2pByID[proposerID]
		if stepper == nil {
			t.Fatalf("missing online proposer service for %s at height %d", proposerID, height)
		}
		stepper.RunConsensusStep()

		waitUntil(t, 2*time.Second, func() bool {
			for _, id := range onlineIDs {
				if chains[id].GetStatus().Height < height {
					return false
				}
			}
			return true
		}, "all online nodes finalized height %d", height)
	}
	if targetHeight == 0 {
		t.Fatalf("failed to encounter offline proposer %s within %d heights", offlineID, maxPlanHeights)
	}

	for _, id := range onlineIDs {
		if got := chains[id].GetStatus().Height; got != targetHeight-1 {
			t.Fatalf("unexpected pre-view-change height on %s: got %d want %d", id, got, targetHeight-1)
		}
	}

	advanced := false
	for step := 0; step < 8; step++ {
		for _, id := range onlineIDs {
			p2pByID[id].RunConsensusStep()
		}
		allAdvanced := true
		for _, id := range onlineIDs {
			if chains[id].GetStatus().Height < targetHeight {
				allAdvanced = false
				break
			}
		}
		if allAdvanced {
			advanced = true
			break
		}
	}
	if !advanced {
		t.Fatalf("all online nodes failed to finalize target height %d after proposer timeout/view-change", targetHeight)
	}

	head := chains[onlineIDs[0]].GetBlocks(int(targetHeight), 1)
	if len(head) != 1 {
		t.Fatalf("expected 1 block at target height %d, got %d", targetHeight, len(head))
	}
	if head[0].Round == 0 {
		t.Fatalf("expected finalized block at height %d to be round > 0 after proposer timeout", targetHeight)
	}
	if head[0].Proposer == offlineID {
		t.Fatalf("unexpected offline proposer finalized block at height %d", targetHeight)
	}
}

func waitUntil(t *testing.T, timeout time.Duration, cond func() bool, msg string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf(msg, args...)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func buildDeterministicValidators(t *testing.T, nodeCount int, stakeOverrides map[string]uint64) (map[string]string, map[string]string, []chain.GenesisValidator, []string) {
	t.Helper()

	validatorPubByID := make(map[string]string, nodeCount)
	validatorPrivByID := make(map[string]string, nodeCount)
	validators := make([]chain.GenesisValidator, 0, nodeCount)
	ids := make([]string, 0, nodeCount)
	for i := 1; i <= nodeCount; i++ {
		id := fmt.Sprintf("v%d", i)
		label := fmt.Sprintf("it-validator-%d", i)
		pub, priv, _, err := chain.DeterministicKeypair(label)
		if err != nil {
			t.Fatalf("deterministic keypair %s: %v", label, err)
		}

		stake := uint64(1_000)
		if override, ok := stakeOverrides[id]; ok && override > 0 {
			stake = override
		}

		ids = append(ids, id)
		validatorPubByID[id] = pub
		validatorPrivByID[id] = priv
		validators = append(validators, chain.GenesisValidator{
			ID:         id,
			PubKey:     pub,
			Stake:      stake,
			WorkWeight: 100,
			Active:     true,
		})
	}

	sort.Strings(ids)
	sort.SliceStable(validators, func(i, j int) bool {
		return validators[i].ID < validators[j].ID
	})

	return validatorPubByID, validatorPrivByID, validators, ids
}

func planSafeRoundsBeforeOfflineProposer(t *testing.T, validators []chain.GenesisValidator, offlineID string, maxRounds int) int {
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
		t.Fatalf("plan chain init: %v", err)
	}

	for h := 1; h <= maxRounds; h++ {
		_, proposerID, err := c.NextExpectedProposer()
		if err != nil {
			t.Fatalf("plan next proposer height %d: %v", h, err)
		}
		if proposerID == offlineID {
			return h - 1
		}
		if _, err := c.ProduceOnce(); err != nil {
			t.Fatalf("plan produce height %d: %v", h, err)
		}
	}
	return maxRounds
}

func planOfflineProposerHeightWithFallback(t *testing.T, validators []chain.GenesisValidator, offlineID string, maxHeights int) (uint64, string, bool) {
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
		t.Fatalf("plan chain init: %v", err)
	}

	for h := 1; h <= maxHeights; h++ {
		height, proposerID, err := c.NextExpectedProposer()
		if err != nil {
			t.Fatalf("plan next proposer height %d: %v", h, err)
		}
		round1, err := c.ExpectedProposerForRound(height, 1)
		if err != nil {
			t.Fatalf("plan round-1 proposer height %d: %v", h, err)
		}

		if proposerID == offlineID && round1 != offlineID {
			return height, round1, true
		}

		if _, err := c.ProduceOnce(); err != nil {
			t.Fatalf("plan produce height %d: %v", h, err)
		}
	}

	return 0, "", false
}
