package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"fastpos/internal/chain"
	"fastpos/internal/node"
)

func newSyncChain(t *testing.T, produced int) (*chain.Chain, chain.Config) {
	t.Helper()

	accounts, validators, genesisTimestampMs, _, err := defaultGenesis()
	if err != nil {
		t.Fatalf("default genesis: %v", err)
	}

	cfg := chain.Config{
		BlockInterval:      2 * time.Second,
		GenesisTimestampMs: genesisTimestampMs,
		BaseReward:         1,
		MaxTxPerBlock:      500,
		MaxMempoolSize:     20_000,
		MinTxFee:           1,
		GenesisAccounts:    accounts,
		GenesisValidators:  validators,
	}
	c, err := chain.New(cfg)
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}
	for i := 0; i < produced; i++ {
		if _, err := c.ProduceOnce(); err != nil {
			t.Fatalf("produce block %d: %v", i+1, err)
		}
	}
	return c, cfg
}

func TestSyncChainFromPeers_BlockCatchUp(t *testing.T) {
	source, chainCfg := newSyncChain(t, 6)
	target, _ := newSyncChain(t, 2)

	peer := httptest.NewServer(node.NewServer(source, node.Config{}))
	defer peer.Close()

	synced, result, err := syncChainFromPeers(target, chainCfg, []string{peer.URL}, nil)
	if err != nil {
		t.Fatalf("sync chain from peers: %v", err)
	}
	if !result.Used {
		t.Fatalf("expected sync result to be used")
	}
	if result.Mode != "blocks" {
		t.Fatalf("expected block sync mode, got %s", result.Mode)
	}

	sourceStatus := source.GetStatus()
	syncedStatus := synced.GetStatus()
	if syncedStatus.Height != sourceStatus.Height {
		t.Fatalf("expected synced height %d, got %d", sourceStatus.Height, syncedStatus.Height)
	}
	if syncedStatus.HeadHash != sourceStatus.HeadHash {
		t.Fatalf("expected synced head hash %s, got %s", sourceStatus.HeadHash, syncedStatus.HeadHash)
	}
}

func TestSyncChainFromPeers_SnapshotFallback(t *testing.T) {
	source, chainCfg := newSyncChain(t, 5)
	target, _ := newSyncChain(t, 1)

	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			writeJSON(t, w, source.GetStatus())
			return
		case "/blocks":
			from, _ := strconv.Atoi(r.URL.Query().Get("from"))
			limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
			blocks := source.GetBlocks(from, limit)
			if len(blocks) > 0 {
				blocks[0].PrevHash = "corrupted-prev-hash"
			}
			writeJSON(t, w, blocks)
			return
		case "/sync/snapshot":
			writeJSON(t, w, source.Snapshot())
			return
		default:
			http.NotFound(w, r)
			return
		}
	}))
	defer peer.Close()

	synced, result, err := syncChainFromPeers(target, chainCfg, []string{peer.URL}, nil)
	if err != nil {
		t.Fatalf("sync chain from peers: %v", err)
	}
	if !result.Used {
		t.Fatalf("expected sync result to be used")
	}
	if result.Mode != "snapshot" {
		t.Fatalf("expected snapshot sync mode, got %s", result.Mode)
	}

	sourceStatus := source.GetStatus()
	syncedStatus := synced.GetStatus()
	if syncedStatus.Height != sourceStatus.Height {
		t.Fatalf("expected synced height %d, got %d", sourceStatus.Height, syncedStatus.Height)
	}
	if syncedStatus.HeadHash != sourceStatus.HeadHash {
		t.Fatalf("expected synced head hash %s, got %s", sourceStatus.HeadHash, syncedStatus.HeadHash)
	}
}

func TestSyncChainFromPeers_NoReachablePeer(t *testing.T) {
	target, chainCfg := newSyncChain(t, 2)
	originalStatus := target.GetStatus()

	synced, result, err := syncChainFromPeers(target, chainCfg, []string{"http://127.0.0.1:1"}, nil)
	if err != nil {
		t.Fatalf("expected no error when peers are unreachable, got %v", err)
	}
	if result.Used {
		t.Fatalf("expected sync result used=false")
	}
	if synced.GetStatus() != originalStatus {
		t.Fatalf("expected chain status to remain unchanged")
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("encode json: %v", err)
	}
}
