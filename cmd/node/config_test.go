package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRunConfig_Defaults(t *testing.T) {
	cfg, err := parseRunConfig([]string{"node"}, "env-token")
	if err != nil {
		t.Fatalf("parse run config: %v", err)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Fatalf("expected default http addr :8080, got %s", cfg.HTTPAddr)
	}
	if cfg.AdminToken != "env-token" {
		t.Fatalf("expected admin token from env, got %s", cfg.AdminToken)
	}
	if cfg.StateBackend != stateBackendSnapshot {
		t.Fatalf("expected default state backend %s, got %s", stateBackendSnapshot, cfg.StateBackend)
	}
	if cfg.P2PProposerTimeout != 2 {
		t.Fatalf("expected default p2p proposer timeout 2, got %d", cfg.P2PProposerTimeout)
	}
	if cfg.P2PMaxRoundLookahead != 16 {
		t.Fatalf("expected default p2p max round lookahead 16, got %d", cfg.P2PMaxRoundLookahead)
	}
	if cfg.P2PPeerBackoffInit.String() != "500ms" {
		t.Fatalf("expected default p2p peer backoff initial 500ms, got %s", cfg.P2PPeerBackoffInit)
	}
	if cfg.P2PPeerBackoffMax.String() != "15s" {
		t.Fatalf("expected default p2p peer backoff max 15s, got %s", cfg.P2PPeerBackoffMax)
	}
	if cfg.P2PInboundRateLimit != 120 {
		t.Fatalf("expected default p2p inbound rate limit 120, got %d", cfg.P2PInboundRateLimit)
	}
	if cfg.P2PInboundRateWindow.String() != "1s" {
		t.Fatalf("expected default p2p inbound rate window 1s, got %s", cfg.P2PInboundRateWindow)
	}
	if cfg.MinJailBlocks != 0 {
		t.Fatalf("expected default min jail blocks 0 (auto), got %d", cfg.MinJailBlocks)
	}
	if cfg.EpochLengthBlocks != 1 {
		t.Fatalf("expected default epoch length blocks 1, got %d", cfg.EpochLengthBlocks)
	}
	if cfg.ProductRewardBps != 2000 {
		t.Fatalf("expected default product reward bps 2000, got %d", cfg.ProductRewardBps)
	}
	if cfg.ProductChallengeMinBond != 10 {
		t.Fatalf("expected default product challenge min bond 10, got %d", cfg.ProductChallengeMinBond)
	}
	if cfg.ProductUnitPrice != 1 {
		t.Fatalf("expected default product unit price 1, got %d", cfg.ProductUnitPrice)
	}
	if cfg.MaxPendingPerAccount != 64 {
		t.Fatalf("expected default max pending per account 64, got %d", cfg.MaxPendingPerAccount)
	}
	if cfg.MaxMempoolAgeBlocks != 120 {
		t.Fatalf("expected default max mempool age blocks 120, got %d", cfg.MaxMempoolAgeBlocks)
	}
	if cfg.BackupDir != "./data/backups" {
		t.Fatalf("expected default backup dir ./data/backups, got %s", cfg.BackupDir)
	}
	if cfg.BackupEveryBlocks != 0 {
		t.Fatalf("expected default backup every blocks 0, got %d", cfg.BackupEveryBlocks)
	}
	if cfg.BackupRetain != 20 {
		t.Fatalf("expected default backup retain 20, got %d", cfg.BackupRetain)
	}
}

func TestParseRunConfig_ConfigFileAndCLIOverride(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "node.yaml")
	content := []byte("http: ':7777'\nstateBackend: 'sqlite'\nstate: './data/state.db'\nbackupDir: './data/backups-custom'\nbackupEveryBlocks: 10\nbackupRetain: 7\nblockInterval: '3s'\nminJailBlocks: 6\nepochLengthBlocks: 4\nmaxMempoolSize: 111\nmaxPendingTxPerAccount: 22\nmaxMempoolTxAgeBlocks: 30\nminTxFee: 9\nproductRewardBps: 2500\nproductChallengeMinBond: 15\nproductUnitPrice: 3\nadminToken: 'from-file'\np2pPeerBackoffInitial: '750ms'\np2pPeerBackoffMax: '9s'\np2pInboundRateLimitPerPeer: 77\np2pInboundRateWindow: '5s'\n")
	if err := os.WriteFile(configPath, content, 0o644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := parseRunConfig([]string{
		"node",
		"-config", configPath,
		"-http", ":8888",
		"-admin-token", "from-cli",
	}, "env-token")
	if err != nil {
		t.Fatalf("parse run config: %v", err)
	}
	if cfg.HTTPAddr != ":8888" {
		t.Fatalf("expected CLI http override :8888, got %s", cfg.HTTPAddr)
	}
	if cfg.AdminToken != "from-cli" {
		t.Fatalf("expected CLI admin token override, got %s", cfg.AdminToken)
	}
	if cfg.MaxMempoolSize != 111 {
		t.Fatalf("expected max mempool from file 111, got %d", cfg.MaxMempoolSize)
	}
	if cfg.MaxPendingPerAccount != 22 {
		t.Fatalf("expected max pending per account from file 22, got %d", cfg.MaxPendingPerAccount)
	}
	if cfg.MaxMempoolAgeBlocks != 30 {
		t.Fatalf("expected max mempool age blocks from file 30, got %d", cfg.MaxMempoolAgeBlocks)
	}
	if cfg.MinTxFee != 9 {
		t.Fatalf("expected min tx fee from file 9, got %d", cfg.MinTxFee)
	}
	if cfg.BlockInterval.String() != "3s" {
		t.Fatalf("expected block interval 3s from file, got %s", cfg.BlockInterval)
	}
	if cfg.MinJailBlocks != 6 {
		t.Fatalf("expected min jail blocks from file 6, got %d", cfg.MinJailBlocks)
	}
	if cfg.EpochLengthBlocks != 4 {
		t.Fatalf("expected epoch length blocks from file 4, got %d", cfg.EpochLengthBlocks)
	}
	if cfg.ProductRewardBps != 2500 {
		t.Fatalf("expected product reward bps from file 2500, got %d", cfg.ProductRewardBps)
	}
	if cfg.ProductChallengeMinBond != 15 {
		t.Fatalf("expected product challenge min bond from file 15, got %d", cfg.ProductChallengeMinBond)
	}
	if cfg.ProductUnitPrice != 3 {
		t.Fatalf("expected product unit price from file 3, got %d", cfg.ProductUnitPrice)
	}
	if cfg.StateBackend != stateBackendSQLite {
		t.Fatalf("expected state backend sqlite from file, got %s", cfg.StateBackend)
	}
	if cfg.StatePath != "./data/state.db" {
		t.Fatalf("expected state path from file, got %s", cfg.StatePath)
	}
	if cfg.BackupDir != "./data/backups-custom" {
		t.Fatalf("expected backup dir from file, got %s", cfg.BackupDir)
	}
	if cfg.BackupEveryBlocks != 10 {
		t.Fatalf("expected backup every blocks from file 10, got %d", cfg.BackupEveryBlocks)
	}
	if cfg.BackupRetain != 7 {
		t.Fatalf("expected backup retain from file 7, got %d", cfg.BackupRetain)
	}
	if cfg.P2PPeerBackoffInit.String() != "750ms" {
		t.Fatalf("expected p2p peer backoff initial 750ms from file, got %s", cfg.P2PPeerBackoffInit)
	}
	if cfg.P2PPeerBackoffMax.String() != "9s" {
		t.Fatalf("expected p2p peer backoff max 9s from file, got %s", cfg.P2PPeerBackoffMax)
	}
	if cfg.P2PInboundRateLimit != 77 {
		t.Fatalf("expected p2p inbound rate limit 77 from file, got %d", cfg.P2PInboundRateLimit)
	}
	if cfg.P2PInboundRateWindow.String() != "5s" {
		t.Fatalf("expected p2p inbound rate window 5s from file, got %s", cfg.P2PInboundRateWindow)
	}
}

func TestParseRunConfig_P2PValidationAndPeers(t *testing.T) {
	_, err := parseRunConfig([]string{
		"node",
		"-p2p-enabled=true",
	}, "")
	if err == nil {
		t.Fatalf("expected parse error when p2p is enabled without node-id")
	}

	cfg, err := parseRunConfig([]string{
		"node",
		"-p2p-enabled=true",
		"-node-id=v1",
		"-peers", "http://127.0.0.1:18082, http://127.0.0.1:18083/",
		"-p2p-proposer-timeout-ticks", "3",
		"-p2p-max-round-lookahead", "12",
		"-p2p-peer-backoff-initial", "250ms",
		"-p2p-peer-backoff-max", "4s",
		"-p2p-inbound-rate-limit-per-peer", "50",
		"-p2p-inbound-rate-window", "2s",
		"-state-backend", "sqlite",
		"-state", "./tmp/state.db",
	}, "")
	if err != nil {
		t.Fatalf("parse run config: %v", err)
	}
	if !cfg.P2PEnabled {
		t.Fatalf("expected p2p enabled")
	}
	if cfg.NodeID != "v1" {
		t.Fatalf("expected node id v1, got %s", cfg.NodeID)
	}
	if len(cfg.Peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(cfg.Peers))
	}
	if cfg.P2PProposerTimeout != 3 {
		t.Fatalf("expected p2p proposer timeout 3, got %d", cfg.P2PProposerTimeout)
	}
	if cfg.P2PMaxRoundLookahead != 12 {
		t.Fatalf("expected p2p max round lookahead 12, got %d", cfg.P2PMaxRoundLookahead)
	}
	if cfg.P2PPeerBackoffInit.String() != "250ms" {
		t.Fatalf("expected p2p peer backoff initial 250ms, got %s", cfg.P2PPeerBackoffInit)
	}
	if cfg.P2PPeerBackoffMax.String() != "4s" {
		t.Fatalf("expected p2p peer backoff max 4s, got %s", cfg.P2PPeerBackoffMax)
	}
	if cfg.P2PInboundRateLimit != 50 {
		t.Fatalf("expected p2p inbound rate limit 50, got %d", cfg.P2PInboundRateLimit)
	}
	if cfg.P2PInboundRateWindow.String() != "2s" {
		t.Fatalf("expected p2p inbound rate window 2s, got %s", cfg.P2PInboundRateWindow)
	}
	if cfg.StateBackend != stateBackendSQLite {
		t.Fatalf("expected state backend sqlite, got %s", cfg.StateBackend)
	}
	if cfg.StatePath != "./tmp/state.db" {
		t.Fatalf("expected state path ./tmp/state.db, got %s", cfg.StatePath)
	}

	_, err = parseRunConfig([]string{
		"node",
		"-p2p-proposer-timeout-ticks", "0",
	}, "")
	if err == nil {
		t.Fatalf("expected parse error when p2p proposer timeout is 0")
	}

	_, err = parseRunConfig([]string{
		"node",
		"-p2p-peer-backoff-initial", "2s",
		"-p2p-peer-backoff-max", "1s",
	}, "")
	if err == nil {
		t.Fatalf("expected parse error when p2p peer backoff max < initial")
	}

	_, err = parseRunConfig([]string{
		"node",
		"-state-backend", "unknown",
	}, "")
	if err == nil {
		t.Fatalf("expected parse error when state backend is invalid")
	}

	_, err = parseRunConfig([]string{
		"node",
		"-backup-every-blocks", "5",
		"-backup-dir", "",
	}, "")
	if err == nil {
		t.Fatalf("expected parse error when backups are enabled with empty backup dir")
	}
}
