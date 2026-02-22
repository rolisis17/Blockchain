package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fastpos/internal/chain"
)

func newBackupTestChain(t *testing.T) *chain.Chain {
	t.Helper()

	pub, _, valAddr, err := chain.DeterministicKeypair("backup-validator")
	if err != nil {
		t.Fatalf("deterministic keypair: %v", err)
	}
	c, err := chain.New(chain.Config{
		GenesisTimestampMs: 1_700_000_000_000,
		BaseReward:         0,
		MinTxFee:           1,
		GenesisAccounts: map[chain.Address]uint64{
			valAddr: 0,
		},
		GenesisValidators: []chain.GenesisValidator{
			{ID: "v1", PubKey: pub, Stake: 1_000, WorkWeight: 100, Active: true},
		},
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}
	return c
}

func TestMaybeWriteBackupSnapshotRetention(t *testing.T) {
	c := newBackupTestChain(t)
	backupDir := filepath.Join(t.TempDir(), "backups")

	for i := 0; i < 6; i++ {
		block, err := c.ProduceOnce()
		if err != nil {
			t.Fatalf("produce block %d: %v", i+1, err)
		}
		if _, err := maybeWriteBackupSnapshot(c, block, backupDir, 2, 2); err != nil {
			t.Fatalf("write backup for block %d: %v", block.Height, err)
		}
	}

	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatalf("read backup dir: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 backups retained, got %d", len(entries))
	}

	names := []string{entries[0].Name(), entries[1].Name()}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "snapshot-h000000000004") || !strings.Contains(joined, "snapshot-h000000000006") {
		t.Fatalf("expected retained backups for heights 4 and 6, got %v", names)
	}
}

func TestMaybeWriteBackupSnapshotDisabled(t *testing.T) {
	c := newBackupTestChain(t)
	backupDir := filepath.Join(t.TempDir(), "backups")

	block, err := c.ProduceOnce()
	if err != nil {
		t.Fatalf("produce block: %v", err)
	}
	path, err := maybeWriteBackupSnapshot(c, block, backupDir, 0, 10)
	if err != nil {
		t.Fatalf("backup write: %v", err)
	}
	if path != "" {
		t.Fatalf("expected empty backup path when disabled, got %s", path)
	}
	if _, err := os.Stat(backupDir); !os.IsNotExist(err) {
		t.Fatalf("expected no backup dir when disabled, got err=%v", err)
	}
}
