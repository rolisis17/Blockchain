package main

import (
	"path/filepath"
	"testing"

	"fastpos/internal/chain"
)

func newMigrationTestChain(t *testing.T) *chain.Chain {
	t.Helper()

	pub, _, valAddr, err := chain.DeterministicKeypair("migration-validator")
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
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce block: %v", err)
	}
	return c
}

func TestMaybeRunStateMigrationSnapshotToSQLite(t *testing.T) {
	c := newMigrationTestChain(t)
	snapshotPath := filepath.Join(t.TempDir(), "state.json")
	sqlitePath := filepath.Join(t.TempDir(), "state.db")
	if err := c.SaveSnapshot(snapshotPath); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}

	ran, err := maybeRunStateMigration(
		[]string{
			"node",
			stateMigrateCommand,
			"-from-backend", stateBackendSnapshot,
			"-from", snapshotPath,
			"-to-backend", stateBackendSQLite,
			"-to", sqlitePath,
		},
		nil,
	)
	if err != nil {
		t.Fatalf("maybeRunStateMigration: %v", err)
	}
	if !ran {
		t.Fatalf("expected migration command to run")
	}

	loaded, err := chain.LoadSQLiteSnapshot(sqlitePath, chain.Config{})
	if err != nil {
		t.Fatalf("load sqlite snapshot: %v", err)
	}
	if loaded.GetStatus().Height != c.GetStatus().Height {
		t.Fatalf("height mismatch after migration: got %d want %d", loaded.GetStatus().Height, c.GetStatus().Height)
	}
}

func TestMaybeRunStateMigrationSQLiteToSnapshot(t *testing.T) {
	c := newMigrationTestChain(t)
	sqlitePath := filepath.Join(t.TempDir(), "state.db")
	snapshotPath := filepath.Join(t.TempDir(), "state.json")
	if err := c.SaveSQLiteSnapshot(sqlitePath); err != nil {
		t.Fatalf("save sqlite snapshot: %v", err)
	}

	ran, err := maybeRunStateMigration(
		[]string{
			"node",
			stateMigrateCommand,
			"-from-backend", stateBackendSQLite,
			"-from", sqlitePath,
			"-to-backend", stateBackendSnapshot,
			"-to", snapshotPath,
		},
		nil,
	)
	if err != nil {
		t.Fatalf("maybeRunStateMigration: %v", err)
	}
	if !ran {
		t.Fatalf("expected migration command to run")
	}

	loaded, err := chain.LoadSnapshot(snapshotPath, chain.Config{})
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}
	if loaded.GetStatus().Height != c.GetStatus().Height {
		t.Fatalf("height mismatch after migration: got %d want %d", loaded.GetStatus().Height, c.GetStatus().Height)
	}
}

func TestMaybeRunStateMigrationNoCommand(t *testing.T) {
	ran, err := maybeRunStateMigration([]string{"node"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ran {
		t.Fatalf("expected migration command not to run")
	}
}
