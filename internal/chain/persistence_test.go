package chain

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSnapshotRoundTrip(t *testing.T) {
	valLabels := []string{"val-a", "val-b", "val-c"}
	validators := make([]GenesisValidator, 0, len(valLabels))
	accounts := map[Address]uint64{}

	for i, label := range valLabels {
		pub, _, addr, err := DeterministicKeypair(label)
		if err != nil {
			t.Fatalf("deterministic keypair: %v", err)
		}
		validators = append(validators, GenesisValidator{
			ID:         string(rune('a' + i)),
			PubKey:     pub,
			Stake:      100,
			WorkWeight: 100,
			Active:     true,
		})
		accounts[addr] = 0
	}

	_, alicePriv, aliceAddr, err := DeterministicKeypair("alice-persist")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}
	_, _, bobAddr, err := DeterministicKeypair("bob-persist")
	if err != nil {
		t.Fatalf("bob keypair: %v", err)
	}
	accounts[aliceAddr] = 5000
	accounts[bobAddr] = 1000

	original, err := New(Config{
		BlockInterval:     3 * time.Second,
		BaseReward:        7,
		MaxTxPerBlock:     200,
		GenesisAccounts:   accounts,
		GenesisValidators: validators,
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}

	tx := Transaction{
		From:   aliceAddr,
		To:     bobAddr,
		Amount: 100,
		Fee:    3,
		Nonce:  1,
	}
	if err := SignTransaction(&tx, alicePriv); err != nil {
		t.Fatalf("sign tx: %v", err)
	}
	if _, err := original.SubmitTx(tx); err != nil {
		t.Fatalf("submit tx: %v", err)
	}
	if _, err := original.ProduceOnce(); err != nil {
		t.Fatalf("produce block: %v", err)
	}

	snapshotPath := filepath.Join(t.TempDir(), "state.json")
	if err := original.SaveSnapshot(snapshotPath); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}

	loaded, err := LoadSnapshot(snapshotPath, Config{})
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}

	if loaded.GetStatus().Height != original.GetStatus().Height {
		t.Fatalf("height mismatch after load")
	}

	aliceOriginal, _ := original.GetAccount(aliceAddr)
	aliceLoaded, ok := loaded.GetAccount(aliceAddr)
	if !ok {
		t.Fatalf("alice account missing in loaded chain")
	}
	if aliceOriginal != aliceLoaded {
		t.Fatalf("alice account mismatch: got %+v want %+v", aliceLoaded, aliceOriginal)
	}

	bobOriginal, _ := original.GetAccount(bobAddr)
	bobLoaded, ok := loaded.GetAccount(bobAddr)
	if !ok {
		t.Fatalf("bob account missing in loaded chain")
	}
	if bobOriginal != bobLoaded {
		t.Fatalf("bob account mismatch: got %+v want %+v", bobLoaded, bobOriginal)
	}

	if len(loaded.GetValidators()) != len(original.GetValidators()) {
		t.Fatalf("validator count mismatch after load")
	}

	blocksLoaded := loaded.GetBlocks(0, 100)
	blocksOriginal := original.GetBlocks(0, 100)
	if len(blocksLoaded) != len(blocksOriginal) {
		t.Fatalf("block count mismatch after load")
	}
}

func TestSQLiteSnapshotRoundTrip(t *testing.T) {
	valLabels := []string{"sqlite-a", "sqlite-b", "sqlite-c"}
	validators := make([]GenesisValidator, 0, len(valLabels))
	accounts := map[Address]uint64{}

	for i, label := range valLabels {
		pub, _, addr, err := DeterministicKeypair(label)
		if err != nil {
			t.Fatalf("deterministic keypair: %v", err)
		}
		validators = append(validators, GenesisValidator{
			ID:         string(rune('a' + i)),
			PubKey:     pub,
			Stake:      100,
			WorkWeight: 100,
			Active:     true,
		})
		accounts[addr] = 0
	}

	_, alicePriv, aliceAddr, err := DeterministicKeypair("alice-sqlite")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}
	_, _, bobAddr, err := DeterministicKeypair("bob-sqlite")
	if err != nil {
		t.Fatalf("bob keypair: %v", err)
	}
	accounts[aliceAddr] = 5000
	accounts[bobAddr] = 1000

	original, err := New(Config{
		BlockInterval:     3 * time.Second,
		BaseReward:        7,
		MaxTxPerBlock:     200,
		GenesisAccounts:   accounts,
		GenesisValidators: validators,
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}

	tx := Transaction{
		From:   aliceAddr,
		To:     bobAddr,
		Amount: 100,
		Fee:    3,
		Nonce:  1,
	}
	if err := SignTransaction(&tx, alicePriv); err != nil {
		t.Fatalf("sign tx: %v", err)
	}
	if _, err := original.SubmitTx(tx); err != nil {
		t.Fatalf("submit tx: %v", err)
	}
	if _, err := original.ProduceOnce(); err != nil {
		t.Fatalf("produce block: %v", err)
	}

	sqlitePath := filepath.Join(t.TempDir(), "state.db")
	if err := original.SaveSQLiteSnapshot(sqlitePath); err != nil {
		t.Fatalf("save sqlite snapshot: %v", err)
	}

	loaded, err := LoadSQLiteSnapshot(sqlitePath, Config{})
	if err != nil {
		t.Fatalf("load sqlite snapshot: %v", err)
	}

	if loaded.GetStatus().Height != original.GetStatus().Height {
		t.Fatalf("height mismatch after sqlite load")
	}

	aliceOriginal, _ := original.GetAccount(aliceAddr)
	aliceLoaded, ok := loaded.GetAccount(aliceAddr)
	if !ok {
		t.Fatalf("alice account missing in sqlite-loaded chain")
	}
	if aliceOriginal != aliceLoaded {
		t.Fatalf("alice account mismatch: got %+v want %+v", aliceLoaded, aliceOriginal)
	}

	blocksLoaded := loaded.GetBlocks(0, 100)
	blocksOriginal := original.GetBlocks(0, 100)
	if len(blocksLoaded) != len(blocksOriginal) {
		t.Fatalf("block count mismatch after sqlite load")
	}
}

func TestLoadSQLiteSnapshotMissingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.db")
	_, err := LoadSQLiteSnapshot(path, Config{})
	if err == nil {
		t.Fatalf("expected missing sqlite snapshot error")
	}
}
