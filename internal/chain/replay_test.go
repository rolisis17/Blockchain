package chain

import "testing"

type replayGenesis struct {
	cfg       Config
	alicePriv string
	bobPriv   string
	aliceAddr Address
	bobAddr   Address
	carolAddr Address
}

func buildReplayGenesis(t *testing.T) replayGenesis {
	t.Helper()

	valLabels := []string{"replay-val-1", "replay-val-2", "replay-val-3"}
	validators := make([]GenesisValidator, 0, len(valLabels))
	accounts := map[Address]uint64{}
	for i, label := range valLabels {
		pub, _, addr, err := DeterministicKeypair(label)
		if err != nil {
			t.Fatalf("validator keypair: %v", err)
		}
		validators = append(validators, GenesisValidator{
			ID:         string(rune('a' + i)),
			PubKey:     pub,
			Stake:      1000,
			WorkWeight: 100,
			Active:     true,
		})
		accounts[addr] = 0
	}

	_, alicePriv, aliceAddr, err := DeterministicKeypair("replay-alice")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}
	_, bobPriv, bobAddr, err := DeterministicKeypair("replay-bob")
	if err != nil {
		t.Fatalf("bob keypair: %v", err)
	}
	_, _, carolAddr, err := DeterministicKeypair("replay-carol")
	if err != nil {
		t.Fatalf("carol keypair: %v", err)
	}

	accounts[aliceAddr] = 100_000
	accounts[bobAddr] = 100_000
	accounts[carolAddr] = 0

	cfg := Config{
		GenesisTimestampMs: 1_700_000_000_000,
		BaseReward:         1,
		MaxTxPerBlock:      2,
		MaxMempoolSize:     100,
		MinTxFee:           1,
		GenesisAccounts:    accounts,
		GenesisValidators:  validators,
	}

	return replayGenesis{
		cfg:       cfg,
		alicePriv: alicePriv,
		bobPriv:   bobPriv,
		aliceAddr: aliceAddr,
		bobAddr:   bobAddr,
		carolAddr: carolAddr,
	}
}

func TestDeterministicReplayFromGenesisAndTxLog(t *testing.T) {
	g := buildReplayGenesis(t)

	primary, err := New(g.cfg)
	if err != nil {
		t.Fatalf("new primary chain: %v", err)
	}

	txLog := make([]Transaction, 0, 6)
	mkTx := func(priv string, from, to Address, amount, fee, nonce uint64, ts int64) Transaction {
		tx := Transaction{
			From:      from,
			To:        to,
			Amount:    amount,
			Fee:       fee,
			Nonce:     nonce,
			Timestamp: ts,
		}
		if err := SignTransaction(&tx, priv); err != nil {
			t.Fatalf("sign tx: %v", err)
		}
		return tx
	}

	txLog = append(txLog,
		mkTx(g.alicePriv, g.aliceAddr, g.carolAddr, 100, 2, 1, 1_000_000_001),
		mkTx(g.bobPriv, g.bobAddr, g.carolAddr, 200, 3, 1, 1_000_000_002),
		mkTx(g.alicePriv, g.aliceAddr, g.bobAddr, 50, 2, 2, 1_000_000_003),
		mkTx(g.bobPriv, g.bobAddr, g.aliceAddr, 75, 2, 2, 1_000_000_004),
		mkTx(g.alicePriv, g.aliceAddr, g.carolAddr, 25, 1, 3, 1_000_000_005),
		mkTx(g.bobPriv, g.bobAddr, g.carolAddr, 40, 4, 3, 1_000_000_006),
	)

	for _, tx := range txLog {
		if _, err := primary.SubmitTx(tx); err != nil {
			t.Fatalf("primary submit tx: %v", err)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := primary.ProduceOnce(); err != nil {
			t.Fatalf("primary produce block %d: %v", i+1, err)
		}
	}

	replay, err := New(g.cfg)
	if err != nil {
		t.Fatalf("new replay chain: %v", err)
	}
	for _, tx := range txLog {
		if _, err := replay.SubmitTx(tx); err != nil {
			t.Fatalf("replay submit tx: %v", err)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := replay.ProduceOnce(); err != nil {
			t.Fatalf("replay produce block %d: %v", i+1, err)
		}
	}

	primaryBlocks := primary.GetBlocks(0, 100)
	replayBlocks := replay.GetBlocks(0, 100)
	if len(primaryBlocks) != len(replayBlocks) {
		t.Fatalf("block count mismatch: primary=%d replay=%d", len(primaryBlocks), len(replayBlocks))
	}
	for i := range primaryBlocks {
		if primaryBlocks[i].Hash != replayBlocks[i].Hash {
			t.Fatalf("block hash mismatch at index %d", i)
		}
		if primaryBlocks[i].StateRoot != replayBlocks[i].StateRoot {
			t.Fatalf("state root mismatch at index %d", i)
		}
	}

	addresses := []Address{g.aliceAddr, g.bobAddr, g.carolAddr}
	for _, addr := range addresses {
		pAcc, ok := primary.GetAccount(addr)
		if !ok {
			t.Fatalf("primary missing account %s", addr)
		}
		rAcc, ok := replay.GetAccount(addr)
		if !ok {
			t.Fatalf("replay missing account %s", addr)
		}
		if pAcc != rAcc {
			t.Fatalf("account mismatch for %s: primary=%+v replay=%+v", addr, pAcc, rAcc)
		}
	}
}
