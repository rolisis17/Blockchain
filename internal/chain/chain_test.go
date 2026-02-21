package chain

import "testing"

func TestTransferFinalize(t *testing.T) {
	valLabels := []string{"val-1", "val-2", "val-3"}
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

	_, alicePriv, aliceAddr, err := DeterministicKeypair("alice-test")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}
	_, _, bobAddr, err := DeterministicKeypair("bob-test")
	if err != nil {
		t.Fatalf("bob keypair: %v", err)
	}
	accounts[aliceAddr] = 1_000
	accounts[bobAddr] = 500

	c, err := New(Config{
		BaseReward:        0,
		MaxTxPerBlock:     100,
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
		Fee:    2,
		Nonce:  1,
	}
	if err := SignTransaction(&tx, alicePriv); err != nil {
		t.Fatalf("sign tx: %v", err)
	}
	if _, err := c.SubmitTx(tx); err != nil {
		t.Fatalf("submit tx: %v", err)
	}

	block, err := c.ProduceOnce()
	if err != nil {
		t.Fatalf("produce block: %v", err)
	}
	if !block.Finalized {
		t.Fatalf("expected finalized block")
	}
	if len(block.Transactions) != 1 {
		t.Fatalf("expected 1 tx in block, got %d", len(block.Transactions))
	}

	alice, ok := c.GetAccount(aliceAddr)
	if !ok {
		t.Fatalf("alice account missing")
	}
	if alice.Balance != 898 {
		t.Fatalf("unexpected alice balance: got %d want %d", alice.Balance, 898)
	}
	if alice.Nonce != 1 {
		t.Fatalf("unexpected alice nonce: got %d want %d", alice.Nonce, 1)
	}

	bob, ok := c.GetAccount(bobAddr)
	if !ok {
		t.Fatalf("bob account missing")
	}
	if bob.Balance != 600 {
		t.Fatalf("unexpected bob balance: got %d want %d", bob.Balance, 600)
	}
}
