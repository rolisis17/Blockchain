package chain

import (
	"errors"
	"testing"
)

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

func TestGetTransactionPendingAndFinalized(t *testing.T) {
	pub, _, valAddr, err := DeterministicKeypair("validator-lookup")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}
	_, alicePriv, aliceAddr, err := DeterministicKeypair("alice-lookup")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}
	_, _, bobAddr, err := DeterministicKeypair("bob-lookup")
	if err != nil {
		t.Fatalf("bob keypair: %v", err)
	}

	c, err := New(Config{
		BaseReward: 0,
		GenesisAccounts: map[Address]uint64{
			valAddr:   1_000,
			aliceAddr: 1_000,
			bobAddr:   0,
		},
		GenesisValidators: []GenesisValidator{
			{
				ID:         "v1",
				PubKey:     pub,
				Stake:      1_000,
				WorkWeight: 100,
				Active:     true,
			},
		},
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}

	tx := Transaction{
		From:   aliceAddr,
		To:     bobAddr,
		Amount: 25,
		Fee:    1,
		Nonce:  1,
	}
	if err := SignTransaction(&tx, alicePriv); err != nil {
		t.Fatalf("sign tx: %v", err)
	}
	txID, err := c.SubmitTx(tx)
	if err != nil {
		t.Fatalf("submit tx: %v", err)
	}

	pending, ok := c.GetTransaction(txID)
	if !ok {
		t.Fatalf("expected pending transaction lookup to succeed")
	}
	if pending.State != TxStatePending {
		t.Fatalf("expected pending state, got %q", pending.State)
	}
	if pending.MempoolIndex == nil {
		t.Fatalf("expected pending mempool index")
	}
	if pending.Finalized != nil {
		t.Fatalf("expected no finalized metadata for pending tx")
	}
	pendingList := c.GetPendingTransactions()
	if len(pendingList) != 1 {
		t.Fatalf("expected one pending tx in pending list, got %d", len(pendingList))
	}
	if pendingList[0].TxID != txID {
		t.Fatalf("expected pending tx id %s, got %s", txID, pendingList[0].TxID)
	}

	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce block: %v", err)
	}

	finalized, ok := c.GetTransaction(txID)
	if !ok {
		t.Fatalf("expected finalized transaction lookup to succeed")
	}
	if finalized.State != TxStateFinalized {
		t.Fatalf("expected finalized state, got %q", finalized.State)
	}
	if finalized.Finalized == nil {
		t.Fatalf("expected finalized metadata")
	}
	if finalized.Finalized.Height != 1 {
		t.Fatalf("expected finalized at height 1, got %d", finalized.Finalized.Height)
	}
	if finalized.MempoolIndex != nil {
		t.Fatalf("expected nil mempool index after finalization")
	}
	if pendingAfter := c.GetPendingTransactions(); len(pendingAfter) != 0 {
		t.Fatalf("expected no pending tx after finalization, got %d", len(pendingAfter))
	}
}

func TestSubmitTxDuplicateAndFinalizedErrors(t *testing.T) {
	pub, _, valAddr, err := DeterministicKeypair("validator-dup")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}
	_, alicePriv, aliceAddr, err := DeterministicKeypair("alice-dup")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}
	_, _, bobAddr, err := DeterministicKeypair("bob-dup")
	if err != nil {
		t.Fatalf("bob keypair: %v", err)
	}

	c, err := New(Config{
		BaseReward: 0,
		GenesisAccounts: map[Address]uint64{
			valAddr:   1_000,
			aliceAddr: 1_000,
			bobAddr:   0,
		},
		GenesisValidators: []GenesisValidator{
			{
				ID:         "v1",
				PubKey:     pub,
				Stake:      1_000,
				WorkWeight: 100,
				Active:     true,
			},
		},
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}

	tx := Transaction{
		From:   aliceAddr,
		To:     bobAddr,
		Amount: 10,
		Fee:    1,
		Nonce:  1,
	}
	if err := SignTransaction(&tx, alicePriv); err != nil {
		t.Fatalf("sign tx: %v", err)
	}

	if _, err := c.SubmitTx(tx); err != nil {
		t.Fatalf("submit tx: %v", err)
	}
	if _, err := c.SubmitTx(tx); !errors.Is(err, ErrDuplicateTransaction) {
		t.Fatalf("expected ErrDuplicateTransaction, got %v", err)
	}

	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce block: %v", err)
	}
	if _, err := c.SubmitTx(tx); !errors.Is(err, ErrTransactionAlreadyFinalized) {
		t.Fatalf("expected ErrTransactionAlreadyFinalized, got %v", err)
	}
}
