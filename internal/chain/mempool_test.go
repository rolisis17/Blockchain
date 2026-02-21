package chain

import (
	"errors"
	"testing"
)

func newMempoolTestChain(t *testing.T, cfg Config) (*Chain, string, Address, Address) {
	t.Helper()

	pub, _, valAddr, err := DeterministicKeypair("validator-mempool")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}
	_, alicePriv, aliceAddr, err := DeterministicKeypair("alice-mempool")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}
	_, _, bobAddr, err := DeterministicKeypair("bob-mempool")
	if err != nil {
		t.Fatalf("bob keypair: %v", err)
	}

	cfg.GenesisAccounts = map[Address]uint64{
		valAddr:   0,
		aliceAddr: 10_000,
		bobAddr:   0,
	}
	cfg.GenesisValidators = []GenesisValidator{{
		ID:         "v1",
		PubKey:     pub,
		Stake:      1_000,
		WorkWeight: 100,
		Active:     true,
	}}

	c, err := New(cfg)
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}
	return c, alicePriv, aliceAddr, bobAddr
}

func signTxForTest(t *testing.T, priv string, from, to Address, amount, fee, nonce uint64) Transaction {
	t.Helper()
	tx := Transaction{
		From:   from,
		To:     to,
		Amount: amount,
		Fee:    fee,
		Nonce:  nonce,
	}
	if err := SignTransaction(&tx, priv); err != nil {
		t.Fatalf("sign tx: %v", err)
	}
	return tx
}

func TestMinFeePolicy(t *testing.T) {
	c, alicePriv, aliceAddr, bobAddr := newMempoolTestChain(t, Config{
		BaseReward:     0,
		MaxTxPerBlock:  100,
		MaxMempoolSize: 100,
		MinTxFee:       5,
	})

	tx := signTxForTest(t, alicePriv, aliceAddr, bobAddr, 10, 1, 1)
	_, err := c.SubmitTx(tx)
	if !errors.Is(err, ErrTxFeeTooLow) {
		t.Fatalf("expected ErrTxFeeTooLow, got %v", err)
	}

	m := c.GetMetrics()
	if m.RejectedTxTotal != 1 {
		t.Fatalf("expected rejected tx total 1, got %d", m.RejectedTxTotal)
	}
	if m.SubmittedTxTotal != 0 {
		t.Fatalf("expected submitted tx total 0, got %d", m.SubmittedTxTotal)
	}
}

func TestMempoolEvictionWithHigherFeeReplacement(t *testing.T) {
	c, alicePriv, aliceAddr, bobAddr := newMempoolTestChain(t, Config{
		BaseReward:     0,
		MaxTxPerBlock:  100,
		MaxMempoolSize: 2,
		MinTxFee:       1,
	})

	tx1 := signTxForTest(t, alicePriv, aliceAddr, bobAddr, 10, 1, 1)
	tx2 := signTxForTest(t, alicePriv, aliceAddr, bobAddr, 20, 1, 2)
	tx3 := signTxForTest(t, alicePriv, aliceAddr, bobAddr, 20, 5, 2)

	if _, err := c.SubmitTx(tx1); err != nil {
		t.Fatalf("submit tx1: %v", err)
	}
	if _, err := c.SubmitTx(tx2); err != nil {
		t.Fatalf("submit tx2: %v", err)
	}
	if _, err := c.SubmitTx(tx3); err != nil {
		t.Fatalf("submit tx3: %v", err)
	}

	block, err := c.ProduceOnce()
	if err != nil {
		t.Fatalf("produce block: %v", err)
	}
	if len(block.Transactions) != 2 {
		t.Fatalf("expected 2 included txs, got %d", len(block.Transactions))
	}
	if block.Transactions[0].ID() != tx1.ID() || block.Transactions[1].ID() != tx3.ID() {
		t.Fatalf("expected tx1 and tx3 in block, got %s and %s", block.Transactions[0].ID(), block.Transactions[1].ID())
	}

	bob, ok := c.GetAccount(bobAddr)
	if !ok {
		t.Fatalf("bob account missing")
	}
	if bob.Balance != 30 {
		t.Fatalf("expected bob balance 30, got %d", bob.Balance)
	}

	m := c.GetMetrics()
	if m.EvictedTxTotal != 1 {
		t.Fatalf("expected evicted tx total 1, got %d", m.EvictedTxTotal)
	}
	if m.SubmittedTxTotal != 3 {
		t.Fatalf("expected submitted tx total 3, got %d", m.SubmittedTxTotal)
	}
}
