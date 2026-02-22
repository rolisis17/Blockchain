package chain

import (
	"strings"
	"testing"
)

func TestValidatorLifecycleTransactionsOnChain(t *testing.T) {
	pub1, priv1, addr1, err := DeterministicKeypair("validator-tx-v1")
	if err != nil {
		t.Fatalf("validator v1 keypair: %v", err)
	}
	pub2, _, addr2, err := DeterministicKeypair("validator-tx-v2")
	if err != nil {
		t.Fatalf("validator v2 keypair: %v", err)
	}

	c, err := New(Config{
		BaseReward:      0,
		MinTxFee:        1,
		MinJailBlocks:   2,
		GenesisAccounts: map[Address]uint64{addr1: 500, addr2: 0},
		GenesisValidators: []GenesisValidator{
			{ID: "v1", PubKey: pub1, Stake: 1_000, WorkWeight: 100, Active: true},
			{ID: "v2", PubKey: pub2, Stake: 1_000, WorkWeight: 100, Active: true},
		},
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}

	signAndSubmit := func(tx Transaction) Block {
		t.Helper()
		if err := SignTransaction(&tx, priv1); err != nil {
			t.Fatalf("sign tx: %v", err)
		}
		if _, err := c.SubmitTx(tx); err != nil {
			t.Fatalf("submit tx: %v", err)
		}
		block, err := c.ProduceOnce()
		if err != nil {
			t.Fatalf("produce block: %v", err)
		}
		return block
	}

	bondBefore, _ := c.GetAccount(addr1)
	bondTx := Transaction{
		Kind:        TxKindValidatorBond,
		Amount:      100,
		Fee:         1,
		Nonce:       1,
		ValidatorID: "v1",
	}
	bondBlock := signAndSubmit(bondTx)
	bondAfter, _ := c.GetAccount(addr1)
	reward := uint64(0)
	if bondBlock.Proposer == "v1" {
		reward = bondTx.Fee
	}
	wantBondBalance := bondBefore.Balance - bondTx.Amount - bondTx.Fee + reward
	if bondAfter.Balance != wantBondBalance {
		t.Fatalf("unexpected balance after bond: got %d want %d", bondAfter.Balance, wantBondBalance)
	}
	v1, _ := c.GetValidator("v1")
	if v1.Stake != 1_100 {
		t.Fatalf("expected stake 1100 after bond, got %d", v1.Stake)
	}

	unbondBefore, _ := c.GetAccount(addr1)
	unbondTx := Transaction{
		Kind:        TxKindValidatorUnbond,
		Amount:      40,
		Fee:         1,
		Nonce:       2,
		ValidatorID: "v1",
	}
	unbondBlock := signAndSubmit(unbondTx)
	unbondAfter, _ := c.GetAccount(addr1)
	reward = 0
	if unbondBlock.Proposer == "v1" {
		reward = unbondTx.Fee
	}
	wantUnbondBalance := unbondBefore.Balance - unbondTx.Fee + unbondTx.Amount + reward
	if unbondAfter.Balance != wantUnbondBalance {
		t.Fatalf("unexpected balance after unbond: got %d want %d", unbondAfter.Balance, wantUnbondBalance)
	}
	v1, _ = c.GetValidator("v1")
	if v1.Stake != 1_060 {
		t.Fatalf("expected stake 1060 after unbond, got %d", v1.Stake)
	}

	slashBefore, _ := c.GetAccount(addr1)
	slashTx := Transaction{
		Kind:        TxKindValidatorSlash,
		Fee:         1,
		Nonce:       3,
		ValidatorID: "v1",
		BasisPoints: 500,
	}
	slashBlock := signAndSubmit(slashTx)
	slashAfter, _ := c.GetAccount(addr1)
	reward = 0
	if slashBlock.Proposer == "v1" {
		reward = slashTx.Fee
	}
	wantSlashBalance := slashBefore.Balance - slashTx.Fee + reward
	if slashAfter.Balance != wantSlashBalance {
		t.Fatalf("unexpected balance after slash: got %d want %d", slashAfter.Balance, wantSlashBalance)
	}
	v1, _ = c.GetValidator("v1")
	if v1.Stake != 1_007 {
		t.Fatalf("expected stake 1007 after slash, got %d", v1.Stake)
	}

	jailBefore, _ := c.GetAccount(addr1)
	jailTx := Transaction{
		Kind:        TxKindValidatorJail,
		Fee:         1,
		Nonce:       4,
		ValidatorID: "v1",
	}
	jailBlock := signAndSubmit(jailTx)
	jailAfter, _ := c.GetAccount(addr1)
	reward = 0
	if jailBlock.Proposer == "v1" {
		reward = jailTx.Fee
	}
	wantJailBalance := jailBefore.Balance - jailTx.Fee + reward
	if jailAfter.Balance != wantJailBalance {
		t.Fatalf("unexpected balance after jail: got %d want %d", jailAfter.Balance, wantJailBalance)
	}
	v1, _ = c.GetValidator("v1")
	if !v1.Jailed {
		t.Fatalf("expected validator v1 to be jailed")
	}
	effective, err := c.ValidatorEffectiveStake("v1")
	if err != nil {
		t.Fatalf("validator effective stake: %v", err)
	}
	if effective != 0 {
		t.Fatalf("expected effective stake 0 after jail, got %d", effective)
	}
	_, proposerID, err := c.NextExpectedProposer()
	if err != nil {
		t.Fatalf("next expected proposer: %v", err)
	}
	if proposerID != "v2" {
		t.Fatalf("expected proposer v2 after v1 jail, got %s", proposerID)
	}

	unjailTx := Transaction{
		Kind:        TxKindValidatorUnjail,
		Fee:         1,
		Nonce:       5,
		ValidatorID: "v1",
	}
	if err := SignTransaction(&unjailTx, priv1); err != nil {
		t.Fatalf("sign unjail tx: %v", err)
	}
	if _, err := c.SubmitTx(unjailTx); err == nil {
		t.Fatalf("expected unjail submit to fail before minimum jail duration")
	} else if !strings.Contains(err.Error(), ErrValidatorStillJailed.Error()) {
		t.Fatalf("expected still jailed error, got %v", err)
	}

	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce block while jailed: %v", err)
	}
	if _, err := c.SubmitTx(unjailTx); err != nil {
		t.Fatalf("submit mature unjail tx: %v", err)
	}
	unjailBlock, err := c.ProduceOnce()
	if err != nil {
		t.Fatalf("produce block with unjail tx: %v", err)
	}

	v1, _ = c.GetValidator("v1")
	if v1.Jailed {
		t.Fatalf("expected validator v1 to be unjailed")
	}
	if v1.JailedUntilHeight != 0 {
		t.Fatalf("expected jailedUntilHeight to reset to 0, got %d", v1.JailedUntilHeight)
	}
	effective, err = c.ValidatorEffectiveStake("v1")
	if err != nil {
		t.Fatalf("validator effective stake after unjail: %v", err)
	}
	if effective == 0 {
		t.Fatalf("expected non-zero effective stake after unjail")
	}
	_ = unjailBlock
}

func TestValidatorBondTransactionSignerMustMatchValidator(t *testing.T) {
	pub, _, valAddr, err := DeterministicKeypair("validator-bond-mismatch-v1")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}
	_, alicePriv, aliceAddr, err := DeterministicKeypair("validator-bond-mismatch-alice")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}

	c, err := New(Config{
		GenesisAccounts: map[Address]uint64{
			valAddr:   0,
			aliceAddr: 100,
		},
		GenesisValidators: []GenesisValidator{
			{ID: "v1", PubKey: pub, Stake: 1_000, WorkWeight: 100, Active: true},
		},
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}

	tx := Transaction{
		Kind:        TxKindValidatorBond,
		Amount:      10,
		Fee:         1,
		Nonce:       1,
		ValidatorID: "v1",
	}
	if err := SignTransaction(&tx, alicePriv); err != nil {
		t.Fatalf("sign tx: %v", err)
	}
	if _, err := c.SubmitTx(tx); err == nil {
		t.Fatalf("expected submit error for signer/validator mismatch")
	} else if !strings.Contains(err.Error(), "does not match validator") {
		t.Fatalf("expected mismatch validator error, got %v", err)
	}
}
