package chain

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDelegationTransactionsOnChain(t *testing.T) {
	pubVal, _, valAddr, err := DeterministicKeypair("delegation-v1")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}
	_, alicePriv, aliceAddr, err := DeterministicKeypair("delegation-alice")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}

	c, err := New(Config{
		BaseReward: 0,
		MinTxFee:   1,
		GenesisAccounts: map[Address]uint64{
			valAddr:   0,
			aliceAddr: 500,
		},
		GenesisValidators: []GenesisValidator{
			{ID: "v1", PubKey: pubVal, Stake: 1_000, WorkWeight: 100, Active: true},
		},
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}

	delegate := Transaction{
		Kind:        TxKindDelegate,
		Amount:      100,
		Fee:         1,
		Nonce:       1,
		ValidatorID: "v1",
	}
	if err := SignTransaction(&delegate, alicePriv); err != nil {
		t.Fatalf("sign delegate tx: %v", err)
	}
	if _, err := c.SubmitTx(delegate); err != nil {
		t.Fatalf("submit delegate tx: %v", err)
	}
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce delegate block: %v", err)
	}

	alice, ok := c.GetAccount(aliceAddr)
	if !ok {
		t.Fatalf("alice account missing")
	}
	if alice.Balance != 399 {
		t.Fatalf("unexpected alice balance after delegate: got %d want 399", alice.Balance)
	}

	delegations := c.GetDelegations()
	if len(delegations) != 1 {
		t.Fatalf("expected one delegation, got %d", len(delegations))
	}
	if delegations[0].Delegator != aliceAddr || delegations[0].ValidatorID != "v1" || delegations[0].Amount != 100 {
		t.Fatalf("unexpected delegation: %+v", delegations[0])
	}

	effective, err := c.ValidatorEffectiveStake("v1")
	if err != nil {
		t.Fatalf("validator effective stake: %v", err)
	}
	if effective != 1_100 {
		t.Fatalf("unexpected effective stake after delegate: got %d want 1100", effective)
	}

	undelegate := Transaction{
		Kind:        TxKindUndelegate,
		Amount:      40,
		Fee:         1,
		Nonce:       2,
		ValidatorID: "v1",
	}
	if err := SignTransaction(&undelegate, alicePriv); err != nil {
		t.Fatalf("sign undelegate tx: %v", err)
	}
	if _, err := c.SubmitTx(undelegate); err != nil {
		t.Fatalf("submit undelegate tx: %v", err)
	}
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce undelegate block: %v", err)
	}

	alice, _ = c.GetAccount(aliceAddr)
	if alice.Balance != 438 {
		t.Fatalf("unexpected alice balance after undelegate: got %d want 438", alice.Balance)
	}

	delegations = c.GetDelegations()
	if len(delegations) != 1 {
		t.Fatalf("expected one delegation after undelegate, got %d", len(delegations))
	}
	if delegations[0].Amount != 60 {
		t.Fatalf("unexpected delegated amount after undelegate: got %d want 60", delegations[0].Amount)
	}

	effective, err = c.ValidatorEffectiveStake("v1")
	if err != nil {
		t.Fatalf("validator effective stake after undelegate: %v", err)
	}
	if effective != 1_060 {
		t.Fatalf("unexpected effective stake after undelegate: got %d want 1060", effective)
	}
}

func TestDelegationValidation(t *testing.T) {
	pubVal, _, valAddr, err := DeterministicKeypair("delegation-validate-v1")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}
	_, alicePriv, aliceAddr, err := DeterministicKeypair("delegation-validate-alice")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}

	c, err := New(Config{
		BaseReward: 0,
		MinTxFee:   1,
		GenesisAccounts: map[Address]uint64{
			valAddr:   0,
			aliceAddr: 500,
		},
		GenesisValidators: []GenesisValidator{
			{ID: "v1", PubKey: pubVal, Stake: 1_000, WorkWeight: 100, Active: true},
		},
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}

	unknownValidatorTx := Transaction{
		Kind:        TxKindDelegate,
		Amount:      10,
		Fee:         1,
		Nonce:       1,
		ValidatorID: "missing",
	}
	if err := SignTransaction(&unknownValidatorTx, alicePriv); err != nil {
		t.Fatalf("sign unknown validator tx: %v", err)
	}
	if _, err := c.SubmitTx(unknownValidatorTx); err == nil {
		t.Fatalf("expected delegate tx to unknown validator to fail")
	} else if !strings.Contains(err.Error(), "validator \"missing\" not found") {
		t.Fatalf("expected unknown validator error, got %v", err)
	}

	delegate := Transaction{
		Kind:        TxKindDelegate,
		Amount:      20,
		Fee:         1,
		Nonce:       1,
		ValidatorID: "v1",
	}
	if err := SignTransaction(&delegate, alicePriv); err != nil {
		t.Fatalf("sign delegate tx: %v", err)
	}
	if _, err := c.SubmitTx(delegate); err != nil {
		t.Fatalf("submit delegate tx: %v", err)
	}
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce delegate block: %v", err)
	}

	undelegateTooMuch := Transaction{
		Kind:        TxKindUndelegate,
		Amount:      21,
		Fee:         1,
		Nonce:       2,
		ValidatorID: "v1",
	}
	if err := SignTransaction(&undelegateTooMuch, alicePriv); err != nil {
		t.Fatalf("sign undelegate tx: %v", err)
	}
	if _, err := c.SubmitTx(undelegateTooMuch); err == nil {
		t.Fatalf("expected undelegate over delegated amount to fail")
	} else if !strings.Contains(err.Error(), "insufficient delegated stake") {
		t.Fatalf("expected insufficient delegated stake error, got %v", err)
	}
}

func TestDelegationSnapshotRoundTrip(t *testing.T) {
	pubVal, _, valAddr, err := DeterministicKeypair("delegation-snapshot-v1")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}
	_, alicePriv, aliceAddr, err := DeterministicKeypair("delegation-snapshot-alice")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}

	original, err := New(Config{
		BaseReward: 0,
		MinTxFee:   1,
		GenesisAccounts: map[Address]uint64{
			valAddr:   0,
			aliceAddr: 500,
		},
		GenesisValidators: []GenesisValidator{
			{ID: "v1", PubKey: pubVal, Stake: 1_000, WorkWeight: 100, Active: true},
		},
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}

	delegate := Transaction{
		Kind:        TxKindDelegate,
		Amount:      70,
		Fee:         1,
		Nonce:       1,
		ValidatorID: "v1",
	}
	if err := SignTransaction(&delegate, alicePriv); err != nil {
		t.Fatalf("sign delegate tx: %v", err)
	}
	if _, err := original.SubmitTx(delegate); err != nil {
		t.Fatalf("submit delegate tx: %v", err)
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

	delegations := loaded.GetDelegations()
	if len(delegations) != 1 {
		t.Fatalf("expected one delegation after snapshot load, got %d", len(delegations))
	}
	if delegations[0].Delegator != aliceAddr || delegations[0].ValidatorID != "v1" || delegations[0].Amount != 70 {
		t.Fatalf("unexpected delegation after load: %+v", delegations[0])
	}

	effective, err := loaded.ValidatorEffectiveStake("v1")
	if err != nil {
		t.Fatalf("validator effective stake after load: %v", err)
	}
	if effective != 1_070 {
		t.Fatalf("unexpected effective stake after load: got %d want 1070", effective)
	}
}
