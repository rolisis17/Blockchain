package chain

import (
	"path/filepath"
	"testing"
)

func TestEpochTransitionAppliesValidatorSetUpdates(t *testing.T) {
	pub1, _, valAddr1, err := DeterministicKeypair("epoch-v1")
	if err != nil {
		t.Fatalf("validator v1 keypair: %v", err)
	}
	pub2, _, valAddr2, err := DeterministicKeypair("epoch-v2")
	if err != nil {
		t.Fatalf("validator v2 keypair: %v", err)
	}
	_, alicePriv, aliceAddr, err := DeterministicKeypair("epoch-alice")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}

	c, err := New(Config{
		BaseReward:         0,
		MinTxFee:           1,
		EpochLengthBlocks:  2,
		GenesisTimestampMs: 1_700_000_000_000,
		GenesisAccounts: map[Address]uint64{
			valAddr1:  0,
			valAddr2:  0,
			aliceAddr: 500,
		},
		GenesisValidators: []GenesisValidator{
			{ID: "v1", PubKey: pub1, Stake: 1_000, WorkWeight: 100, Active: true},
			{ID: "v2", PubKey: pub2, Stake: 1_000, WorkWeight: 100, Active: true},
		},
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}

	tx := Transaction{
		Kind:        TxKindDelegate,
		Amount:      100,
		Fee:         1,
		Nonce:       1,
		ValidatorID: "v1",
		Timestamp:   1_700_000_000_001,
	}
	if err := SignTransaction(&tx, alicePriv); err != nil {
		t.Fatalf("sign delegate tx: %v", err)
	}
	if _, err := c.SubmitTx(tx); err != nil {
		t.Fatalf("submit delegate tx: %v", err)
	}

	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce block 1: %v", err)
	}
	info := c.GetEpochInfo()
	if info.Current != 0 {
		t.Fatalf("expected epoch 0 after first block, got %d", info.Current)
	}
	stake, err := c.ValidatorEffectiveStake("v1")
	if err != nil {
		t.Fatalf("validator effective stake: %v", err)
	}
	if stake != 1_000 {
		t.Fatalf("expected v1 effective stake 1000 before epoch transition, got %d", stake)
	}

	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce block 2: %v", err)
	}
	info = c.GetEpochInfo()
	if info.Current != 1 {
		t.Fatalf("expected epoch 1 after transition block, got %d", info.Current)
	}
	if info.StartHeight != 3 {
		t.Fatalf("expected epoch start height 3, got %d", info.StartHeight)
	}
	stake, err = c.ValidatorEffectiveStake("v1")
	if err != nil {
		t.Fatalf("validator effective stake after epoch transition: %v", err)
	}
	if stake != 1_100 {
		t.Fatalf("expected v1 effective stake 1100 after epoch transition, got %d", stake)
	}
}

func TestProductSettlementAttestationChallengeFlow(t *testing.T) {
	pub, valPriv, valAddr, err := DeterministicKeypair("product-v1")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}
	_, alicePriv, aliceAddr, err := DeterministicKeypair("product-alice")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}

	c, err := New(Config{
		BaseReward:              0,
		MinTxFee:                1,
		EpochLengthBlocks:       4,
		ProductRewardBps:        2_000,
		ProductChallengeMinBond: 10,
		GenesisTimestampMs:      1_700_000_000_000,
		GenesisAccounts: map[Address]uint64{
			valAddr:   1_000,
			aliceAddr: 1_000,
		},
		GenesisValidators: []GenesisValidator{
			{ID: "v1", PubKey: pub, Stake: 1_000, WorkWeight: 100, Active: true},
		},
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}

	settleTx := Transaction{
		Kind:      TxKindProductSettle,
		To:        Address("order-1"),
		Amount:    200,
		Fee:       1,
		Nonce:     1,
		Timestamp: 1_700_000_000_001,
	}
	if err := SignTransaction(&settleTx, alicePriv); err != nil {
		t.Fatalf("sign settle tx: %v", err)
	}
	if _, err := c.SubmitTx(settleTx); err != nil {
		t.Fatalf("submit settle tx: %v", err)
	}
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce settle block: %v", err)
	}
	if c.GetProductStatus().TreasuryBalance != 200 {
		t.Fatalf("expected treasury balance 200 after settlement, got %d", c.GetProductStatus().TreasuryBalance)
	}

	attestTx := Transaction{
		Kind:        TxKindProductAttest,
		To:          Address("proof-ref-1"),
		Amount:      50,
		Fee:         1,
		Nonce:       1,
		Timestamp:   1_700_000_000_002,
		ValidatorID: "v1",
		BasisPoints: 9000,
	}
	if err := SignTransaction(&attestTx, valPriv); err != nil {
		t.Fatalf("sign attest tx: %v", err)
	}
	if _, err := c.SubmitTx(attestTx); err != nil {
		t.Fatalf("submit attest tx: %v", err)
	}
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce attest block: %v", err)
	}
	proofs := c.GetProductProofs()
	if len(proofs) != 1 {
		t.Fatalf("expected 1 product proof, got %d", len(proofs))
	}
	if proofs[0].Invalidated {
		t.Fatalf("expected proof to be valid before challenge resolution")
	}

	challengeTx := Transaction{
		Kind:      TxKindProductChallenge,
		To:        Address(proofs[0].ID),
		Amount:    20,
		Fee:       1,
		Nonce:     2,
		Timestamp: 1_700_000_000_003,
	}
	if err := SignTransaction(&challengeTx, alicePriv); err != nil {
		t.Fatalf("sign challenge tx: %v", err)
	}
	if _, err := c.SubmitTx(challengeTx); err != nil {
		t.Fatalf("submit challenge tx: %v", err)
	}
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce challenge block: %v", err)
	}
	challenges := c.GetProductChallenges()
	if len(challenges) != 1 {
		t.Fatalf("expected 1 product challenge, got %d", len(challenges))
	}
	if !challenges[0].Open {
		t.Fatalf("expected challenge to be open")
	}

	resolveTx := Transaction{
		Kind:        TxKindProductResolveChallenge,
		To:          Address(challenges[0].ID),
		Amount:      2,
		Fee:         1,
		Nonce:       2,
		Timestamp:   1_700_000_000_004,
		BasisPoints: 500,
	}
	if err := SignTransaction(&resolveTx, valPriv); err != nil {
		t.Fatalf("sign resolve tx: %v", err)
	}
	if _, err := c.SubmitTx(resolveTx); err != nil {
		t.Fatalf("submit resolve tx: %v", err)
	}
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce resolve block: %v", err)
	}

	challenges = c.GetProductChallenges()
	if len(challenges) != 1 {
		t.Fatalf("expected 1 product challenge after resolve, got %d", len(challenges))
	}
	if challenges[0].Open {
		t.Fatalf("expected challenge to be closed after resolve")
	}
	if !challenges[0].Successful {
		t.Fatalf("expected challenge to be successful")
	}
	if challenges[0].SlashBasisPoints != 500 {
		t.Fatalf("expected slash basis points 500, got %d", challenges[0].SlashBasisPoints)
	}

	proofs = c.GetProductProofs()
	if len(proofs) != 1 {
		t.Fatalf("expected 1 product proof after resolve, got %d", len(proofs))
	}
	if !proofs[0].Invalidated {
		t.Fatalf("expected proof to be invalidated after successful challenge")
	}

	validator, ok := c.GetValidator("v1")
	if !ok {
		t.Fatalf("validator v1 not found")
	}
	if validator.Stake != 950 {
		t.Fatalf("expected validator stake 950 after 5%% slash, got %d", validator.Stake)
	}
	if !validator.Jailed {
		t.Fatalf("expected validator to be jailed after successful challenge")
	}

	alice, ok := c.GetAccount(aliceAddr)
	if !ok {
		t.Fatalf("alice account not found")
	}
	if alice.Balance != 800 {
		t.Fatalf("expected alice balance 800 after payout, got %d", alice.Balance)
	}
	if c.GetProductStatus().TreasuryBalance != 198 {
		t.Fatalf("expected treasury balance 198 after payout, got %d", c.GetProductStatus().TreasuryBalance)
	}
}

func TestProductSnapshotRoundTrip(t *testing.T) {
	pub, valPriv, valAddr, err := DeterministicKeypair("product-snapshot-v1")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}
	_, alicePriv, aliceAddr, err := DeterministicKeypair("product-snapshot-alice")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}

	original, err := New(Config{
		BaseReward:              0,
		MinTxFee:                1,
		EpochLengthBlocks:       3,
		ProductRewardBps:        1_500,
		ProductChallengeMinBond: 10,
		GenesisTimestampMs:      1_700_000_000_000,
		GenesisAccounts: map[Address]uint64{
			valAddr:   1_000,
			aliceAddr: 1_000,
		},
		GenesisValidators: []GenesisValidator{
			{ID: "v1", PubKey: pub, Stake: 1_000, WorkWeight: 100, Active: true},
		},
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}

	settleTx := Transaction{
		Kind:      TxKindProductSettle,
		To:        Address("order-snapshot"),
		Amount:    120,
		Fee:       1,
		Nonce:     1,
		Timestamp: 1_700_000_000_001,
	}
	if err := SignTransaction(&settleTx, alicePriv); err != nil {
		t.Fatalf("sign settle tx: %v", err)
	}
	if _, err := original.SubmitTx(settleTx); err != nil {
		t.Fatalf("submit settle tx: %v", err)
	}
	if _, err := original.ProduceOnce(); err != nil {
		t.Fatalf("produce settle block: %v", err)
	}

	attestTx := Transaction{
		Kind:        TxKindProductAttest,
		To:          Address("proof-snapshot"),
		Amount:      10,
		Fee:         1,
		Nonce:       1,
		Timestamp:   1_700_000_000_002,
		ValidatorID: "v1",
		BasisPoints: 8000,
	}
	if err := SignTransaction(&attestTx, valPriv); err != nil {
		t.Fatalf("sign attest tx: %v", err)
	}
	if _, err := original.SubmitTx(attestTx); err != nil {
		t.Fatalf("submit attest tx: %v", err)
	}
	if _, err := original.ProduceOnce(); err != nil {
		t.Fatalf("produce attest block: %v", err)
	}

	snapshotPath := filepath.Join(t.TempDir(), "state.json")
	if err := original.SaveSnapshot(snapshotPath); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}

	loaded, err := LoadSnapshot(snapshotPath, Config{})
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}

	origStatus := original.GetProductStatus()
	loadedStatus := loaded.GetProductStatus()
	if loadedStatus.TreasuryBalance != origStatus.TreasuryBalance {
		t.Fatalf("treasury mismatch after load: got %d want %d", loadedStatus.TreasuryBalance, origStatus.TreasuryBalance)
	}
	if loadedStatus.RewardBasisPoints != origStatus.RewardBasisPoints {
		t.Fatalf("reward bps mismatch after load: got %d want %d", loadedStatus.RewardBasisPoints, origStatus.RewardBasisPoints)
	}
	if len(loaded.GetProductProofs()) != len(original.GetProductProofs()) {
		t.Fatalf("proof count mismatch after load: got %d want %d", len(loaded.GetProductProofs()), len(original.GetProductProofs()))
	}

	origEpoch := original.GetEpochInfo()
	loadedEpoch := loaded.GetEpochInfo()
	if loadedEpoch.Current != origEpoch.Current {
		t.Fatalf("epoch mismatch after load: got %d want %d", loadedEpoch.Current, origEpoch.Current)
	}
	if loadedEpoch.Length != origEpoch.Length {
		t.Fatalf("epoch length mismatch after load: got %d want %d", loadedEpoch.Length, origEpoch.Length)
	}
}
