package chain

import (
	"errors"
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

func TestProductSettlementRejectsDuplicateReferencePerPayer(t *testing.T) {
	pub, _, valAddr, err := DeterministicKeypair("product-settle-idempotent-v1")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}
	_, alicePriv, aliceAddr, err := DeterministicKeypair("product-settle-idempotent-alice")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}
	_, bobPriv, bobAddr, err := DeterministicKeypair("product-settle-idempotent-bob")
	if err != nil {
		t.Fatalf("bob keypair: %v", err)
	}

	c, err := New(Config{
		BaseReward:              0,
		MinTxFee:                1,
		ProductChallengeMinBond: 10,
		GenesisTimestampMs:      1_700_000_100_000,
		GenesisAccounts: map[Address]uint64{
			valAddr:   1_000,
			aliceAddr: 1_000,
			bobAddr:   1_000,
		},
		GenesisValidators: []GenesisValidator{
			{ID: "v1", PubKey: pub, Stake: 1_000, WorkWeight: 100, Active: true},
		},
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}

	first := Transaction{
		Kind:      TxKindProductSettle,
		To:        Address("invoice-42"),
		Amount:    100,
		Fee:       1,
		Nonce:     1,
		Timestamp: 1_700_000_100_001,
	}
	if err := SignTransaction(&first, alicePriv); err != nil {
		t.Fatalf("sign first settlement: %v", err)
	}
	if _, err := c.SubmitTx(first); err != nil {
		t.Fatalf("submit first settlement: %v", err)
	}
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce first settlement block: %v", err)
	}

	duplicate := Transaction{
		Kind:      TxKindProductSettle,
		To:        Address("invoice-42"),
		Amount:    100,
		Fee:       1,
		Nonce:     2,
		Timestamp: 1_700_000_100_002,
	}
	if err := SignTransaction(&duplicate, alicePriv); err != nil {
		t.Fatalf("sign duplicate settlement: %v", err)
	}
	if _, err := c.SubmitTx(duplicate); !errors.Is(err, ErrProductSettlementDuplicate) {
		t.Fatalf("expected ErrProductSettlementDuplicate, got %v", err)
	}

	otherPayer := Transaction{
		Kind:      TxKindProductSettle,
		To:        Address("invoice-42"),
		Amount:    80,
		Fee:       1,
		Nonce:     1,
		Timestamp: 1_700_000_100_003,
	}
	if err := SignTransaction(&otherPayer, bobPriv); err != nil {
		t.Fatalf("sign other payer settlement: %v", err)
	}
	if _, err := c.SubmitTx(otherPayer); err != nil {
		t.Fatalf("submit other payer settlement: %v", err)
	}
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce other payer settlement block: %v", err)
	}

	settlements := c.GetProductSettlements()
	if len(settlements) != 2 {
		t.Fatalf("expected 2 settlements total, got %d", len(settlements))
	}
	if c.GetProductStatus().TreasuryBalance != 180 {
		t.Fatalf("expected treasury balance 180 after unique settlements, got %d", c.GetProductStatus().TreasuryBalance)
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

func TestProductAttestationRequiresOracleQuorum(t *testing.T) {
	pub1, priv1, addr1, err := DeterministicKeypair("attest-quorum-v1")
	if err != nil {
		t.Fatalf("validator v1 keypair: %v", err)
	}
	pub2, priv2, addr2, err := DeterministicKeypair("attest-quorum-v2")
	if err != nil {
		t.Fatalf("validator v2 keypair: %v", err)
	}

	c, err := New(Config{
		BaseReward:             0,
		MinTxFee:               1,
		EpochLengthBlocks:      10,
		ProductOracleQuorumBps: 7000,
		GenesisTimestampMs:     1_700_000_000_000,
		GenesisAccounts: map[Address]uint64{
			addr1: 1_000,
			addr2: 1_000,
		},
		GenesisValidators: []GenesisValidator{
			{ID: "v1", PubKey: pub1, Stake: 1_000, WorkWeight: 100, Active: true},
			{ID: "v2", PubKey: pub2, Stake: 1_000, WorkWeight: 100, Active: true},
		},
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}

	attestV1 := Transaction{
		Kind:        TxKindProductAttest,
		To:          Address("proof-quorum"),
		Amount:      10,
		Fee:         1,
		Nonce:       1,
		Timestamp:   1_700_000_000_001,
		ValidatorID: "v1",
		BasisPoints: 9000,
	}
	if err := SignTransaction(&attestV1, priv1); err != nil {
		t.Fatalf("sign attest tx v1: %v", err)
	}
	if _, err := c.SubmitTx(attestV1); err != nil {
		t.Fatalf("submit attest tx v1: %v", err)
	}
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce attestation block v1: %v", err)
	}

	if len(c.GetProductProofs()) != 0 {
		t.Fatalf("expected no finalized proof with only one oracle vote")
	}
	pending := c.GetProductPendingAttestations()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending attestation after first vote, got %d", len(pending))
	}

	attestV2 := Transaction{
		Kind:        TxKindProductAttest,
		To:          Address("proof-quorum"),
		Amount:      10,
		Fee:         1,
		Nonce:       1,
		Timestamp:   1_700_000_000_002,
		ValidatorID: "v1",
		BasisPoints: 9000,
	}
	if err := SignTransaction(&attestV2, priv2); err != nil {
		t.Fatalf("sign attest tx v2: %v", err)
	}
	if _, err := c.SubmitTx(attestV2); err != nil {
		t.Fatalf("submit attest tx v2: %v", err)
	}
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce attestation block v2: %v", err)
	}

	proofs := c.GetProductProofs()
	if len(proofs) != 1 {
		t.Fatalf("expected 1 finalized proof after quorum, got %d", len(proofs))
	}
	if proofs[0].Attestations != 2 {
		t.Fatalf("expected 2 attestations on finalized proof, got %d", proofs[0].Attestations)
	}
	if len(c.GetProductPendingAttestations()) != 0 {
		t.Fatalf("expected no pending attestations after quorum finalization")
	}
}

func TestProductChallengeResolveDelayEnforced(t *testing.T) {
	pub, valPriv, valAddr, err := DeterministicKeypair("resolve-delay-v1")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}
	_, alicePriv, aliceAddr, err := DeterministicKeypair("resolve-delay-alice")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}

	c, err := New(Config{
		BaseReward:                         0,
		MinTxFee:                           1,
		ProductChallengeResolveDelayBlocks: 2,
		ProductChallengeMinBond:            10,
		GenesisTimestampMs:                 1_700_000_000_000,
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
		To:        Address("order-delay"),
		Amount:    100,
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

	attestTx := Transaction{
		Kind:        TxKindProductAttest,
		To:          Address("proof-delay"),
		Amount:      10,
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
		t.Fatalf("expected 1 proof before challenge, got %d", len(proofs))
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
		t.Fatalf("expected 1 challenge, got %d", len(challenges))
	}

	resolveEarly := Transaction{
		Kind:        TxKindProductResolveChallenge,
		To:          Address(challenges[0].ID),
		Amount:      1,
		Fee:         1,
		Nonce:       2,
		Timestamp:   1_700_000_000_004,
		BasisPoints: 500,
	}
	if err := SignTransaction(&resolveEarly, valPriv); err != nil {
		t.Fatalf("sign early resolve tx: %v", err)
	}
	if _, err := c.SubmitTx(resolveEarly); !errors.Is(err, ErrProductChallengeTooEarly) {
		t.Fatalf("expected ErrProductChallengeTooEarly, got %v", err)
	}

	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce spacer block: %v", err)
	}

	resolveTx := Transaction{
		Kind:        TxKindProductResolveChallenge,
		To:          Address(challenges[0].ID),
		Amount:      1,
		Fee:         1,
		Nonce:       2,
		Timestamp:   1_700_000_000_005,
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
	if len(challenges) != 1 || challenges[0].Open {
		t.Fatalf("expected challenge to be closed after delayed resolution")
	}
}

func TestProductPendingAttestationExpiresByTTL(t *testing.T) {
	pub1, priv1, addr1, err := DeterministicKeypair("pending-ttl-v1")
	if err != nil {
		t.Fatalf("validator v1 keypair: %v", err)
	}
	pub2, _, addr2, err := DeterministicKeypair("pending-ttl-v2")
	if err != nil {
		t.Fatalf("validator v2 keypair: %v", err)
	}

	c, err := New(Config{
		BaseReward:                  0,
		MinTxFee:                    1,
		EpochLengthBlocks:           20,
		ProductOracleQuorumBps:      7000,
		ProductAttestationTTLBlocks: 1,
		GenesisTimestampMs:          1_700_000_000_000,
		GenesisAccounts: map[Address]uint64{
			addr1: 1_000,
			addr2: 1_000,
		},
		GenesisValidators: []GenesisValidator{
			{ID: "v1", PubKey: pub1, Stake: 1_000, WorkWeight: 100, Active: true},
			{ID: "v2", PubKey: pub2, Stake: 1_000, WorkWeight: 100, Active: true},
		},
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}

	attest := Transaction{
		Kind:        TxKindProductAttest,
		To:          Address("proof-ttl"),
		Amount:      5,
		Fee:         1,
		Nonce:       1,
		Timestamp:   1_700_000_000_001,
		ValidatorID: "v1",
		BasisPoints: 8000,
	}
	if err := SignTransaction(&attest, priv1); err != nil {
		t.Fatalf("sign attest tx: %v", err)
	}
	if _, err := c.SubmitTx(attest); err != nil {
		t.Fatalf("submit attest tx: %v", err)
	}
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce attest block: %v", err)
	}

	if len(c.GetProductPendingAttestations()) != 1 {
		t.Fatalf("expected 1 pending attestation before ttl expiry")
	}
	if len(c.GetProductProofs()) != 0 {
		t.Fatalf("expected no finalized proofs before ttl expiry")
	}

	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce ttl-expiry block: %v", err)
	}
	if len(c.GetProductPendingAttestations()) != 0 {
		t.Fatalf("expected pending attestations to expire after ttl")
	}
	if len(c.GetProductProofs()) != 0 {
		t.Fatalf("expected no finalized proofs after ttl expiry")
	}
}

func TestProductChallengeTimesOutAfterMaxOpenBlocks(t *testing.T) {
	pub, valPriv, valAddr, err := DeterministicKeypair("challenge-timeout-v1")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}
	_, alicePriv, aliceAddr, err := DeterministicKeypair("challenge-timeout-alice")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}

	c, err := New(Config{
		BaseReward:                         0,
		MinTxFee:                           1,
		ProductChallengeMinBond:            10,
		ProductChallengeMaxOpenBlocks:      1,
		ProductChallengeResolveDelayBlocks: 1,
		GenesisTimestampMs:                 1_700_000_000_000,
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
		To:        Address("order-timeout"),
		Amount:    100,
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

	attestTx := Transaction{
		Kind:        TxKindProductAttest,
		To:          Address("proof-timeout"),
		Amount:      10,
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
		t.Fatalf("expected 1 proof before challenge, got %d", len(proofs))
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
	if len(challenges) != 1 || !challenges[0].Open {
		t.Fatalf("expected open challenge before timeout")
	}

	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce timeout block: %v", err)
	}
	challenges = c.GetProductChallenges()
	if len(challenges) != 1 {
		t.Fatalf("expected 1 challenge after timeout, got %d", len(challenges))
	}
	if challenges[0].Open {
		t.Fatalf("expected challenge to close on timeout")
	}
	if challenges[0].Successful {
		t.Fatalf("expected timed-out challenge to be unsuccessful")
	}
	if challenges[0].Resolver != Address("system-timeout") {
		t.Fatalf("expected system-timeout resolver, got %s", challenges[0].Resolver)
	}

	resolveTx := Transaction{
		Kind:        TxKindProductResolveChallenge,
		To:          Address(challenges[0].ID),
		Amount:      1,
		Fee:         1,
		Nonce:       2,
		Timestamp:   1_700_000_000_004,
		BasisPoints: 500,
	}
	if err := SignTransaction(&resolveTx, valPriv); err != nil {
		t.Fatalf("sign resolve tx: %v", err)
	}
	if _, err := c.SubmitTx(resolveTx); !errors.Is(err, ErrProductChallengeClosed) {
		t.Fatalf("expected ErrProductChallengeClosed after timeout, got %v", err)
	}
}
