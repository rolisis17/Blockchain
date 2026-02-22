package chain

import "testing"

func FuzzConsensusStateTransitions(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8})
	f.Add([]byte{9, 8, 7, 6, 5, 4, 3, 2, 1})

	f.Fuzz(func(t *testing.T, ops []byte) {
		pub1, _, addrV1, err := DeterministicKeypair("fuzz-validator-1")
		if err != nil {
			t.Fatalf("deterministic keypair v1: %v", err)
		}
		pub2, _, addrV2, err := DeterministicKeypair("fuzz-validator-2")
		if err != nil {
			t.Fatalf("deterministic keypair v2: %v", err)
		}
		pub3, _, addrV3, err := DeterministicKeypair("fuzz-validator-3")
		if err != nil {
			t.Fatalf("deterministic keypair v3: %v", err)
		}
		_, alicePriv, aliceAddr, err := DeterministicKeypair("fuzz-alice")
		if err != nil {
			t.Fatalf("deterministic keypair alice: %v", err)
		}
		_, bobPriv, bobAddr, err := DeterministicKeypair("fuzz-bob")
		if err != nil {
			t.Fatalf("deterministic keypair bob: %v", err)
		}

		c, err := New(Config{
			GenesisTimestampMs:     1_700_000_000_000,
			BaseReward:             1,
			MaxTxPerBlock:          50,
			MaxMempoolSize:         2_000,
			MaxPendingTxPerAccount: 128,
			MaxMempoolTxAgeBlocks:  300,
			MinTxFee:               1,
			GenesisAccounts: map[Address]uint64{
				addrV1:    0,
				addrV2:    0,
				addrV3:    0,
				aliceAddr: 1_000_000,
				bobAddr:   1_000_000,
			},
			GenesisValidators: []GenesisValidator{
				{ID: "v1", PubKey: pub1, Stake: 1_000, WorkWeight: 100, Active: true},
				{ID: "v2", PubKey: pub2, Stake: 1_000, WorkWeight: 100, Active: true},
				{ID: "v3", PubKey: pub3, Stake: 1_000, WorkWeight: 100, Active: true},
			},
		})
		if err != nil {
			t.Fatalf("new chain: %v", err)
		}

		ts := int64(1_700_000_000_001)
		maxSteps := len(ops)
		if maxSteps > 256 {
			maxSteps = 256
		}

		for i := 0; i < maxSteps; i++ {
			op := ops[i] % 5
			switch op {
			case 0, 1:
				from := aliceAddr
				to := bobAddr
				priv := alicePriv
				if op == 1 {
					from = bobAddr
					to = aliceAddr
					priv = bobPriv
				}
				nonce, err := c.NextNonce(from)
				if err != nil {
					continue
				}
				tx := Transaction{
					From:      from,
					To:        to,
					Amount:    uint64(ops[i]%50) + 1,
					Fee:       uint64(ops[i]%4) + 1,
					Nonce:     nonce,
					Timestamp: ts,
				}
				ts++
				if err := SignTransaction(&tx, priv); err != nil {
					t.Fatalf("sign tx: %v", err)
				}
				_, _ = c.SubmitTx(tx)
			case 2:
				_, _ = c.ProduceOnce()
			case 3:
				if (ops[i] & 1) == 0 {
					_, _ = c.NextNonce(aliceAddr)
				} else {
					_, _ = c.NextNonce(bobAddr)
				}
			case 4:
				_ = c.GetMetrics()
				_ = c.GetStatus()
			}
		}
	})
}
