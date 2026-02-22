package chain

import "testing"

func TestValidatorLifecyclePrimitives(t *testing.T) {
	pub, _, valAddr, err := DeterministicKeypair("validator-lifecycle")
	if err != nil {
		t.Fatalf("deterministic keypair: %v", err)
	}

	c, err := New(Config{
		GenesisAccounts: map[Address]uint64{
			valAddr: 500,
		},
		GenesisValidators: []GenesisValidator{
			{ID: "v1", PubKey: pub, Stake: 1_000, WorkWeight: 100, Active: true},
		},
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}

	if err := c.BondValidatorStake("v1", 100); err != nil {
		t.Fatalf("bond validator stake: %v", err)
	}
	v, ok := c.GetValidator("v1")
	if !ok {
		t.Fatalf("validator v1 not found")
	}
	if v.Stake != 1_100 {
		t.Fatalf("expected stake 1100 after bond, got %d", v.Stake)
	}
	acc, ok := c.GetAccount(valAddr)
	if !ok {
		t.Fatalf("validator account missing")
	}
	if acc.Balance != 400 {
		t.Fatalf("expected validator account balance 400 after bond, got %d", acc.Balance)
	}

	if err := c.UnbondValidatorStake("v1", 50); err != nil {
		t.Fatalf("unbond validator stake: %v", err)
	}
	v, _ = c.GetValidator("v1")
	if v.Stake != 1_050 {
		t.Fatalf("expected stake 1050 after unbond, got %d", v.Stake)
	}
	acc, _ = c.GetAccount(valAddr)
	if acc.Balance != 450 {
		t.Fatalf("expected validator account balance 450 after unbond, got %d", acc.Balance)
	}

	slashed, err := c.SlashValidatorStake("v1", 1_000)
	if err != nil {
		t.Fatalf("slash validator stake: %v", err)
	}
	if slashed != 105 {
		t.Fatalf("expected slashed amount 105, got %d", slashed)
	}
	v, _ = c.GetValidator("v1")
	if v.Stake != 945 {
		t.Fatalf("expected stake 945 after slash, got %d", v.Stake)
	}

	if err := c.SetValidatorJailed("v1", true); err != nil {
		t.Fatalf("set validator jailed: %v", err)
	}
	effectiveStake, err := c.ValidatorEffectiveStake("v1")
	if err != nil {
		t.Fatalf("validator effective stake: %v", err)
	}
	if effectiveStake != 0 {
		t.Fatalf("expected effective stake 0 while jailed, got %d", effectiveStake)
	}

	if err := c.SetValidatorJailed("v1", false); err != nil {
		t.Fatalf("clear validator jailed: %v", err)
	}
	effectiveStake, err = c.ValidatorEffectiveStake("v1")
	if err != nil {
		t.Fatalf("validator effective stake after unjail: %v", err)
	}
	if effectiveStake == 0 {
		t.Fatalf("expected non-zero effective stake after unjail")
	}
}

func TestValidatorLifecycleValidation(t *testing.T) {
	pub, _, _, err := DeterministicKeypair("validator-lifecycle-validation")
	if err != nil {
		t.Fatalf("deterministic keypair: %v", err)
	}
	c, err := New(Config{
		GenesisValidators: []GenesisValidator{
			{ID: "v1", PubKey: pub, Stake: 1_000, WorkWeight: 100, Active: true},
		},
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}

	if err := c.BondValidatorStake("v1", 0); err == nil {
		t.Fatalf("expected error for zero bond amount")
	}
	if err := c.UnbondValidatorStake("v1", 0); err == nil {
		t.Fatalf("expected error for zero unbond amount")
	}
	if _, err := c.SlashValidatorStake("v1", 0); err == nil {
		t.Fatalf("expected error for zero slash basis points")
	}
	if _, err := c.SlashValidatorStake("v1", 20_000); err == nil {
		t.Fatalf("expected error for invalid slash basis points")
	}
}
