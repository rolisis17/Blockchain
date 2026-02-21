package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"fastpos/internal/chain"
)

const defaultGenesisTimestampMs int64 = 1_700_000_000_000

type demoUser struct {
	Address    chain.Address
	PrivateKey string
}

type bootInfo struct {
	LoadedFromSnapshot bool
	SnapshotPath       string
	GenesisSource      string
	DemoUsers          map[string]demoUser
}

type genesisFile struct {
	GenesisTimestampMs int64                    `json:"genesisTimestampMs"`
	Accounts           map[string]uint64        `json:"accounts"`
	Validators         []chain.GenesisValidator `json:"validators"`
}

func buildChain(cfg chain.Config, genesisPath, statePath string) (*chain.Chain, bootInfo, error) {
	if statePath != "" {
		if _, err := os.Stat(statePath); err == nil {
			loaded, err := chain.LoadSnapshot(statePath, cfg)
			if err != nil {
				return nil, bootInfo{}, fmt.Errorf("load snapshot %s: %w", statePath, err)
			}
			return loaded, bootInfo{
				LoadedFromSnapshot: true,
				SnapshotPath:       statePath,
				GenesisSource:      "snapshot",
			}, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, bootInfo{}, fmt.Errorf("check snapshot %s: %w", statePath, err)
		}
	}

	accounts, validators, genesisTimestampMs, demoUsers, source, err := loadGenesis(genesisPath)
	if err != nil {
		return nil, bootInfo{}, err
	}

	cfg.GenesisAccounts = accounts
	cfg.GenesisValidators = validators
	cfg.GenesisTimestampMs = genesisTimestampMs

	c, err := chain.New(cfg)
	if err != nil {
		return nil, bootInfo{}, fmt.Errorf("new chain from genesis: %w", err)
	}

	return c, bootInfo{
		LoadedFromSnapshot: false,
		SnapshotPath:       statePath,
		GenesisSource:      source,
		DemoUsers:          demoUsers,
	}, nil
}

func loadGenesis(path string) (map[chain.Address]uint64, []chain.GenesisValidator, int64, map[string]demoUser, string, error) {
	if path == "" {
		accounts, validators, genesisTimestampMs, demoUsers, err := defaultGenesis()
		if err != nil {
			return nil, nil, 0, nil, "", err
		}
		return accounts, validators, genesisTimestampMs, demoUsers, "built-in deterministic genesis", nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, 0, nil, "", fmt.Errorf("read genesis file %s: %w", path, err)
	}

	var gf genesisFile
	if err := json.Unmarshal(raw, &gf); err != nil {
		return nil, nil, 0, nil, "", fmt.Errorf("decode genesis file %s: %w", path, err)
	}
	if len(gf.Accounts) == 0 {
		return nil, nil, 0, nil, "", errors.New("genesis file has no accounts")
	}
	if len(gf.Validators) == 0 {
		return nil, nil, 0, nil, "", errors.New("genesis file has no validators")
	}

	accounts := make(map[chain.Address]uint64, len(gf.Accounts))
	for addr, balance := range gf.Accounts {
		accounts[chain.Address(addr)] = balance
	}

	genesisTimestampMs := gf.GenesisTimestampMs
	if genesisTimestampMs <= 0 {
		genesisTimestampMs = defaultGenesisTimestampMs
	}

	return accounts, gf.Validators, genesisTimestampMs, nil, path, nil
}

func defaultGenesis() (map[chain.Address]uint64, []chain.GenesisValidator, int64, map[string]demoUser, error) {
	validatorLabels := []string{"validator-1", "validator-2", "validator-3"}
	validators := make([]chain.GenesisValidator, 0, len(validatorLabels))
	accounts := map[chain.Address]uint64{}

	for i, label := range validatorLabels {
		pub, _, addr, err := chain.DeterministicKeypair(label)
		if err != nil {
			return nil, nil, 0, nil, fmt.Errorf("build validator keypair: %w", err)
		}
		validators = append(validators, chain.GenesisValidator{
			ID:         fmt.Sprintf("v%d", i+1),
			PubKey:     pub,
			Stake:      1_000,
			WorkWeight: 100,
			Active:     true,
		})
		accounts[addr] = 0
	}

	_, alicePriv, aliceAddr, err := chain.DeterministicKeypair("alice")
	if err != nil {
		return nil, nil, 0, nil, fmt.Errorf("build alice keypair: %w", err)
	}
	_, bobPriv, bobAddr, err := chain.DeterministicKeypair("bob")
	if err != nil {
		return nil, nil, 0, nil, fmt.Errorf("build bob keypair: %w", err)
	}

	accounts[aliceAddr] = 1_000_000
	accounts[bobAddr] = 1_000_000

	demoUsers := map[string]demoUser{
		"alice": {Address: aliceAddr, PrivateKey: alicePriv},
		"bob":   {Address: bobAddr, PrivateKey: bobPriv},
	}

	return accounts, validators, defaultGenesisTimestampMs, demoUsers, nil
}
