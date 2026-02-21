package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type runConfig struct {
	ConfigPath      string
	HTTPAddr        string
	GenesisPath     string
	StatePath       string
	BlockInterval   time.Duration
	BaseReward      uint64
	MaxTxPerBlock   int
	MaxMempoolSize  int
	MinTxFee        uint64
	AdminToken      string
	AllowDevSigning bool
	ReadinessMaxLag time.Duration
}

type fileConfig struct {
	HTTPAddr        *string `yaml:"http"`
	GenesisPath     *string `yaml:"genesis"`
	StatePath       *string `yaml:"state"`
	BlockInterval   *string `yaml:"blockInterval"`
	BaseReward      *uint64 `yaml:"baseReward"`
	MaxTxPerBlock   *int    `yaml:"maxTxPerBlock"`
	MaxMempoolSize  *int    `yaml:"maxMempoolSize"`
	MinTxFee        *uint64 `yaml:"minTxFee"`
	AdminToken      *string `yaml:"adminToken"`
	AllowDevSigning *bool   `yaml:"allowDevSigning"`
	ReadinessMaxLag *string `yaml:"readinessMaxLag"`
}

func parseRunConfig(args []string, envAdminToken string) (runConfig, error) {
	cfg := defaultRunConfig(envAdminToken)

	bootstrapConfigPath, err := discoverConfigPath(args)
	if err != nil {
		return runConfig{}, err
	}
	if bootstrapConfigPath != "" {
		if err := applyConfigFile(bootstrapConfigPath, &cfg); err != nil {
			return runConfig{}, err
		}
		cfg.ConfigPath = bootstrapConfigPath
	}

	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.StringVar(&cfg.ConfigPath, "config", cfg.ConfigPath, "path to config YAML file")
	fs.StringVar(&cfg.HTTPAddr, "http", cfg.HTTPAddr, "http listen address")
	fs.StringVar(&cfg.GenesisPath, "genesis", cfg.GenesisPath, "path to genesis JSON file (optional)")
	fs.StringVar(&cfg.StatePath, "state", cfg.StatePath, "path to state snapshot file")
	fs.DurationVar(&cfg.BlockInterval, "block-interval", cfg.BlockInterval, "block production interval")
	fs.Uint64Var(&cfg.BaseReward, "base-reward", cfg.BaseReward, "base reward paid to proposer per block")
	fs.IntVar(&cfg.MaxTxPerBlock, "max-tx", cfg.MaxTxPerBlock, "max transactions per block")
	fs.IntVar(&cfg.MaxMempoolSize, "max-mempool", cfg.MaxMempoolSize, "max pending transactions in mempool")
	fs.Uint64Var(&cfg.MinTxFee, "min-tx-fee", cfg.MinTxFee, "minimum transaction fee accepted into mempool")
	fs.StringVar(&cfg.AdminToken, "admin-token", cfg.AdminToken, "admin token for validator control endpoints")
	fs.BoolVar(&cfg.AllowDevSigning, "allow-dev-signing", cfg.AllowDevSigning, "enable unsafe server-side signing endpoints")
	fs.DurationVar(&cfg.ReadinessMaxLag, "readiness-max-lag", cfg.ReadinessMaxLag, "max finality lag for /readyz (0=auto)")

	if err := fs.Parse(args[1:]); err != nil {
		return runConfig{}, err
	}

	if cfg.BlockInterval <= 0 {
		return runConfig{}, errors.New("block-interval must be > 0")
	}
	if cfg.MaxTxPerBlock <= 0 {
		return runConfig{}, errors.New("max-tx must be > 0")
	}
	if cfg.MaxMempoolSize <= 0 {
		return runConfig{}, errors.New("max-mempool must be > 0")
	}
	if cfg.MinTxFee == 0 {
		return runConfig{}, errors.New("min-tx-fee must be > 0")
	}

	return cfg, nil
}

func defaultRunConfig(adminToken string) runConfig {
	return runConfig{
		ConfigPath:      "",
		HTTPAddr:        ":8080",
		GenesisPath:     "",
		StatePath:       "./data/state.json",
		BlockInterval:   2 * time.Second,
		BaseReward:      1,
		MaxTxPerBlock:   500,
		MaxMempoolSize:  20_000,
		MinTxFee:        1,
		AdminToken:      adminToken,
		AllowDevSigning: false,
		ReadinessMaxLag: 0,
	}
}

func discoverConfigPath(args []string) (string, error) {
	for i := 1; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		if arg == "" {
			continue
		}
		if arg == "-config" {
			if i+1 >= len(args) {
				return "", errors.New("-config requires a value")
			}
			return strings.TrimSpace(args[i+1]), nil
		}
		if strings.HasPrefix(arg, "-config=") {
			parts := strings.SplitN(arg, "=", 2)
			if len(parts) != 2 {
				return "", errors.New("invalid -config argument")
			}
			return strings.TrimSpace(parts[1]), nil
		}
	}
	return "", nil
}

func applyConfigFile(path string, cfg *runConfig) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("config path is empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}

	var fc fileConfig
	if err := yaml.Unmarshal(raw, &fc); err != nil {
		return fmt.Errorf("decode config %s: %w", path, err)
	}

	if fc.HTTPAddr != nil {
		cfg.HTTPAddr = *fc.HTTPAddr
	}
	if fc.GenesisPath != nil {
		cfg.GenesisPath = *fc.GenesisPath
	}
	if fc.StatePath != nil {
		cfg.StatePath = *fc.StatePath
	}
	if fc.BlockInterval != nil {
		d, err := time.ParseDuration(*fc.BlockInterval)
		if err != nil {
			return fmt.Errorf("parse blockInterval: %w", err)
		}
		cfg.BlockInterval = d
	}
	if fc.BaseReward != nil {
		cfg.BaseReward = *fc.BaseReward
	}
	if fc.MaxTxPerBlock != nil {
		cfg.MaxTxPerBlock = *fc.MaxTxPerBlock
	}
	if fc.MaxMempoolSize != nil {
		cfg.MaxMempoolSize = *fc.MaxMempoolSize
	}
	if fc.MinTxFee != nil {
		cfg.MinTxFee = *fc.MinTxFee
	}
	if fc.AdminToken != nil {
		cfg.AdminToken = *fc.AdminToken
	}
	if fc.AllowDevSigning != nil {
		cfg.AllowDevSigning = *fc.AllowDevSigning
	}
	if fc.ReadinessMaxLag != nil {
		d, err := time.ParseDuration(*fc.ReadinessMaxLag)
		if err != nil {
			return fmt.Errorf("parse readinessMaxLag: %w", err)
		}
		cfg.ReadinessMaxLag = d
	}

	return nil
}
