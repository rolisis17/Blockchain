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

const (
	stateBackendSnapshot = "snapshot"
	stateBackendSQLite   = "sqlite"
)

type runConfig struct {
	ConfigPath                         string
	HTTPAddr                           string
	GenesisPath                        string
	StateBackend                       string
	StatePath                          string
	BackupDir                          string
	BackupEveryBlocks                  uint64
	BackupRetain                       int
	BlockInterval                      time.Duration
	BaseReward                         uint64
	MinJailBlocks                      uint64
	EpochLengthBlocks                  uint64
	MaxTxPerBlock                      int
	MaxMempoolSize                     int
	MaxPendingPerAccount               int
	MaxMempoolAgeBlocks                uint64
	MinTxFee                           uint64
	ProductRewardBps                   uint64
	ProductChallengeMinBond            uint64
	ProductOracleQuorumBps             uint64
	ProductChallengeResolveDelayBlocks uint64
	ProductAttestationTTLBlocks        uint64
	ProductChallengeMaxOpenBlocks      uint64
	ProductUnitPrice                   uint64
	AdminToken                         string
	AllowDevSigning                    bool
	ReadinessMaxLag                    time.Duration
	P2PEnabled                         bool
	NodeID                             string
	ValidatorPrivateKey                string
	Peers                              []string
	P2PProposerTimeout                 uint64
	P2PMaxRoundLookahead               uint64
	P2PPeerBackoffInit                 time.Duration
	P2PPeerBackoffMax                  time.Duration
	P2PInboundRateLimit                uint64
	P2PInboundRateWindow               time.Duration
}

type fileConfig struct {
	HTTPAddr                           *string  `yaml:"http"`
	GenesisPath                        *string  `yaml:"genesis"`
	StateBackend                       *string  `yaml:"stateBackend"`
	StatePath                          *string  `yaml:"state"`
	BackupDir                          *string  `yaml:"backupDir"`
	BackupEveryBlocks                  *uint64  `yaml:"backupEveryBlocks"`
	BackupRetain                       *int     `yaml:"backupRetain"`
	BlockInterval                      *string  `yaml:"blockInterval"`
	BaseReward                         *uint64  `yaml:"baseReward"`
	MinJailBlocks                      *uint64  `yaml:"minJailBlocks"`
	EpochLengthBlocks                  *uint64  `yaml:"epochLengthBlocks"`
	MaxTxPerBlock                      *int     `yaml:"maxTxPerBlock"`
	MaxMempoolSize                     *int     `yaml:"maxMempoolSize"`
	MaxPendingPerAccount               *int     `yaml:"maxPendingTxPerAccount"`
	MaxMempoolAgeBlocks                *uint64  `yaml:"maxMempoolTxAgeBlocks"`
	MinTxFee                           *uint64  `yaml:"minTxFee"`
	ProductRewardBps                   *uint64  `yaml:"productRewardBps"`
	ProductChallengeMinBond            *uint64  `yaml:"productChallengeMinBond"`
	ProductOracleQuorumBps             *uint64  `yaml:"productOracleQuorumBps"`
	ProductChallengeResolveDelayBlocks *uint64  `yaml:"productChallengeResolveDelayBlocks"`
	ProductAttestationTTLBlocks        *uint64  `yaml:"productAttestationTtlBlocks"`
	ProductChallengeMaxOpenBlocks      *uint64  `yaml:"productChallengeMaxOpenBlocks"`
	ProductUnitPrice                   *uint64  `yaml:"productUnitPrice"`
	AdminToken                         *string  `yaml:"adminToken"`
	AllowDevSigning                    *bool    `yaml:"allowDevSigning"`
	ReadinessMaxLag                    *string  `yaml:"readinessMaxLag"`
	P2PEnabled                         *bool    `yaml:"p2pEnabled"`
	NodeID                             *string  `yaml:"nodeId"`
	ValidatorPrivateKey                *string  `yaml:"validatorPrivateKey"`
	Peers                              []string `yaml:"peers"`
	P2PProposerTimeout                 *uint64  `yaml:"p2pProposerTimeoutTicks"`
	P2PMaxRoundLookahead               *uint64  `yaml:"p2pMaxRoundLookahead"`
	P2PPeerBackoffInit                 *string  `yaml:"p2pPeerBackoffInitial"`
	P2PPeerBackoffMax                  *string  `yaml:"p2pPeerBackoffMax"`
	P2PInboundRateLimit                *uint64  `yaml:"p2pInboundRateLimitPerPeer"`
	P2PInboundRateWindow               *string  `yaml:"p2pInboundRateWindow"`
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
	fs.StringVar(&cfg.StateBackend, "state-backend", cfg.StateBackend, "state backend: snapshot or sqlite")
	fs.StringVar(&cfg.StatePath, "state", cfg.StatePath, "path to state file (snapshot json or sqlite db)")
	fs.StringVar(&cfg.BackupDir, "backup-dir", cfg.BackupDir, "directory for periodic JSON snapshot backups (empty disables backups)")
	fs.Uint64Var(&cfg.BackupEveryBlocks, "backup-every-blocks", cfg.BackupEveryBlocks, "write backup snapshot every N finalized blocks (0 disables)")
	fs.IntVar(&cfg.BackupRetain, "backup-retain", cfg.BackupRetain, "number of backup snapshots to retain (<=0 keeps all)")
	fs.DurationVar(&cfg.BlockInterval, "block-interval", cfg.BlockInterval, "block production interval")
	fs.Uint64Var(&cfg.BaseReward, "base-reward", cfg.BaseReward, "base reward paid to proposer per block")
	fs.Uint64Var(&cfg.MinJailBlocks, "min-jail-blocks", cfg.MinJailBlocks, "minimum finalized blocks a jailed validator must wait before unjailing")
	fs.Uint64Var(&cfg.EpochLengthBlocks, "epoch-length-blocks", cfg.EpochLengthBlocks, "number of blocks per epoch (validator set/reward transitions)")
	fs.IntVar(&cfg.MaxTxPerBlock, "max-tx", cfg.MaxTxPerBlock, "max transactions per block")
	fs.IntVar(&cfg.MaxMempoolSize, "max-mempool", cfg.MaxMempoolSize, "max pending transactions in mempool")
	fs.IntVar(&cfg.MaxPendingPerAccount, "max-pending-per-account", cfg.MaxPendingPerAccount, "max pending transactions per sender account in mempool")
	fs.Uint64Var(&cfg.MaxMempoolAgeBlocks, "max-mempool-age-blocks", cfg.MaxMempoolAgeBlocks, "max mempool residence age in blocks before a pending tx expires")
	fs.Uint64Var(&cfg.MinTxFee, "min-tx-fee", cfg.MinTxFee, "minimum transaction fee accepted into mempool")
	fs.Uint64Var(&cfg.ProductRewardBps, "product-reward-bps", cfg.ProductRewardBps, "portion of product treasury paid each epoch in basis points (0..10000)")
	fs.Uint64Var(&cfg.ProductChallengeMinBond, "product-challenge-min-bond", cfg.ProductChallengeMinBond, "minimum bond for product challenge transaction")
	fs.Uint64Var(&cfg.ProductOracleQuorumBps, "product-oracle-quorum-bps", cfg.ProductOracleQuorumBps, "oracle quorum threshold in basis points for product attestation/challenge resolution")
	fs.Uint64Var(&cfg.ProductChallengeResolveDelayBlocks, "product-challenge-resolve-delay-blocks", cfg.ProductChallengeResolveDelayBlocks, "minimum finalized blocks between challenge creation and resolution")
	fs.Uint64Var(&cfg.ProductAttestationTTLBlocks, "product-attestation-ttl-blocks", cfg.ProductAttestationTTLBlocks, "max block age for pending product attestations before expiry")
	fs.Uint64Var(&cfg.ProductChallengeMaxOpenBlocks, "product-challenge-max-open-blocks", cfg.ProductChallengeMaxOpenBlocks, "max block age for open product challenges before timeout close")
	fs.Uint64Var(&cfg.ProductUnitPrice, "product-unit-price", cfg.ProductUnitPrice, "billing quote unit price for product settlement API")
	fs.StringVar(&cfg.AdminToken, "admin-token", cfg.AdminToken, "admin token for validator control endpoints")
	fs.BoolVar(&cfg.AllowDevSigning, "allow-dev-signing", cfg.AllowDevSigning, "enable unsafe server-side signing endpoints")
	fs.DurationVar(&cfg.ReadinessMaxLag, "readiness-max-lag", cfg.ReadinessMaxLag, "max finality lag for /readyz (0=auto)")
	fs.BoolVar(&cfg.P2PEnabled, "p2p-enabled", cfg.P2PEnabled, "enable p2p message endpoint and peer gossip")
	fs.StringVar(&cfg.NodeID, "node-id", cfg.NodeID, "local validator/node id used for p2p messages")
	fs.StringVar(&cfg.ValidatorPrivateKey, "validator-priv", cfg.ValidatorPrivateKey, "hex private key for p2p message signing")
	fs.Uint64Var(&cfg.P2PProposerTimeout, "p2p-proposer-timeout-ticks", cfg.P2PProposerTimeout, "consensus ticks before proposer timeout view-change")
	fs.Uint64Var(&cfg.P2PMaxRoundLookahead, "p2p-max-round-lookahead", cfg.P2PMaxRoundLookahead, "max accepted round gap for incoming proposals")
	fs.DurationVar(&cfg.P2PPeerBackoffInit, "p2p-peer-backoff-initial", cfg.P2PPeerBackoffInit, "initial backoff for failed peer broadcasts")
	fs.DurationVar(&cfg.P2PPeerBackoffMax, "p2p-peer-backoff-max", cfg.P2PPeerBackoffMax, "maximum backoff for failed peer broadcasts")
	fs.Uint64Var(&cfg.P2PInboundRateLimit, "p2p-inbound-rate-limit-per-peer", cfg.P2PInboundRateLimit, "max inbound p2p messages per peer within rate window")
	fs.DurationVar(&cfg.P2PInboundRateWindow, "p2p-inbound-rate-window", cfg.P2PInboundRateWindow, "time window for inbound p2p peer rate limiting")
	peersFlag := fs.String("peers", "", "comma-separated peer base URLs (e.g. http://127.0.0.1:18082,http://127.0.0.1:18083)")

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
	if cfg.MaxPendingPerAccount < 0 {
		return runConfig{}, errors.New("max-pending-per-account must be >= 0")
	}
	if cfg.MinTxFee == 0 {
		return runConfig{}, errors.New("min-tx-fee must be > 0")
	}
	if cfg.EpochLengthBlocks == 0 {
		return runConfig{}, errors.New("epoch-length-blocks must be > 0")
	}
	if cfg.ProductRewardBps > 10_000 {
		return runConfig{}, errors.New("product-reward-bps must be in [0,10000]")
	}
	if cfg.ProductChallengeMinBond == 0 {
		return runConfig{}, errors.New("product-challenge-min-bond must be > 0")
	}
	if cfg.ProductOracleQuorumBps <= 5_000 || cfg.ProductOracleQuorumBps > 10_000 {
		return runConfig{}, errors.New("product-oracle-quorum-bps must be in [5001,10000]")
	}
	if cfg.ProductChallengeResolveDelayBlocks == 0 {
		return runConfig{}, errors.New("product-challenge-resolve-delay-blocks must be > 0")
	}
	if cfg.ProductAttestationTTLBlocks == 0 {
		return runConfig{}, errors.New("product-attestation-ttl-blocks must be > 0")
	}
	if cfg.ProductChallengeMaxOpenBlocks == 0 {
		return runConfig{}, errors.New("product-challenge-max-open-blocks must be > 0")
	}
	if cfg.ProductUnitPrice == 0 {
		return runConfig{}, errors.New("product-unit-price must be > 0")
	}
	if cfg.BackupRetain < 0 {
		return runConfig{}, errors.New("backup-retain must be >= 0")
	}
	if cfg.BackupEveryBlocks > 0 && strings.TrimSpace(cfg.BackupDir) == "" {
		return runConfig{}, errors.New("backup-dir is required when backup-every-blocks is > 0")
	}
	cfg.StateBackend = normalizeStateBackend(cfg.StateBackend)
	if !isSupportedStateBackend(cfg.StateBackend) {
		return runConfig{}, fmt.Errorf("unsupported state-backend %q (supported: %s, %s)", cfg.StateBackend, stateBackendSnapshot, stateBackendSQLite)
	}
	if cfg.P2PProposerTimeout == 0 {
		return runConfig{}, errors.New("p2p-proposer-timeout-ticks must be > 0")
	}
	if cfg.P2PMaxRoundLookahead == 0 {
		return runConfig{}, errors.New("p2p-max-round-lookahead must be > 0")
	}
	if cfg.P2PPeerBackoffInit <= 0 {
		return runConfig{}, errors.New("p2p-peer-backoff-initial must be > 0")
	}
	if cfg.P2PPeerBackoffMax <= 0 {
		return runConfig{}, errors.New("p2p-peer-backoff-max must be > 0")
	}
	if cfg.P2PPeerBackoffMax < cfg.P2PPeerBackoffInit {
		return runConfig{}, errors.New("p2p-peer-backoff-max must be >= p2p-peer-backoff-initial")
	}
	if cfg.P2PInboundRateLimit == 0 {
		return runConfig{}, errors.New("p2p-inbound-rate-limit-per-peer must be > 0")
	}
	if cfg.P2PInboundRateWindow <= 0 {
		return runConfig{}, errors.New("p2p-inbound-rate-window must be > 0")
	}
	if strings.TrimSpace(*peersFlag) != "" {
		cfg.Peers = splitAndTrimCSV(*peersFlag)
	}
	if cfg.P2PEnabled {
		if strings.TrimSpace(cfg.NodeID) == "" {
			return runConfig{}, errors.New("node-id is required when p2p is enabled")
		}
	}

	return cfg, nil
}

func defaultRunConfig(adminToken string) runConfig {
	return runConfig{
		ConfigPath:                         "",
		HTTPAddr:                           ":8080",
		GenesisPath:                        "",
		StateBackend:                       stateBackendSnapshot,
		StatePath:                          "./data/state.json",
		BackupDir:                          "./data/backups",
		BackupEveryBlocks:                  0,
		BackupRetain:                       20,
		BlockInterval:                      2 * time.Second,
		BaseReward:                         1,
		MinJailBlocks:                      0,
		EpochLengthBlocks:                  1,
		MaxTxPerBlock:                      500,
		MaxMempoolSize:                     20_000,
		MaxPendingPerAccount:               64,
		MaxMempoolAgeBlocks:                120,
		MinTxFee:                           1,
		ProductRewardBps:                   2_000,
		ProductChallengeMinBond:            10,
		ProductOracleQuorumBps:             6_667,
		ProductChallengeResolveDelayBlocks: 1,
		ProductAttestationTTLBlocks:        8,
		ProductChallengeMaxOpenBlocks:      64,
		ProductUnitPrice:                   1,
		AdminToken:                         adminToken,
		AllowDevSigning:                    false,
		ReadinessMaxLag:                    0,
		P2PEnabled:                         false,
		NodeID:                             "",
		Peers:                              nil,
		P2PProposerTimeout:                 2,
		P2PMaxRoundLookahead:               16,
		P2PPeerBackoffInit:                 500 * time.Millisecond,
		P2PPeerBackoffMax:                  15 * time.Second,
		P2PInboundRateLimit:                120,
		P2PInboundRateWindow:               time.Second,
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
	if fc.StateBackend != nil {
		cfg.StateBackend = normalizeStateBackend(*fc.StateBackend)
	}
	if fc.StatePath != nil {
		cfg.StatePath = *fc.StatePath
	}
	if fc.BackupDir != nil {
		cfg.BackupDir = *fc.BackupDir
	}
	if fc.BackupEveryBlocks != nil {
		cfg.BackupEveryBlocks = *fc.BackupEveryBlocks
	}
	if fc.BackupRetain != nil {
		cfg.BackupRetain = *fc.BackupRetain
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
	if fc.MinJailBlocks != nil {
		cfg.MinJailBlocks = *fc.MinJailBlocks
	}
	if fc.EpochLengthBlocks != nil {
		cfg.EpochLengthBlocks = *fc.EpochLengthBlocks
	}
	if fc.MaxTxPerBlock != nil {
		cfg.MaxTxPerBlock = *fc.MaxTxPerBlock
	}
	if fc.MaxMempoolSize != nil {
		cfg.MaxMempoolSize = *fc.MaxMempoolSize
	}
	if fc.MaxPendingPerAccount != nil {
		cfg.MaxPendingPerAccount = *fc.MaxPendingPerAccount
	}
	if fc.MaxMempoolAgeBlocks != nil {
		cfg.MaxMempoolAgeBlocks = *fc.MaxMempoolAgeBlocks
	}
	if fc.MinTxFee != nil {
		cfg.MinTxFee = *fc.MinTxFee
	}
	if fc.ProductRewardBps != nil {
		cfg.ProductRewardBps = *fc.ProductRewardBps
	}
	if fc.ProductChallengeMinBond != nil {
		cfg.ProductChallengeMinBond = *fc.ProductChallengeMinBond
	}
	if fc.ProductOracleQuorumBps != nil {
		cfg.ProductOracleQuorumBps = *fc.ProductOracleQuorumBps
	}
	if fc.ProductChallengeResolveDelayBlocks != nil {
		cfg.ProductChallengeResolveDelayBlocks = *fc.ProductChallengeResolveDelayBlocks
	}
	if fc.ProductAttestationTTLBlocks != nil {
		cfg.ProductAttestationTTLBlocks = *fc.ProductAttestationTTLBlocks
	}
	if fc.ProductChallengeMaxOpenBlocks != nil {
		cfg.ProductChallengeMaxOpenBlocks = *fc.ProductChallengeMaxOpenBlocks
	}
	if fc.ProductUnitPrice != nil {
		cfg.ProductUnitPrice = *fc.ProductUnitPrice
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
	if fc.P2PEnabled != nil {
		cfg.P2PEnabled = *fc.P2PEnabled
	}
	if fc.NodeID != nil {
		cfg.NodeID = *fc.NodeID
	}
	if fc.ValidatorPrivateKey != nil {
		cfg.ValidatorPrivateKey = *fc.ValidatorPrivateKey
	}
	if len(fc.Peers) > 0 {
		cfg.Peers = normalizePeers(fc.Peers)
	}
	if fc.P2PProposerTimeout != nil {
		cfg.P2PProposerTimeout = *fc.P2PProposerTimeout
	}
	if fc.P2PMaxRoundLookahead != nil {
		cfg.P2PMaxRoundLookahead = *fc.P2PMaxRoundLookahead
	}
	if fc.P2PPeerBackoffInit != nil {
		d, err := time.ParseDuration(*fc.P2PPeerBackoffInit)
		if err != nil {
			return fmt.Errorf("parse p2pPeerBackoffInitial: %w", err)
		}
		cfg.P2PPeerBackoffInit = d
	}
	if fc.P2PPeerBackoffMax != nil {
		d, err := time.ParseDuration(*fc.P2PPeerBackoffMax)
		if err != nil {
			return fmt.Errorf("parse p2pPeerBackoffMax: %w", err)
		}
		cfg.P2PPeerBackoffMax = d
	}
	if fc.P2PInboundRateLimit != nil {
		cfg.P2PInboundRateLimit = *fc.P2PInboundRateLimit
	}
	if fc.P2PInboundRateWindow != nil {
		d, err := time.ParseDuration(*fc.P2PInboundRateWindow)
		if err != nil {
			return fmt.Errorf("parse p2pInboundRateWindow: %w", err)
		}
		cfg.P2PInboundRateWindow = d
	}

	return nil
}

func normalizeStateBackend(raw string) string {
	backend := strings.TrimSpace(strings.ToLower(raw))
	switch backend {
	case "", "json":
		return stateBackendSnapshot
	default:
		return backend
	}
}

func isSupportedStateBackend(backend string) bool {
	switch backend {
	case stateBackendSnapshot, stateBackendSQLite:
		return true
	default:
		return false
	}
}

func splitAndTrimCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	return normalizePeers(parts)
}

func normalizePeers(raw []string) []string {
	set := map[string]struct{}{}
	for _, peer := range raw {
		peer = strings.TrimSpace(peer)
		if peer == "" {
			continue
		}
		peer = strings.TrimSuffix(peer, "/")
		set[peer] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for peer := range set {
		out = append(out, peer)
	}
	return out
}
