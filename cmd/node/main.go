package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"fastpos/internal/chain"
	"fastpos/internal/node"
	"fastpos/internal/p2p"
)

func main() {
	if ran, err := maybeRunStateMigration(os.Args, log.Printf); err != nil {
		log.Fatalf("state migration failed: %v", err)
	} else if ran {
		return
	}

	defaultAdminToken := os.Getenv("FASTPOS_ADMIN_TOKEN")
	cfg, err := parseRunConfig(os.Args, defaultAdminToken)
	if err != nil {
		log.Fatalf("parse config: %v", err)
	}

	chainCfg := chain.Config{
		BlockInterval:                      cfg.BlockInterval,
		BaseReward:                         cfg.BaseReward,
		MinJailBlocks:                      cfg.MinJailBlocks,
		EpochLengthBlocks:                  cfg.EpochLengthBlocks,
		MaxTxPerBlock:                      cfg.MaxTxPerBlock,
		MaxMempoolSize:                     cfg.MaxMempoolSize,
		MaxPendingTxPerAccount:             cfg.MaxPendingPerAccount,
		MaxMempoolTxAgeBlocks:              cfg.MaxMempoolAgeBlocks,
		MinTxFee:                           cfg.MinTxFee,
		ProductRewardBps:                   cfg.ProductRewardBps,
		ProductChallengeMinBond:            cfg.ProductChallengeMinBond,
		ProductOracleQuorumBps:             cfg.ProductOracleQuorumBps,
		ProductChallengeResolveDelayBlocks: cfg.ProductChallengeResolveDelayBlocks,
		ProductAttestationTTLBlocks:        cfg.ProductAttestationTTLBlocks,
		ProductChallengeMaxOpenBlocks:      cfg.ProductChallengeMaxOpenBlocks,
	}

	c, boot, err := buildChain(chainCfg, cfg.GenesisPath, cfg.StateBackend, cfg.StatePath)
	if err != nil {
		log.Fatalf("init chain: %v", err)
	}
	if cfg.P2PEnabled && len(cfg.Peers) > 0 {
		syncedChain, syncResult, err := syncChainFromPeers(c, chainCfg, cfg.Peers, log.Printf)
		if err != nil {
			log.Printf("startup sync skipped: %v", err)
		} else if syncResult.Used {
			log.Printf(
				"startup sync applied mode=%s peer=%s fromHeight=%d toHeight=%d",
				syncResult.Mode,
				syncResult.Peer,
				syncResult.FromHeight,
				syncResult.ToHeight,
			)
		}
		if syncedChain != nil {
			c = syncedChain
		}
	}

	var p2pSvc *p2p.Service
	if cfg.P2PEnabled {
		validatorPubKeys := map[string]string{}
		for _, v := range c.GetValidators() {
			validatorPubKeys[v.ID] = v.PubKey
		}
		p2pSvc, err = p2p.NewService(p2p.Config{
			Enabled:              true,
			NodeID:               cfg.NodeID,
			ValidatorPrivateKey:  cfg.ValidatorPrivateKey,
			ValidatorPubKeys:     validatorPubKeys,
			Peers:                cfg.Peers,
			ProposerTimeoutTicks: cfg.P2PProposerTimeout,
			MaxRoundLookahead:    cfg.P2PMaxRoundLookahead,
			PeerBackoffInitial:   cfg.P2PPeerBackoffInit,
			PeerBackoffMax:       cfg.P2PPeerBackoffMax,
			InboundRateLimit:     cfg.P2PInboundRateLimit,
			InboundRateWindow:    cfg.P2PInboundRateWindow,
			Logf:                 log.Printf,
		})
		if err != nil {
			log.Fatalf("init p2p service: %v", err)
		}
	}

	c.SetFinalizeHook(func(block chain.Block) {
		if p2pSvc != nil {
			status := c.GetStatus()
			log.Printf("finalized block height=%d hash=%s", status.Height, status.HeadHash)
		}
		if cfg.StatePath != "" {
			if err := saveChainState(c, cfg.StateBackend, cfg.StatePath); err != nil {
				log.Printf("persist state failed: %v", err)
			}
		}
		if path, err := maybeWriteBackupSnapshot(c, block, cfg.BackupDir, cfg.BackupEveryBlocks, cfg.BackupRetain); err != nil {
			log.Printf("backup snapshot failed: %v", err)
		} else if path != "" {
			log.Printf("backup snapshot written: %s", path)
		}
	})
	if cfg.StatePath != "" {
		if err := saveChainState(c, cfg.StateBackend, cfg.StatePath); err != nil {
			log.Fatalf("write initial state: %v", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if p2pSvc != nil {
		p2pSvc.StartConsensus(ctx, c)
	} else {
		c.Start(ctx, log.Printf)
	}

	srv := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: node.NewServer(c, node.Config{
			AdminToken:       cfg.AdminToken,
			AllowDevSigning:  cfg.AllowDevSigning,
			ReadinessMaxLag:  cfg.ReadinessMaxLag,
			ProductUnitPrice: cfg.ProductUnitPrice,
			P2PService:       p2pSvc,
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if cfg.StatePath != "" {
			if err := saveChainState(c, cfg.StateBackend, cfg.StatePath); err != nil {
				log.Printf("final state save failed: %v", err)
			}
		}
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("fastpos node listening on %s", cfg.HTTPAddr)
	if cfg.ConfigPath != "" {
		log.Printf("loaded config file: %s", cfg.ConfigPath)
	}
	log.Printf("state backend=%s path=%s", cfg.StateBackend, cfg.StatePath)
	log.Printf("backup config dir=%s everyBlocks=%d retain=%d", cfg.BackupDir, cfg.BackupEveryBlocks, cfg.BackupRetain)
	log.Printf("min jail blocks=%d", c.MinJailBlocks())
	log.Printf("epoch length blocks=%d", cfg.EpochLengthBlocks)
	log.Printf(
		"product reward bps=%d challenge min bond=%d oracle quorum bps=%d challenge resolve delay blocks=%d attestation ttl blocks=%d challenge max-open blocks=%d unit price=%d",
		cfg.ProductRewardBps,
		cfg.ProductChallengeMinBond,
		cfg.ProductOracleQuorumBps,
		cfg.ProductChallengeResolveDelayBlocks,
		cfg.ProductAttestationTTLBlocks,
		cfg.ProductChallengeMaxOpenBlocks,
		cfg.ProductUnitPrice,
	)
	log.Printf("mempool controls max-size=%d max-pending-per-account=%d max-age-blocks=%d", cfg.MaxMempoolSize, cfg.MaxPendingPerAccount, cfg.MaxMempoolAgeBlocks)
	if boot.LoadedFromSnapshot {
		log.Printf("chain loaded from %s state: %s", boot.GenesisSource, boot.SnapshotPath)
	} else {
		log.Printf("chain initialized from genesis source: %s", boot.GenesisSource)
	}
	if len(boot.DemoUsers) > 0 {
		if alice, ok := boot.DemoUsers["alice"]; ok {
			log.Printf("demo user alice address=%s privateKey=%s", alice.Address, alice.PrivateKey)
		}
		if bob, ok := boot.DemoUsers["bob"]; ok {
			log.Printf("demo user bob   address=%s privateKey=%s", bob.Address, bob.PrivateKey)
		}
	}
	if cfg.AdminToken == "" {
		log.Printf("warning: admin token is empty; validator admin endpoints are open")
	}
	if !cfg.AllowDevSigning {
		log.Printf("server-side signing endpoints are disabled")
	}
	if cfg.P2PEnabled {
		log.Printf(
			"p2p enabled node-id=%s peers=%d proposer-timeout-ticks=%d max-round-lookahead=%d peer-backoff-initial=%s peer-backoff-max=%s inbound-rate-limit=%d inbound-rate-window=%s",
			cfg.NodeID,
			len(cfg.Peers),
			cfg.P2PProposerTimeout,
			cfg.P2PMaxRoundLookahead,
			cfg.P2PPeerBackoffInit,
			cfg.P2PPeerBackoffMax,
			cfg.P2PInboundRateLimit,
			cfg.P2PInboundRateWindow,
		)
		if cfg.ValidatorPrivateKey == "" {
			log.Printf("warning: p2p is enabled but validator private key is empty; outbound p2p signing/broadcast is disabled")
		}
	}

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server failed: %v", err)
	}
}
