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
)

func main() {
	defaultAdminToken := os.Getenv("FASTPOS_ADMIN_TOKEN")
	cfg, err := parseRunConfig(os.Args, defaultAdminToken)
	if err != nil {
		log.Fatalf("parse config: %v", err)
	}

	chainCfg := chain.Config{
		BlockInterval:  cfg.BlockInterval,
		BaseReward:     cfg.BaseReward,
		MaxTxPerBlock:  cfg.MaxTxPerBlock,
		MaxMempoolSize: cfg.MaxMempoolSize,
		MinTxFee:       cfg.MinTxFee,
	}

	c, boot, err := buildChain(chainCfg, cfg.GenesisPath, cfg.StatePath)
	if err != nil {
		log.Fatalf("init chain: %v", err)
	}

	if cfg.StatePath != "" {
		c.SetFinalizeHook(func(_ chain.Block) {
			if err := c.SaveSnapshot(cfg.StatePath); err != nil {
				log.Printf("persist snapshot failed: %v", err)
			}
		})
		if err := c.SaveSnapshot(cfg.StatePath); err != nil {
			log.Fatalf("write initial snapshot: %v", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c.Start(ctx, log.Printf)

	srv := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: node.NewServer(c, node.Config{
			AdminToken:      cfg.AdminToken,
			AllowDevSigning: cfg.AllowDevSigning,
			ReadinessMaxLag: cfg.ReadinessMaxLag,
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if cfg.StatePath != "" {
			if err := c.SaveSnapshot(cfg.StatePath); err != nil {
				log.Printf("final snapshot save failed: %v", err)
			}
		}
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("fastpos node listening on %s", cfg.HTTPAddr)
	if cfg.ConfigPath != "" {
		log.Printf("loaded config file: %s", cfg.ConfigPath)
	}
	if boot.LoadedFromSnapshot {
		log.Printf("chain loaded from snapshot: %s", boot.SnapshotPath)
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

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server failed: %v", err)
	}
}
