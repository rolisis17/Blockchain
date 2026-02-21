package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRunConfig_Defaults(t *testing.T) {
	cfg, err := parseRunConfig([]string{"node"}, "env-token")
	if err != nil {
		t.Fatalf("parse run config: %v", err)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Fatalf("expected default http addr :8080, got %s", cfg.HTTPAddr)
	}
	if cfg.AdminToken != "env-token" {
		t.Fatalf("expected admin token from env, got %s", cfg.AdminToken)
	}
}

func TestParseRunConfig_ConfigFileAndCLIOverride(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "node.yaml")
	content := []byte("http: ':7777'\nblockInterval: '3s'\nmaxMempoolSize: 111\nminTxFee: 9\nadminToken: 'from-file'\n")
	if err := os.WriteFile(configPath, content, 0o644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := parseRunConfig([]string{
		"node",
		"-config", configPath,
		"-http", ":8888",
		"-admin-token", "from-cli",
	}, "env-token")
	if err != nil {
		t.Fatalf("parse run config: %v", err)
	}
	if cfg.HTTPAddr != ":8888" {
		t.Fatalf("expected CLI http override :8888, got %s", cfg.HTTPAddr)
	}
	if cfg.AdminToken != "from-cli" {
		t.Fatalf("expected CLI admin token override, got %s", cfg.AdminToken)
	}
	if cfg.MaxMempoolSize != 111 {
		t.Fatalf("expected max mempool from file 111, got %d", cfg.MaxMempoolSize)
	}
	if cfg.MinTxFee != 9 {
		t.Fatalf("expected min tx fee from file 9, got %d", cfg.MinTxFee)
	}
	if cfg.BlockInterval.String() != "3s" {
		t.Fatalf("expected block interval 3s from file, got %s", cfg.BlockInterval)
	}
}
