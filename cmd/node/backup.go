package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"fastpos/internal/chain"
)

const backupFilePrefix = "snapshot-h"

func maybeWriteBackupSnapshot(c *chain.Chain, block chain.Block, backupDir string, everyBlocks uint64, retain int) (string, error) {
	if c == nil {
		return "", fmt.Errorf("backup requires chain instance")
	}
	backupDir = strings.TrimSpace(backupDir)
	if backupDir == "" || everyBlocks == 0 {
		return "", nil
	}
	if block.Height == 0 || block.Height%everyBlocks != 0 {
		return "", nil
	}
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return "", fmt.Errorf("create backup dir: %w", err)
	}

	filename := fmt.Sprintf("%s%012d-ts%d.json", backupFilePrefix, block.Height, block.Timestamp)
	path := filepath.Join(backupDir, filename)
	if err := c.SaveSnapshot(path); err != nil {
		return "", fmt.Errorf("write backup snapshot: %w", err)
	}
	if err := pruneBackupSnapshots(backupDir, retain); err != nil {
		return path, err
	}
	return path, nil
}

func pruneBackupSnapshots(backupDir string, retain int) error {
	if retain <= 0 {
		return nil
	}

	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return fmt.Errorf("read backup dir: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, backupFilePrefix) || !strings.HasSuffix(name, ".json") {
			continue
		}
		files = append(files, filepath.Join(backupDir, name))
	}
	if len(files) <= retain {
		return nil
	}
	sort.Strings(files)
	toDelete := files[:len(files)-retain]
	for _, path := range toDelete {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove old backup %s: %w", path, err)
		}
	}
	return nil
}
