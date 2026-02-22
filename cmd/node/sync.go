package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"fastpos/internal/chain"
)

const (
	startupSyncHTTPTimeout = 4 * time.Second
	startupSyncBatchSize   = 200
	maxSyncPayloadBytes    = 64 << 20
)

type startupSyncResult struct {
	Used       bool
	Mode       string
	Peer       string
	FromHeight uint64
	ToHeight   uint64
}

func syncChainFromPeers(current *chain.Chain, cfg chain.Config, peers []string, logf func(format string, args ...any)) (*chain.Chain, startupSyncResult, error) {
	if current == nil {
		return nil, startupSyncResult{}, errors.New("sync requires a chain instance")
	}
	if len(peers) == 0 {
		return current, startupSyncResult{}, nil
	}

	client := &http.Client{Timeout: startupSyncHTTPTimeout}
	local := current.GetStatus()
	bestPeer, bestStatus, found := selectBestSyncPeer(client, peers, logf)
	if !found {
		return current, startupSyncResult{}, nil
	}
	if bestStatus.Height <= local.Height {
		return current, startupSyncResult{}, nil
	}

	result := startupSyncResult{
		Used:       true,
		Peer:       bestPeer,
		FromHeight: local.Height + 1,
	}

	if err := catchUpBlocksFromPeer(client, current, bestPeer, local.Height+1, bestStatus.Height); err == nil {
		status := current.GetStatus()
		result.Mode = "blocks"
		result.ToHeight = status.Height
		return current, result, nil
	} else if logf != nil {
		logf("startup block sync from peer %s failed: %v; trying snapshot fallback", bestPeer, err)
	}

	snapChain, err := loadSnapshotFromPeer(client, bestPeer, cfg)
	if err != nil {
		return current, startupSyncResult{}, fmt.Errorf("sync peer %s failed (block catch-up and snapshot): %w", bestPeer, err)
	}
	snapStatus := snapChain.GetStatus()
	if snapStatus.Height < local.Height {
		return current, startupSyncResult{}, fmt.Errorf("peer snapshot height %d behind local height %d", snapStatus.Height, local.Height)
	}
	result.Mode = "snapshot"
	result.ToHeight = snapStatus.Height
	return snapChain, result, nil
}

func selectBestSyncPeer(client *http.Client, peers []string, logf func(format string, args ...any)) (string, chain.Status, bool) {
	var (
		bestPeer   string
		bestStatus chain.Status
		found      bool
	)
	for _, peer := range peers {
		status, err := fetchPeerStatus(client, peer)
		if err != nil {
			if logf != nil {
				logf("startup sync: skip peer %s: %v", peer, err)
			}
			continue
		}
		if !found || status.Height > bestStatus.Height {
			bestPeer = peer
			bestStatus = status
			found = true
		}
	}
	return bestPeer, bestStatus, found
}

func catchUpBlocksFromPeer(client *http.Client, c *chain.Chain, peer string, fromHeight uint64, targetHeight uint64) error {
	if fromHeight > targetHeight {
		return nil
	}
	next := fromHeight
	for next <= targetHeight {
		remaining := int(targetHeight - next + 1)
		limit := startupSyncBatchSize
		if remaining < limit {
			limit = remaining
		}
		blocks, err := fetchPeerBlocks(client, peer, next, limit)
		if err != nil {
			return err
		}
		if len(blocks) == 0 {
			return fmt.Errorf("peer %s returned no blocks from height %d", peer, next)
		}

		advanced := false
		for _, block := range blocks {
			if block.Height != next {
				return fmt.Errorf("peer %s returned unexpected block height %d while expecting %d", peer, block.Height, next)
			}
			if err := c.FinalizeExternalBlock(block); err != nil {
				return fmt.Errorf("apply synced block %d: %w", block.Height, err)
			}
			next++
			advanced = true
			if next > targetHeight {
				break
			}
		}
		if !advanced {
			return fmt.Errorf("peer %s sync loop made no progress at height %d", peer, next)
		}
	}
	return nil
}

func fetchPeerStatus(client *http.Client, peer string) (chain.Status, error) {
	url := peerEndpoint(peer, "/status")
	resp, err := client.Get(url)
	if err != nil {
		return chain.Status{}, fmt.Errorf("fetch peer status %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return chain.Status{}, fmt.Errorf("fetch peer status %s: status=%d body=%s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return decodeHTTPJSON[chain.Status](resp.Body)
}

func fetchPeerBlocks(client *http.Client, peer string, fromHeight uint64, limit int) ([]chain.Block, error) {
	url := peerEndpoint(peer, "/blocks") + "?from=" + strconv.FormatUint(fromHeight, 10) + "&limit=" + strconv.Itoa(limit)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch peer blocks %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("fetch peer blocks %s: status=%d body=%s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return decodeHTTPJSON[[]chain.Block](resp.Body)
}

func loadSnapshotFromPeer(client *http.Client, peer string, cfg chain.Config) (*chain.Chain, error) {
	url := peerEndpoint(peer, "/sync/snapshot")
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch peer snapshot %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("fetch peer snapshot %s: status=%d body=%s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSyncPayloadBytes))
	if err != nil {
		return nil, fmt.Errorf("read peer snapshot body: %w", err)
	}
	return chain.LoadSnapshotBytes(data, cfg)
}

func decodeHTTPJSON[T any](reader io.Reader) (T, error) {
	var out T
	dec := json.NewDecoder(io.LimitReader(reader, maxSyncPayloadBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("decode json: %w", err)
	}
	return out, nil
}

func peerEndpoint(peer, path string) string {
	base := strings.TrimSpace(peer)
	base = strings.TrimSuffix(base, "/")
	return base + path
}
