# Phase 4 Disaster Recovery Runbook

This runbook defines a minimal recovery flow for `fastpos` nodes using periodic JSON backups.

## 1) Enable periodic backups

Set these runtime options (CLI or `config.yaml`):

- `backupDir`: directory where JSON backups are written
- `backupEveryBlocks`: backup cadence in finalized blocks (`0` disables)
- `backupRetain`: number of backup files to retain (`0` keeps all)

Example:

```yaml
backupDir: "./data/backups"
backupEveryBlocks: 100
backupRetain: 50
```

Backups are written as:

`snapshot-h000000000123-ts1700000000000.json`

## 2) Restore a snapshot backend node

1. Stop the node.
2. Restore a chosen backup into your configured state path:

```bash
./scripts/ops/restore_snapshot.sh ./data/backups ./data/state.json
```

Optional: restore a specific height:

```bash
./scripts/ops/restore_snapshot.sh ./data/backups ./data/state.json 1200
```

3. Start the node with `stateBackend: snapshot` and the restored `state` path.

## 3) Restore/convert state across backends

Use the built-in migration command:

```bash
go run ./cmd/node migrate-state \
  -from-backend snapshot -from ./data/state.json \
  -to-backend sqlite -to ./data/state.db
```

Reverse conversion is also supported:

```bash
go run ./cmd/node migrate-state \
  -from-backend sqlite -from ./data/state.db \
  -to-backend snapshot -to ./data/state.json
```

This is useful for disaster recovery and backend changes without replay from genesis.

## 4) Post-recovery checks

After restart, verify:

1. `GET /status` height is at/near expected recovered height.
2. `GET /readyz` becomes ready.
3. `GET /metrics.json` shows advancing `height` and `finalizedBlocksTotal`.
4. If p2p is enabled, `GET /p2p/status` shows outbound/inbound activity.

## 5) Operational recommendation

Run periodic recovery drills in non-production:

1. Take latest backup.
2. Restore to a fresh node.
3. Rejoin peers and confirm finality progression.
