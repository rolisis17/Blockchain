#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  restore_snapshot.sh <snapshot-file-or-backup-dir> <target-state-path> [latest|<height>]

Examples:
  restore_snapshot.sh ./data/backups ./data/state.json
  restore_snapshot.sh ./data/backups ./data/state.json 1200
  restore_snapshot.sh ./data/backups/snapshot-h000000001200-ts1700000000000.json ./data/state.json
EOF
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
  usage
  exit 1
fi

source_path="$1"
target_state="$2"
selector="${3:-latest}"

pick_snapshot_from_dir() {
  local dir="$1"
  local sel="$2"
  local candidate=""

  if [[ "$sel" == "latest" ]]; then
    candidate="$(ls -1 "$dir"/snapshot-h*.json 2>/dev/null | sort | tail -n 1 || true)"
  else
    if [[ ! "$sel" =~ ^[0-9]+$ ]]; then
      echo "selector must be 'latest' or a numeric height: $sel" >&2
      return 1
    fi
    local padded
    padded="$(printf "%012d" "$sel")"
    candidate="$(ls -1 "$dir"/snapshot-h"${padded}"-*.json 2>/dev/null | sort | tail -n 1 || true)"
  fi

  if [[ -z "$candidate" ]]; then
    echo "no matching snapshot found in $dir (selector=$sel)" >&2
    return 1
  fi
  printf "%s\n" "$candidate"
}

snapshot_file=""
if [[ -d "$source_path" ]]; then
  snapshot_file="$(pick_snapshot_from_dir "$source_path" "$selector")"
else
  snapshot_file="$source_path"
fi

if [[ ! -f "$snapshot_file" ]]; then
  echo "snapshot file does not exist: $snapshot_file" >&2
  exit 1
fi

mkdir -p "$(dirname "$target_state")"
tmp_path="${target_state}.tmp.$$"
cp "$snapshot_file" "$tmp_path"
mv "$tmp_path" "$target_state"

echo "restored snapshot: $snapshot_file -> $target_state"
