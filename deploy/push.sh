#!/usr/bin/env bash
# DGI Proxy — push this box's working tree to a fresh VPS and provision it.
# Run FROM this box:  bash deploy/push.sh root@<VPS_IP> [domain]
# Needs: ssh key access to the VPS, rsync on both ends.
set -Eeuo pipefail

TARGET="${1:?pakai: bash push.sh root@IP_VPS [domain]}"
DOMAIN="${2:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

log() { printf '\033[1;34m[push]\033[0m %s\n' "$*"; }

log "staging kode"
mkdir -p "$STAGE"/{app,proxyhunt}
rsync -a --exclude='.venv' --exclude='__pycache__' --exclude='*.db*' \
      --exclude='.git' "$HERE/reseller_gw.py" "$HERE/proxy_gw.py" "$STAGE/app/"
rsync -a --exclude='.venv' --exclude='__pycache__' --exclude='*.db*' \
      "$HERE/web" "$STAGE/app/"
rsync -a "$HERE/deploy" "$STAGE/app/"
rsync -a --exclude='work' --exclude='raw' --exclude='__pycache__' \
      "$HERE/../proxyhunt/" "$STAGE/proxyhunt/" 2>/dev/null || \
  rsync -a --exclude='work' --exclude='raw' --exclude='__pycache__' \
        "/home/agentuser/proxyhunt/" "$STAGE/proxyhunt/"

log "kirim ke $TARGET"
ssh -o ConnectTimeout=15 "$TARGET" 'mkdir -p /opt/dgiproxy/src'
rsync -az --delete -e 'ssh -o ConnectTimeout=15' "$STAGE/" "$TARGET:/opt/dgiproxy/src/"

log "provision di VPS"
ssh -o ConnectTimeout=15 "$TARGET" \
  "DOMAIN='$DOMAIN' SRC_DIR=/opt/dgiproxy/src bash /opt/dgiproxy/src/app/deploy/provision.sh"

log "selesai — cek ringkasan di atas"
