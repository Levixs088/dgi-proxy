#!/usr/bin/env bash
# dgi-tunnel — jaga endpoint publik untuk gateway proxy tanpa VPS.
#
# Pakai Pinggy TCP mode (raw TCP, bukan HTTP): bisa meneruskan HTTP proxy DAN
# SOCKS5 karena tidak mem-parsing protokol, cuma pipe byte.
#
# Free tier: tunnel mati tiap 60 menit -> script ini reconnect otomatis dan
# menulis endpoint aktif ke state file supaya panel bisa menampilkannya.
set -u

GW_HOST="${GW_HOST:-127.0.0.1}"
GW_PORT="${GW_PORT:-8899}"
STATE_DIR="${STATE_DIR:-$HOME/.dgi}"
LOG="$STATE_DIR/tunnel.log"
ENDPOINT="$STATE_DIR/endpoint.txt"
mkdir -p "$STATE_DIR"

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*" >>"$LOG"; }

cleanup() { rm -f "$ENDPOINT"; log "shutdown"; }
trap cleanup EXIT INT TERM

attempt=0
while :; do
  attempt=$((attempt+1))
  log "connect #$attempt -> $GW_HOST:$GW_PORT"

  # -R0 = minta port acak; -o ExitOnForwardFailure supaya gagal cepat
  ssh -p 443 \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ServerAliveInterval=20 \
      -o ServerAliveCountMax=3 \
      -o ExitOnForwardFailure=yes \
      -o LogLevel=INFO \
      -R0:"$GW_HOST":"$GW_PORT" tcp@a.pinggy.io 2>&1 \
  | while IFS= read -r line; do
      printf '%s\n' "$line" >>"$LOG"
      # tangkap endpoint tcp://host:port
      ep=$(printf '%s' "$line" | grep -oE 'tcp://[A-Za-z0-9._-]+:[0-9]+' | head -1)
      if [ -n "$ep" ]; then
        printf '%s\n' "$ep" >"$ENDPOINT"
        log "endpoint aktif: $ep"
      fi
    done

  log "tunnel terputus, reconnect 5s"
  rm -f "$ENDPOINT"
  sleep 5
done
