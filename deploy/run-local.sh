#!/usr/bin/env bash
# DGI Proxy — mode TANPA VPS (tanpa VCC, tanpa kartu).
#
# Yang dijalankan:
#   1. gateway reseller di 127.0.0.1:8899 (HTTP + SOCKS5, metering per-GB)
#   2. tunnel keeper Pinggy TCP -> endpoint publik tcp://xxx.pinggy-free.link:PORT
#   3. dashboard panel di 127.0.0.1:8901
#
# Batas free tier: endpoint berganti tiap 60 menit dan hostname memuat IP egress.
# Untuk endpoint permanen dibutuhkan VPS (lihat provision.sh).
set -Eeuo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA="${DATA:-$HOME/.dgi}"
GATE_PORT="${GATE_PORT:-8899}"
PANEL_PORT="${PANEL_PORT:-8901}"
PY="$HERE/.venv/bin/python"

log() { printf '[1;34m[dgi][0m %s
' "$*"; }
mkdir -p "$DATA"/{logs,state}

[[ -x "$PY" ]] || { echo "venv belum ada: python3 -m venv $HERE/.venv && $HERE/.venv/bin/pip install -r $HERE/web/requirements.txt"; exit 1; }

log "init database"
"$PY" "$HERE/reseller_gw.py" --db "$DATA/reseller.db" init >/dev/null 2>&1 || true

POOL="$HERE/../proxyhunt/out/usable.json"
[[ -f "$POOL" ]] || POOL="$DATA/usable.json"

log "start gateway :$GATE_PORT (pool: $POOL)"
"$PY" "$HERE/reseller_gw.py" --db "$DATA/reseller.db" serve       --host 127.0.0.1 --port "$GATE_PORT" --pool "$POOL"       >>"$DATA/logs/gateway.log" 2>&1 &
GW_PID=$!

if [[ -f "$HERE/web/app.py" ]]; then
  log "start panel :$PANEL_PORT"
  ( cd "$HERE/web" && "$PY" app.py serve --host 127.0.0.1 --port "$PANEL_PORT"       >>"$DATA/logs/panel.log" 2>&1 & echo $! >"$DATA/state/panel.pid" )
fi

log "start tunnel keeper"
GW_PORT="$GATE_PORT" STATE_DIR="$DATA/state" bash "$HERE/deploy/dgi-tunnel.sh" &
TUN_PID=$!

cleanup() { kill "$GW_PID" "$TUN_PID" 2>/dev/null || true; exit 0; }
trap cleanup INT TERM

sleep 12
EP="$(cat "$DATA/state/endpoint.txt" 2>/dev/null || echo '(belum siap)')"
echo
echo "=========================================="
echo "  endpoint publik : $EP"
echo "  panel lokal     : http://127.0.0.1:$PANEL_PORT"
echo "  data            : $DATA"
echo
echo "  pakai:"
echo "    curl -x http://USER:PASS@\${ENDPOINT#tcp://} http://ip-api.com/json"
echo "=========================================="
wait "$GW_PID"
