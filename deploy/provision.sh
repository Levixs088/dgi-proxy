#!/usr/bin/env bash
# DGI Proxy — one-shot VPS provisioner.
# Target: fresh Ubuntu 22.04/24.04 or Debian 12 VPS (Oracle A1 free tier works).
# Installs: gateway (HTTP+SOCKS5, per-GB metering), pool hunter + cron, systemd unit,
#           nginx front for the panel, ufw rules, optional DuckDNS updater.
# Idempotent: safe to re-run.
set -Eeuo pipefail

DOMAIN="${DOMAIN:-}"
GATE_PORT="${GATE_PORT:-8899}"
PANEL_PORT="${PANEL_PORT:-8901}"
DUCK_TOKEN="${DUCK_TOKEN:-}"
DUCK_SUB="${DUCK_SUB:-}"
REPO_DIR="${REPO_DIR:-/opt/dgiproxy}"
USER_NAME="${USER_NAME:-dgi}"

log()  { printf '\033[1;34m[dgi]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "jalankan sebagai root: sudo bash provision.sh"

export DEBIAN_FRONTEND=noninteractive
log "apt update + paket dasar"
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  python3 python3-venv python3-pip python3-dev build-essential \
  curl ca-certificates git sqlite3 ufw nginx cron logrotate jq openssl

# ---------- user ----------
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
  log "buat user sistem: $USER_NAME"
  adduser --system --group --home "$REPO_DIR" --shell /usr/sbin/nologin "$USER_NAME"
fi

mkdir -p "$REPO_DIR"/{app,data,logs}
chown -R "$USER_NAME:$USER_NAME" "$REPO_DIR"

# ---------- kode ----------
if [[ -d "$REPO_DIR/app/.git" ]]; then
  log "update repo"
  git -C "$REPO_DIR/app" pull --ff-only || warn "pull gagal, pakai versi lokal"
elif [[ -n "${SRC_DIR:-}" && -d "${SRC_DIR:-}" ]]; then
  log "salin kode dari $SRC_DIR"
  cp -a "$SRC_DIR"/. "$REPO_DIR/app/"
else
  warn "tidak ada sumber kode (set SRC_DIR=/path/ke/proxy-gw atau clone manual)"
fi

# ---------- venv ----------
log "venv + dependensi"
python3 -m venv "$REPO_DIR/venv"
"$REPO_DIR/venv/bin/pip" install -q --upgrade pip wheel
if [[ -f "$REPO_DIR/app/web/requirements.txt" ]]; then
  "$REPO_DIR/venv/bin/pip" install -q -r "$REPO_DIR/app/web/requirements.txt"
else
  "$REPO_DIR/venv/bin/pip" install -q flask argon2-cffi
fi
chown -R "$USER_NAME:$USER_NAME" "$REPO_DIR/venv"

# ---------- systemd: gateway ----------
log "systemd unit: dgi-gateway"
cat >/etc/systemd/system/dgi-gateway.service <<UNIT
[Unit]
Description=DGI Proxy gateway (HTTP+SOCKS5, per-GB metering)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER_NAME
Group=$USER_NAME
WorkingDirectory=$REPO_DIR/app
ExecStart=$REPO_DIR/venv/bin/python reseller_gw.py --db $REPO_DIR/data/reseller.db serve --host 0.0.0.0 --port $GATE_PORT --pool $REPO_DIR/data/usable.json
Restart=always
RestartSec=3
LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$REPO_DIR/data $REPO_DIR/logs
StandardOutput=append:$REPO_DIR/logs/gateway.log
StandardError=append:$REPO_DIR/logs/gateway.log

[Install]
WantedBy=multi-user.target
UNIT

# ---------- systemd: panel ----------
log "systemd unit: dgi-panel"
cat >/etc/systemd/system/dgi-panel.service <<UNIT
[Unit]
Description=DGI Proxy web panel (Flask)
After=network-online.target dgi-gateway.service
Wants=network-online.target

[Service]
Type=simple
User=$USER_NAME
Group=$USER_NAME
WorkingDirectory=$REPO_DIR/app/web
Environment=DGI_ENV=production
Environment=DGI_DATA_DIR=$REPO_DIR/data
ExecStart=$REPO_DIR/venv/bin/python app.py serve --host 127.0.0.1 --port $PANEL_PORT
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$REPO_DIR/data $REPO_DIR/logs $REPO_DIR/app/web
StandardOutput=append:$REPO_DIR/logs/panel.log
StandardError=append:$REPO_DIR/logs/panel.log

[Install]
WantedBy=multi-user.target
UNIT

# ---------- hunt cron ----------
log "cron: pool hunter tiap 20 menit"
cat >/etc/cron.d/dgi-hunt <<CRON
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/20 * * * * $USER_NAME cd $REPO_DIR/app/proxyhunt && $REPO_DIR/venv/bin/python -u pipeline.py --top 400 >> $REPO_DIR/logs/hunt.log 2>&1 && cp -f $REPO_DIR/app/proxyhunt/out/usable.json $REPO_DIR/data/usable.json
CRON
chmod 644 /etc/cron.d/dgi-hunt

# ---------- nginx ----------
log "nginx reverse proxy untuk panel"
cat >/etc/nginx/sites-available/dgi <<NGINX
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name ${DOMAIN:-_};

    client_max_body_size 2m;
    server_tokens off;

    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;

    location / {
        proxy_pass http://127.0.0.1:$PANEL_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 30s;
    }
}
NGINX
ln -sf /etc/nginx/sites-available/dgi /etc/nginx/sites-enabled/dgi
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

# ---------- ufw ----------
log "firewall: 22, 80, 443, $GATE_PORT"
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow 22/tcp comment 'ssh' >/dev/null
ufw allow 80/tcp comment 'http' >/dev/null
ufw allow 443/tcp comment 'https' >/dev/null
ufw allow "$GATE_PORT"/tcp comment 'proxy gateway' >/dev/null
ufw --force enable >/dev/null

# ---------- duckdns ----------
if [[ -n "$DUCK_TOKEN" && -n "$DUCK_SUB" ]]; then
  log "duckdns updater: $DUCK_SUB.duckdns.org"
  cat >/usr/local/bin/dgi-duckdns <<DUCK
#!/usr/bin/env bash
set -eu
curl -fsS "https://www.duckdns.org/update?domains=$DUCK_SUB&token=$DUCK_TOKEN&ip=" -o /dev/null || true
DUCK
  chmod 750 /usr/local/bin/dgi-duckdns
  ( crontab -l 2>/dev/null | grep -v dgi-duckdns; echo "*/5 * * * * /usr/local/bin/dgi-duckdns" ) | crontab -
fi

# ---------- logrotate ----------
cat >/etc/logrotate.d/dgi <<'LR'
/opt/dgiproxy/logs/*.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
    copytruncate
}
LR

# ---------- seed data ----------
log "init database + pool awal"
sudo -u "$USER_NAME" "$REPO_DIR/venv/bin/python" "$REPO_DIR/app/reseller_gw.py" \
  --db "$REPO_DIR/data/reseller.db" init || warn "init db sudah ada"

if [[ -f "$REPO_DIR/app/proxyhunt/out/usable.json" ]]; then
  cp -f "$REPO_DIR/app/proxyhunt/out/usable.json" "$REPO_DIR/data/usable.json"
  log "pool awal: $(jq 'length' "$REPO_DIR/data/usable.json" 2>/dev/null || echo '?') proxy"
else
  warn "pool kosong — jalankan hunt manual: sudo -u $USER_NAME $REPO_DIR/venv/bin/python $REPO_DIR/app/proxyhunt/pipeline.py"
fi

systemctl daemon-reload
systemctl enable --now dgi-gateway dgi-panel
systemctl restart dgi-gateway dgi-panel

sleep 2
log "status:"
systemctl --no-pager --lines=0 status dgi-gateway | head -4 || true
systemctl --no-pager --lines=0 status dgi-panel   | head -4 || true

IP="$(curl -fsS --max-time 8 https://api.ipify.org || echo '<IP_VPS>')"
echo
log "================ RINGKASAN ================"
echo "  gateway   : $IP:$GATE_PORT  (HTTP + SOCKS5, satu port)"
echo "  panel     : http://${DOMAIN:-$IP}/"
echo "  data      : $REPO_DIR/data"
echo "  log       : $REPO_DIR/logs"
echo "  unit      : systemctl status dgi-gateway dgi-panel"
echo
echo "  tambah akun:"
echo "    sudo -u $USER_NAME $REPO_DIR/venv/bin/python $REPO_DIR/app/reseller_gw.py --db $REPO_DIR/data/reseller.db add --user budi --pass RAHASIA --gb 5"
echo
echo "  tes:"
echo "    curl -x http://budi:RAHASIA@$IP:$GATE_PORT https://ip-api.com/json"
echo "    curl --proxy socks5h://budi:RAHASIA@$IP:$GATE_PORT https://ip-api.com/json"
echo "==========================================="
