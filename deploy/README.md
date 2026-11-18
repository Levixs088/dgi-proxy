# DGI Proxy — provisioning

## Kenapa butuh VPS

Box dev ini keluar lewat shared NAT: IP publik berubah tiap request dan **tidak ada inbound**.
Domain apa pun yang menunjuk ke sana akan mati. Proxy butuh raw TCP listen — Vercel, Cloudflare
Tunnel, pinggy, dan localhost.run semuanya hanya meneruskan HTTP, jadi tidak bisa dipakai.

Yang dibutuhkan: **VPS dengan IPv4 publik asli + inbound terbuka**.

## Jalur nol-modal

Oracle Cloud **Always Free** (Ampere A1: 4 OCPU / 24 GB RAM / 10 TB egress) — satu-satunya
free tier yang memberi IP publik + inbound bebas. Alternatif berbayar murah: Contabo, Hetzner CX22,
DigitalOcean $4.

## Cara pakai

Dari box ini:

```bash
bash deploy/push.sh root@<IP_VPS> dgiproxy.example.com
```

Script akan mengirim kode, membuat venv, memasang dua systemd unit (`dgi-gateway`, `dgi-panel`),
nginx untuk panel, ufw (22/80/443/8899), cron hunt tiap 20 menit, dan logrotate.

Atau manual di VPS:

```bash
sudo DOMAIN=dgiproxy.example.com SRC_DIR=/opt/dgiproxy/src bash provision.sh
```

## Setelah selesai

```bash
# tambah akun
sudo -u dgi /opt/dgiproxy/venv/bin/python /opt/dgiproxy/app/reseller_gw.py \
  --db /opt/dgiproxy/data/reseller.db add --user budi --pass RAHASIA --gb 5

# tes
curl -x http://budi:RAHASIA@<IP_VPS>:8899 https://ip-api.com/json
curl --proxy socks5h://budi:RAHASIA@<IP_VPS>:8899 https://ip-api.com/json
```

## DNS

| record | tipe | nilai |
|---|---|---|
| `dgiproxy.example.com` | A | IP VPS (panel, lewat nginx :80) |
| `gw.dgiproxy.example.com` | A | IP VPS (proxy :8899) |

Domain tidak wajib secara teknis — `http://user:pass@IP:8899` sudah jalan. Domain dipakai untuk
kredibilitas dan supaya IP bisa diganti tanpa memberi tahu pelanggan.

## Yang terverifikasi jalan

Diuji pada venv bersih dengan kode yang sama:

- venv + requirements install → Flask 3.1.3, argon2-cffi 25.1.0
- `init` + `add` → akun `budi` 5 GB
- HTTP proxy → keluar US
- SOCKS5 di port yang sama → keluar NL (Amsterdam)
- password salah → **407**
- sticky `-s<token>` → exit konsisten
- ledger mencatat pemakaian (6,639 byte dari tes)

## Perintah operasional

```bash
systemctl status dgi-gateway dgi-panel
journalctl -u dgi-gateway -f
tail -f /opt/dgiproxy/logs/hunt.log      # pool hunter
sqlite3 /opt/dgiproxy/data/reseller.db \
  'select username, used_bytes/1e9, quota_bytes/1e9 from accounts;'
```

## Mode tanpa VPS (tanpa VCC)

`bash deploy/run-local.sh` — gateway + tunnel Pinggy TCP + panel, semua di box ini.

```bash
bash deploy/run-local.sh
# endpoint publik tertulis di ~/.dgi/state/endpoint.txt
```

Terverifikasi jalan lewat internet publik:

| tes | hasil |
|---|---|
| HTTP proxy | `98.170.57.241` · Atlanta · Cox Communications |
| SOCKS5 (port sama) | `116.101.73.52` · Vietnam |
| password salah | `407` |
| sticky `-s<token>` | `198.8.94.174` Seattle, 3× konsisten |
| filter `-cUS` | keluar US |
| ledger | 21 KB tercatat |

**Batas free tier:** endpoint ganti tiap 60 menit dan hostname-nya memuat IP egress box.
Cocok untuk demo/uji, belum untuk jualan produksi. Untuk endpoint permanen: VPS + `provision.sh`.
