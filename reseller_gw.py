#!/usr/bin/env python3
"""
reseller_gw.py — Reseller proxy gateway (model BagiResi).

Satu port, dua protokol (HTTP proxy + SOCKS5), multi-user, metering per-GB,
upstream diputar dari pool proxyhunt (out/usable.json).

Auth client:
  HTTP   : Proxy-Authorization: Basic base64(user:pass)
  SOCKS5 : RFC1929 username/password

Direktif di username (urutan bebas, case-insensitive):
  -s<token>   sticky session -> hash(token) menentukan exit IP yang sama
  -c<CC>      negara keluar, mis. -cUS / -cID

Username tanpa direktif = rotating random tiap koneksi.

CLI:
  python3 reseller_gw.py init
  python3 reseller_gw.py add --user budi --pass rahasia --gb 5
  python3 reseller_gw.py list
  python3 reseller_gw.py topup budi --gb 2
  python3 reseller_gw.py serve --port 8899
  curl -x http://budi-sabc123:rahasia@127.0.0.1:8899 http://ip-api.com/json
  curl --proxy socks5h://budi-sabc123:rahasia@127.0.0.1:8899 https://api.ipify.org
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import random
import re
import secrets
import sqlite3
import struct
import sys
import time
import zlib

DB_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reseller.db")
POOL_DEFAULT = os.path.expanduser("~/proxyhunt/out/usable.json")
GB = 1024 ** 3

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    username    TEXT PRIMARY KEY,
    password    TEXT    NOT NULL,
    quota_bytes INTEGER NOT NULL DEFAULT 0,
    used_bytes  INTEGER NOT NULL DEFAULT 0,
    created     REAL    NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS usage_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT    NOT NULL,
    ts       REAL    NOT NULL,
    nbytes   INTEGER NOT NULL,
    host     TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_usage_user ON usage_log(username, ts);
"""

USER_RE = re.compile(
    r"^(?P<base>.+?)(?:-s(?P<sess>[0-9A-Za-z]{1,32}))?(?:-c(?P<cc>[A-Za-z]{2}))?$",
    re.IGNORECASE,
)


def connect(path: str) -> sqlite3.Connection:
    c = sqlite3.connect(path, timeout=15.0)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=15000")
    return c


def init_db(path: str) -> None:
    with connect(path) as c:
        c.executescript(SCHEMA)


# ---------------------------------------------------------------- accounts

def add_account(path: str, user: str, password: str, gb: float) -> None:
    with connect(path) as c:
        c.execute(
            "INSERT OR REPLACE INTO accounts(username,password,quota_bytes,used_bytes,created,active)"
            " VALUES(?,?,?,?,?,1)",
            (user, password, int(gb * GB), 0, time.time()),
        )


def topup(path: str, user: str, gb: float) -> None:
    with connect(path) as c:
        n = c.execute(
            "UPDATE accounts SET quota_bytes = quota_bytes + ? WHERE username = ?",
            (int(gb * GB), user),
        ).rowcount
    if not n:
        raise SystemExit(f"unknown user: {user}")


def disable(path: str, user: str, state: int) -> None:
    with connect(path) as c:
        c.execute("UPDATE accounts SET active = ? WHERE username = ?", (state, user))


def list_accounts(path: str) -> None:
    with connect(path) as c:
        rows = c.execute(
            "SELECT username,quota_bytes,used_bytes,active,created FROM accounts ORDER BY created"
        ).fetchall()
    if not rows:
        print("(no accounts)")
        return
    print(f"{'user':<20} {'used GB':>9} {'quota GB':>9} {'%':>6}  state")
    print("-" * 60)
    for user, quota, used, active, _ in rows:
        pct = (used / quota * 100) if quota else 0.0
        print(f"{user:<20} {used/GB:>9.3f} {quota/GB:>9.3f} {pct:>5.1f}%  "
              f"{'active' if active else 'DISABLED'}")


# ---------------------------------------------------------------- ledger

class Ledger:
    """Byte ledger per user; pending bytes dihitung dalam quota check."""

    FLUSH_BYTES = 1 * 1024 * 1024

    def __init__(self, path: str):
        self.path = path
        self.pending: dict[str, int] = {}
        self.lock = asyncio.Lock()

    async def authorize(self, user: str, password: str) -> tuple[bool, str, int]:
        async with self.lock:
            pending = self.pending.get(user, 0)
        with connect(self.path) as c:
            row = c.execute(
                "SELECT quota_bytes,used_bytes,active FROM accounts WHERE username=? AND password=?",
                (user, password),
            ).fetchone()
        if not row:
            return False, "invalid credentials", 0
        quota, used, active = row
        if not active:
            return False, "account disabled", quota
        if quota and (used + pending) >= quota:
            return False, "quota exhausted", quota
        return True, "", (used + pending)

    async def charge(self, user: str, nbytes: int, host: str) -> None:
        if nbytes <= 0:
            return
        async with self.lock:
            self.pending[user] = self.pending.get(user, 0) + nbytes
            if self.pending[user] < self.FLUSH_BYTES:
                return
            total = self.pending.pop(user)
        self._write(user, total, host)

    def _write(self, user: str, nbytes: int, host: str) -> None:
        try:
            with connect(self.path) as c:
                c.execute(
                    "UPDATE accounts SET used_bytes = used_bytes + ? WHERE username=?",
                    (nbytes, user),
                )
                c.execute(
                    "INSERT INTO usage_log(username,ts,nbytes,host) VALUES(?,?,?,?)",
                    (user, time.time(), nbytes, host),
                )
        except sqlite3.Error as e:
            print(f"[ledger] write failed: {e}", file=sys.stderr)

    async def flush_all(self) -> None:
        async with self.lock:
            items = list(self.pending.items())
            self.pending.clear()
        for user, nbytes in items:
            self._write(user, nbytes, "")


class QuotaExceeded(Exception):
    pass


# ---------------------------------------------------------------- upstream pool

class Upstreams:
    """Pool upstream dari proxyhunt usable.json, auto-reload saat file berubah,
    deadlist cooldown 5 menit untuk upstream yang gagal."""

    def __init__(self, path: str):
        self.path = path
        self.mtime = 0.0
        self.pool: list[dict] = []
        self.dead: dict[str, float] = {}

    def _load(self) -> None:
        try:
            m = os.path.getmtime(self.path)
        except OSError:
            return
        if m == self.mtime:
            return
        self.mtime = m
        try:
            self.pool = json.load(open(self.path))
            print(f"[pool] loaded {len(self.pool)} upstreams")
        except Exception as e:
            print(f"[pool] load failed: {e}", file=sys.stderr)

    def pick(self, cc: str | None, sess: str | None) -> dict | None:
        self._load()
        now = time.time()
        alive = [p for p in self.pool if self.dead.get(p["addr"], 0) < now]
        if not alive:
            return None
        if cc:
            by_cc = [p for p in alive if (p.get("country") or "").upper() == cc.upper()]
            if by_cc:
                alive = by_cc
        if sess:
            alive = sorted(alive, key=lambda p: p["addr"])
            return alive[zlib.crc32(sess.encode()) % len(alive)]
        return random.choice(alive)

    def fail(self, addr: str) -> None:
        self.dead[addr] = time.time() + 300


async def open_upstream(up: dict, host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Buka tunnel ke host:port LEWAT upstream (http CONNECT atau socks5)."""
    h, p = up["addr"].rsplit(":", 1)
    r, w = await asyncio.wait_for(asyncio.open_connection(h, int(p)), 20)
    try:
        if up["proto"] == "http":
            w.write(
                f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode()
            )
            await w.drain()
            head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 25)
            if b" 200" not in head.split(b"\r\n")[0]:
                raise ConnectionError(f"upstream CONNECT refused: {head[:60]!r}")
        else:  # socks5
            w.write(b"\x05\x01\x00")  # ver5, 1 method, no-auth
            await w.drain()
            greet = await asyncio.wait_for(r.readexactly(2), 20)
            if greet[0] != 5 or greet[1] != 0:
                raise ConnectionError("upstream socks5: no matching method")
            addr = host.encode()
            req = b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr + struct.pack(">H", port)
            w.write(req)
            await w.drain()
            resp = await asyncio.wait_for(r.readexactly(4), 25)
            if resp[1] != 0:
                raise ConnectionError(f"upstream socks5 reply {resp[1]}")
            atyp = resp[3]
            if atyp == 1:
                await r.readexactly(4 + 2)
            elif atyp == 3:
                n = (await r.readexactly(1))[0]
                await r.readexactly(n + 2)
            elif atyp == 4:
                await r.readexactly(16 + 2)
            else:
                raise ConnectionError("upstream socks5 bad atyp")
        return r, w
    except Exception:
        try:
            w.close()
        except Exception:
            pass
        raise


# ---------------------------------------------------------------- metering pump

async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter,
               on_bytes=None) -> None:
    try:
        while True:
            data = await src.read(65536)
            if not data:
                break
            dst.write(data)
            await dst.drain()
            if on_bytes is not None:
                await on_bytes(len(data))
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError, QuotaExceeded):
        pass
    finally:
        try:
            dst.close()
        except Exception:
            pass


def make_meter(ledger: Ledger, user: str, host: str, quota: int, start_used: int):
    state = {"used": start_used}

    async def on_bytes(n: int) -> None:
        state["used"] += n
        await ledger.charge(user, n, host)
        if quota and state["used"] >= quota:
            raise QuotaExceeded()

    return on_bytes


def deny(writer: asyncio.StreamWriter, status: str, body: str) -> None:
    payload = body.encode()
    writer.write(
        f"HTTP/1.1 {status}\r\nContent-Type: text/plain\r\n"
        f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode() + payload
    )


async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                up_r, up_w, ledger: Ledger, user: str, host: str, quota: int, used: int) -> None:
    on_bytes = make_meter(ledger, user, host, quota, used)
    try:
        await asyncio.gather(
            pump(reader, up_w, on_bytes),
            pump(up_r, writer, on_bytes),
        )
    except QuotaExceeded:
        pass
    finally:
        try:
            up_w.close()
        except Exception:
            pass


# ---------------------------------------------------------------- auth parsing

def parse_user(raw: str) -> tuple[str, str | None, str | None]:
    m = USER_RE.match(raw)
    if m:
        return m.group("base"), (m.group("sess") or "").lower() or None, \
            (m.group("cc") or "").upper() or None
    return raw, None, None


async def auth_http(head: bytes, ledger: Ledger) -> tuple[str | None, str | None, str | None]:
    """Return (user, sess, cc) kalau valid, kalau tidak None."""
    raw = None
    for line in head.split(b"\r\n")[1:]:
        if not line:
            break
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"proxy-authorization":
            token = value.strip()
            if token.lower().startswith(b"basic "):
                try:
                    raw = base64.b64decode(token[6:]).decode(errors="replace")
                except Exception:
                    return None, None, None
    if not raw or ":" not in raw:
        return None, None, None
    user_raw, password = raw.split(":", 1)
    user, sess, cc = parse_user(user_raw)
    ok, _, _ = await ledger.authorize(user, password)
    if not ok:
        return None, None, None
    return user, sess, cc


# ---------------------------------------------------------------- client HTTP proxy

async def handle_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                      head: bytes, ledger: Ledger, ups: Upstreams) -> None:
    user, sess, cc = await auth_http(head, ledger)
    if not user:
        deny(writer, "407 Proxy Authentication Required", "invalid user/pass or directives\n")
        await writer.drain()
        return

    ok, reason, used = await ledger.authorize(user, "")  # password check done in auth_http
    # authorize dipanggil ulang via auth_http; di sini ambil used+quota utk meter:
    with connect(ledger.path) as c:
        row = c.execute("SELECT quota_bytes,used_bytes FROM accounts WHERE username=?",
                        (user,)).fetchone()
    quota, used = row

    line = head.split(b"\r\n", 1)[0].decode(errors="replace")
    parts = line.split()
    if len(parts) < 3:
        deny(writer, "400 Bad Request", "bad request line\n")
        await writer.drain()
        return
    method, target = parts[0].upper(), parts[1]

    if method == "CONNECT":
        host, _, port_s = target.partition(":")
        port = int(port_s or 443)
    else:
        if not target.lower().startswith("http://"):
            deny(writer, "400 Bad Request", "only absolute http:// URIs\n")
            await writer.drain()
            return
        rest = target[7:]
        hostport, _, path = rest.partition("/")
        host, _, port_s = hostport.partition(":")
        port = int(port_s or 80)

    up = ups.pick(cc, sess)
    if not up:
        deny(writer, "503 Service Unavailable", "no upstream available\n")
        await writer.drain()
        return

    try:
        up_r, up_w = await open_upstream(up, host, port)
    except Exception as e:
        ups.fail(up["addr"])
        deny(writer, "502 Bad Gateway", f"upstream failed: {type(e).__name__}\n")
        await writer.drain()
        return

    if method == "CONNECT":
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await relay(reader, writer, up_r, up_w, ledger, user, host, quota, used)
    else:
        # forward request baru ke upstream dgn path relatif
        raw_lines = head.split(b"\r\n")
        keep = []
        for ln in raw_lines[1:]:
            if not ln:
                break
            name = ln.split(b":", 1)[0].strip().lower()
            if name in (b"proxy-authorization", b"proxy-connection", b"connection"):
                continue
            keep.append(ln)
        keep.append(b"Connection: close")
        req = f"{method} /{'/' if not path.startswith('/') else path.lstrip('/')} HTTP/1.1\r\n".encode()
        req += b"\r\n".join(keep) + b"\r\n\r\n"
        # NOTE: Host header dari klien sudah dibawa di `keep`
        up_w.write(req)
        await up_w.drain()
        await relay(up_r, writer, up_r, up_w, ledger, user, host, quota, used) if False else None
        await relay(reader, writer, up_r, up_w, ledger, user, host, quota, used)


# ---------------------------------------------------------------- client SOCKS5

async def handle_socks5(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                        ledger: Ledger, ups: Upstreams) -> None:
    # greeting sudah dibaca 1 byte (0x05); baca sisanya
    nmethods = (await reader.readexactly(1))[0]
    await reader.readexactly(nmethods)

    # minta username/password (RFC1929)
    writer.write(b"\x05\x02")
    await writer.drain()
    ver = (await reader.readexactly(1))[0]
    if ver != 0x01:
        return
    ulen = (await reader.readexactly(1))[0]
    user_raw = (await reader.readexactly(ulen)).decode(errors="replace")
    plen = (await reader.readexactly(1))[0]
    password = (await reader.readexactly(plen)).decode(errors="replace")

    user, sess, cc = parse_user(user_raw)
    ok, reason, _ = await ledger.authorize(user, password)
    if not ok:
        writer.write(b"\x01\x01")  # auth failed
        await writer.drain()
        return
    writer.write(b"\x01\x00")  # auth ok
    await writer.drain()

    with connect(ledger.path) as c:
        row = c.execute("SELECT quota_bytes,used_bytes FROM accounts WHERE username=?",
                        (user,)).fetchone()
    quota, used = row

    # request: VER CMD RSV ATYP ...
    hdr = await reader.readexactly(4)
    cmd = hdr[1]
    atyp = hdr[3]
    if cmd != 1:  # hanya CONNECT
        writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
        await writer.drain()
        return
    if atyp == 1:
        host = ".".join(str(b) for b in await reader.readexactly(4))
    elif atyp == 3:
        n = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(n)).decode(errors="replace")
    elif atyp == 4:
        raw = await reader.readexactly(16)
        host = ":".join(f"{raw[i:i+2].hex()}" for i in range(0, 16, 2))
    else:
        writer.write(b"\x05\x08\x00\x01" + b"\x00" * 6)
        await writer.drain()
        return
    (port,) = struct.unpack(">H", await reader.readexactly(2))

    up = ups.pick(cc, sess)
    if not up:
        writer.write(b"\x05\x01\x00\x01" + b"\x00" * 6)
        await writer.drain()
        return

    try:
        up_r, up_w = await open_upstream(up, host, port)
    except Exception:
        ups.fail(up["addr"])
        writer.write(b"\x05\x01\x00\x01" + b"\x00" * 6)
        await writer.drain()
        return

    writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
    await writer.drain()
    await relay(reader, writer, up_r, up_w, ledger, user, host, quota, used)


# ---------------------------------------------------------------- dispatcher

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                        ledger: Ledger, ups: Upstreams) -> None:
    try:
        first = await asyncio.wait_for(reader.readexactly(1), 30)
        if first == b"\x05":  # SOCKS5 greeting mulai dengan 0x05
            await handle_socks5(reader, writer, ledger, ups)
        else:  # HTTP proxy request (method ASCII)
            head = first + await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
            await handle_http(reader, writer, head, ledger, ups)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError,
            ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        print(f"[gw] client error: {type(e).__name__}: {e}", file=sys.stderr)
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def serve(args: argparse.Namespace) -> None:
    init_db(args.db)
    ledger = Ledger(args.db)
    ups = Upstreams(args.pool)

    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, ledger, ups), args.host, args.port, backlog=512
    )
    where = ", ".join(str(s.getsockname()) for s in server.sockets or [])
    print(f"[gw] listening on {where} (HTTP + SOCKS5 autodetect)")
    print(f"[gw] pool:    {args.pool}")
    print(f"[gw] ledger:  {args.db}")

    async def periodic() -> None:
        while True:
            await asyncio.sleep(15)
            await ledger.flush_all()

    flusher = asyncio.create_task(periodic())
    try:
        async with server:
            await server.serve_forever()
    finally:
        flusher.cancel()
        await ledger.flush_all()


# ---------------------------------------------------------------- cli

def main() -> None:
    ap = argparse.ArgumentParser(description="reseller proxy gateway")
    ap.add_argument("--db", default=DB_DEFAULT)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init")

    a = sub.add_parser("add")
    a.add_argument("--user", required=True)
    a.add_argument("--pass", dest="password", required=True)
    a.add_argument("--gb", type=float, default=1.0)

    t = sub.add_parser("topup")
    t.add_argument("user")
    t.add_argument("--gb", type=float, required=True)

    d = sub.add_parser("disable")
    d.add_argument("user")

    e = sub.add_parser("enable")
    e.add_argument("user")

    sub.add_parser("list")

    s = sub.add_parser("serve")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8899)
    s.add_argument("--pool", default=POOL_DEFAULT)

    args = ap.parse_args()
    if args.cmd == "init":
        init_db(args.db)
        print(f"initialised {args.db}")
    elif args.cmd == "add":
        if not args.password:
            args.password = secrets.token_hex(8)
        add_account(args.db, args.user, args.password, args.gb)
        print(f"ok: {args.user} / {args.password} ({args.gb} GB)")
    elif args.cmd == "topup":
        topup(args.db, args.user, args.gb)
        print("ok")
    elif args.cmd == "disable":
        disable(args.db, args.user, 0)
        print("ok")
    elif args.cmd == "enable":
        disable(args.db, args.user, 1)
        print("ok")
    elif args.cmd == "list":
        list_accounts(args.db)
    elif args.cmd == "serve":
        try:
            asyncio.run(serve(args))
        except KeyboardInterrupt:
            print("\n[gw] stopped")


if __name__ == "__main__":
    main()
