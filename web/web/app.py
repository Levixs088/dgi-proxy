#!/usr/bin/env python3
"""
dgi-proxy/web/app.py — DGI Proxy portal (landing + buyer dashboard + admin panel).

Security posture:
  * Argon2id password hashing (never plaintext)
  * Signed, HttpOnly, SameSite=Lax session cookies; Secure when behind TLS
  * Per-form CSRF tokens (double-checked against session)
  * Login rate limiting: 5 fails / 15 min per (IP, username)
  * Parameterized SQL only (sqlite3)
  * Strict CSP + hardening headers, no inline script/style
  * Proxy passwords generated server-side, shown once, stored hashed-adjacent
    (reseller_gw needs the raw password for Basic auth; it is stored ONLY there)
  * Debug off, reloader off, Werkzeug traceback suppressed

Run:
  .venv/bin/python web/app.py create-admin --user levi
  .venv/bin/python web/app.py serve --port 8900
"""
from __future__ import annotations

import argparse
import os
import secrets
import sqlite3
import sys
import time
from functools import wraps

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from flask import (Flask, flash, redirect, render_template, request,
                   make_response, session, url_for, abort, jsonify)

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # ~/proxy-gw
sys.path.insert(0, BASE)
import reseller_gw  # noqa: E402  (shared ledger + pool)

WEB_DB = os.path.join(BASE, "web", "web.db")
RESELLER_DB = reseller_gw.DB_DEFAULT
POOL = reseller_gw.POOL_DEFAULT
GB = reseller_gw.GB

# ---------------------------------------------------------------- secret key

def load_secret_key() -> str:
    path = os.path.join(BASE, "web", ".secret_key")
    try:
        key = open(path, encoding="ascii").read().strip()
        if len(key) >= 64:
            return key
    except FileNotFoundError:
        pass
    key = secrets.token_hex(48)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key)
    return key

# ---------------------------------------------------------------- schema

WEB_SCHEMA = """
CREATE TABLE IF NOT EXISTS web_users (
    username     TEXT PRIMARY KEY,
    password     TEXT NOT NULL,             -- argon2id hash
    role         TEXT NOT NULL DEFAULT 'buyer',
    created      REAL NOT NULL,
    active       INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS login_attempts (
    ip       TEXT    NOT NULL,
    username TEXT    NOT NULL,
    ts       REAL    NOT NULL,
    ok       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts ON login_attempts(ip, username, ts);
"""

def wconnect() -> sqlite3.Connection:
    c = sqlite3.connect(WEB_DB, timeout=15.0)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=15000")
    return c

def web_init() -> None:
    with wconnect() as c:
        c.executescript(WEB_SCHEMA)

# argon2 hasher — tuned for a small portal (64 MiB, t=3)
ph = PasswordHasher(memory_cost=65536, time_cost=3, parallelism=4)

# ---------------------------------------------------------------- app

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("DGI_SECURE_COOKIES") == "1",
    PERMANENT_SESSION_LIFETIME=4 * 3600,
    MAX_CONTENT_LENGTH=64 * 1024,
    SESSION_COOKIE_NAME="dgi_session",
)
app.json.sort_keys = False

@app.after_request
def harden(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.is_secure:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp

# ---------------------------------------------------------------- csrf

@app.route("/healthz")
def healthz():
    return jsonify(ok=True)

def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(24)
    return session["csrf"]

app.jinja_env.globals["csrf_token"] = csrf_token

def check_csrf() -> None:
    tok_s = session.get("csrf")
    tok_f = request.form.get("csrf", "")
    if not tok_s or not tok_f or not secrets.compare_digest(tok_s, tok_f):
        abort(400, "CSRF token invalid — reload the form")

# ---------------------------------------------------------------- auth helpers

def login_required(role: str | None = None):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            u = session.get("user")
            if not u:
                return redirect(url_for("login", next=request.path))
            with wconnect() as c:
                row = c.execute(
                    "SELECT role, active FROM web_users WHERE username=?", (u,)
                ).fetchone()
            if not row or not row[1]:
                session.clear()
                return redirect(url_for("login"))
            if role and row[0] != role and row[0] != "admin":
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco

def rate_limited(ip: str, username: str) -> bool:
    """True = masih terkunci."""
    window = time.time() - 900
    with wconnect() as c:
        fails = c.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE ip=? AND username=? AND ts>? AND ok=0",
            (ip, username, window),
        ).fetchone()[0]
    return fails >= 5

def record_attempt(ip: str, username: str, ok: bool) -> None:
    with wconnect() as c:
        c.execute("INSERT INTO login_attempts(ip,username,ts,ok) VALUES(?,?,?,?)",
                  (ip, username, time.time(), int(ok)))

# ---------------------------------------------------------------- proxy account mgmt

def proxy_get(user: str) -> dict | None:
    with sqlite3.connect(RESELLER_DB, timeout=15) as c:
        row = c.execute(
            "SELECT username,password,quota_bytes,used_bytes,active FROM accounts WHERE username=?",
            (user,),
        ).fetchone()
    if not row:
        return None
    return {"username": row[0], "password": row[1], "quota": row[2],
            "used": row[3], "active": row[4]}

def proxy_create(user: str, gb: float) -> str:
    pwd = secrets.token_urlsafe(9)
    reseller_gw.add_account(RESELLER_DB, user, pwd, gb)
    return pwd

def pool_stats() -> dict:
    try:
        import json
        p = __import__("json").load(open(POOL))
        lat = sorted(x.get("avg_ms") or x["latency_ms"] for x in p)
        return {
            "upstreams": len(p),
            "socks5": sum(1 for x in p if x.get("proto") == "socks5"),
            "sticky": sum(1 for x in p if x.get("stability", 0) >= 0.99),
            "p50": lat[len(lat) // 2] if lat else 0,
        }
    except Exception:
        return {"upstreams": 0, "socks5": 0, "sticky": 0, "p50": 0}

def proxy_list_all() -> list[dict]:
    with sqlite3.connect(RESELLER_DB, timeout=15) as c:
        rows = c.execute(
            "SELECT username,password,quota_bytes,used_bytes,active,created"
            " FROM accounts ORDER BY created DESC"
        ).fetchall()
    return [{"username": r[0], "password": r[1], "quota": r[2], "used": r[3],
             "active": r[4], "created": r[5]} for r in rows]

# ---------------------------------------------------------------- routes

@app.route("/")
def index():
    return render_template("index.html", stats=pool_stats())

@app.route("/stats.json")
def stats_json():
    return jsonify(pool_stats())

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        check_csrf()
        username = request.form.get("username", "").strip()[:64]
        password = request.form.get("password", "")
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()

        if rate_limited(ip, username):
            app.logger.warning("login lockout ip=%s user=%s", ip, username)
            flash("Terlalu banyak percobaan gagal. Coba lagi 15 menit.", "err")
            return render_template("login.html"), 429

        with wconnect() as c:
            row = c.execute(
                "SELECT password, role, active FROM web_users WHERE username=?", (username,)
            ).fetchone()

        ok = False
        if row and row[2]:
            try:
                ph.verify(row[0], password)
                ok = True  # do NOT rehash-branch before flag; keep timing simple
            except VerifyMismatchError:
                ok = False
            except (InvalidHashError, Exception):
                ok = False
        # constant-ish: verify against dummy hash even when user unknown
        if not row:
            try:
                ph.verify(ph.hash("dummy"), password)
            except Exception:
                pass

        record_attempt(ip, username, ok)
        if not ok:
            flash("Kredensial salah.", "err")
            return render_template("login.html"), 401

        session.clear()
        session["user"] = username
        session["role"] = row[1]
        session.permanent = True
        nxt = request.args.get("next", "")
        if nxt.startswith("/") and not nxt.startswith("//"):
            return redirect(nxt)
        return redirect(url_for("panel"))

    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    check_csrf()
    session.clear()
    return redirect(url_for("index"))

@app.route("/panel")
@login_required()
def panel():
    user = session["user"]
    acc = proxy_get(user)
    usage = []
    if acc:
        with sqlite3.connect(RESELLER_DB, timeout=15) as c:
            usage = c.execute(
                "SELECT ts, nbytes, host FROM usage_log WHERE username=?"
                " ORDER BY ts DESC LIMIT 25", (user,)
            ).fetchall()
    return render_template("panel.html", acc=acc, usage=usage, gb=GB)

@app.route("/admin")
@login_required(role="admin")
def admin():
    web_users = []
    with wconnect() as c:
        web_users = c.execute(
            "SELECT username, role, created, active FROM web_users ORDER BY created DESC"
        ).fetchall()
    return render_template("admin.html", web_users=web_users,
                           proxies=proxy_list_all(), stats=pool_stats(), gb=GB)

@app.route("/admin/user/create", methods=["POST"])
@login_required(role="admin")
def admin_create():
    check_csrf()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "buyer")
    gb = float(request.form.get("gb", "1") or 1)
    if not username.isalnum() or len(username) < 3 or len(username) > 32:
        flash("Username: alnum, 3-32 char.", "err")
        return redirect(url_for("admin"))
    if len(password) < 8:
        flash("Password web minimal 8 char.", "err")
        return redirect(url_for("admin"))
    if role not in ("buyer", "admin"):
        role = "buyer"
    try:
        with wconnect() as c:
            c.execute("INSERT INTO web_users(username,password,role,created,active) VALUES(?,?,?,?,1)",
                      (username, ph.hash(password), role, time.time()))
    except sqlite3.IntegrityError:
        flash("Username sudah ada.", "err")
        return redirect(url_for("admin"))
    proxy_pwd = proxy_create(username, gb) if role == "buyer" else ""
    flash(f"User {username} dibuat. Password proxy: {proxy_pwd} (tampil sekali)", "ok")
    return redirect(url_for("admin"))

@app.route("/admin/user/topup", methods=["POST"])
@login_required(role="admin")
def admin_topup():
    check_csrf()
    username = request.form.get("username", "").strip()
    try:
        gb = float(request.form.get("gb", "0") or 0)
    except ValueError:
        gb = 0
    if gb <= 0:
        flash("GB harus > 0", "err")
        return redirect(url_for("admin"))
    try:
        reseller_gw.topup(RESELLER_DB, username, gb)
        flash(f"Topup {gb} GB untuk {username}", "ok")
    except SystemExit:
        flash("User proxy tidak ditemukan.", "err")
    return redirect(url_for("admin"))

@app.route("/admin/user/toggle", methods=["POST"])
@login_required(role="admin")
def admin_toggle():
    check_csrf()
    username = request.form.get("username", "").strip()
    state = 1 if request.form.get("state") == "on" else 0
    with wconnect() as c:
        c.execute("UPDATE web_users SET active=? WHERE username=?", (state, username))
    reseller_gw.disable(RESELLER_DB, username, state)
    flash(f"{username} {'diaktifkan' if state else 'dimatikan'}", "ok")
    return redirect(url_for("admin"))

@app.errorhandler(400)
def e400(e): return render_template("err.html", code=400, msg=str(e)), 400
@app.errorhandler(403)
def e403(e): return render_template("err.html", code=403, msg="Forbidden"), 403
@app.errorhandler(404)
def e404(e): return render_template("err.html", code=404, msg="Not found"), 404
@app.errorhandler(429)
def e429(e): return render_template("err.html", code=429, msg="Slow down"), 429
@app.errorhandler(500)
def e500(e): return render_template("err.html", code=500, msg="Server error"), 500

# ---------------------------------------------------------------- cli / serve

def create_admin(username: str, password: str) -> None:
    web_init()
    with wconnect() as c:
        c.execute("INSERT OR REPLACE INTO web_users(username,password,role,created,active) VALUES(?,?,?,?,1)",
                  (username, ph.hash(password), "admin", time.time()))
    print(f"admin '{username}' created")

def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    ca = sub.add_parser("create-admin")
    ca.add_argument("--user", required=True)
    ca.add_argument("--pass", dest="password")
    sv = sub.add_parser("serve")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8900)
    args = ap.parse_args()
    if args.cmd == "create-admin":
        import getpass
        pwd = args.password or getpass.getpass("password: ")
        if len(pwd) < 8:
            raise SystemExit("password minimal 8 char")
        create_admin(args.user, pwd)
    elif args.cmd == "serve":
        web_init()
        app.run(host=args.host, port=args.port, debug=False, use_reloader=False)

if __name__ == "__main__":
    main()
