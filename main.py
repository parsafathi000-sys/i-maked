#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║                     BEST PANEL v2.0                          ║
║          Premium Subscription Management Panel                ║
║                  Built with FastAPI + SQLite                  ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
import os
import hashlib
import secrets
import time
import re
import base64
import ipaddress
import uuid as uuid_lib
import socket
import struct
from datetime import datetime, timezone, timedelta
from urllib.parse import quote
from collections import deque, defaultdict
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends, Query, Body
from fastapi.responses import Response, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

import uvicorn
import httpx
import psutil
import bcrypt
from jose import jwt, JWTError
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import aiosqlite
import logging
import logging.config

try:
    import uvloop
    uvloop.install()
except ImportError:
    pass

try:
    import asyncpg
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False

# ── Logging ────────────────────────────────────────────────
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
        }
    },
    "handlers": {"json_console": {"class": "logging.StreamHandler", "formatter": "json"}},
    "root": {"level": "INFO", "handlers": ["json_console"]},
}
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("BestPanel")
print("═══ BEST PANEL v2.0 ═══")

limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

# ── Configuration ──────────────────────────────────────────
CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret_key": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
    "jwt_algorithm": "HS256",
    "jwt_expire_minutes": 10080,
    "db_path": os.environ.get("DB_PATH", "/data/panel.db"),
    "admin_password": os.environ.get("ADMIN_PASSWORD", "admin"),
    "database_url": os.environ.get("DATABASE_URL", ""),
}

if HAS_POSTGRES:
    ADDRESS_INTEGRITY_ERRORS = (aiosqlite.IntegrityError, asyncpg.exceptions.UniqueViolationError)
else:
    ADDRESS_INTEGRITY_ERRORS = (aiosqlite.IntegrityError,)

db_conn: Optional[aiosqlite.Connection] = None
db_lock = asyncio.Lock()
ENABLE_LOGGING = True
KEEP_ALIVE_INTERVAL = 300
TIMEZONE_OFFSET = 0.0
KEEP_ALIVE_ENABLED = True
KEEP_ALIVE_MODE = "simple"

traffic_buffer_lock = asyncio.Lock()
traffic_buffer = {"hourly": defaultdict(int), "daily": defaultdict(int)}

# In-memory stores
USERS: dict = {}
USERS_LOCK = asyncio.Lock()
CUSTOM_ADDRESSES: list = ["www.speedtest.net"]
CUSTOM_ADDRESSES_LOCK = asyncio.Lock()

connections: dict = {}
connections_lock = asyncio.Lock()
connection_sockets: dict = {}
link_ip_map: dict = defaultdict(set)

stats = {
    "total_bytes": 0, "total_requests": 0, "total_errors": 0,
    "start_time": time.time(), "upload_bytes": 0, "download_bytes": 0,
}
error_logs: deque = deque(maxlen=2000)
CACHE_TTL = 60
link_cache: dict = {}
SESSION_COOKIE = "BEST_session"
UNLIMITED_QUOTA_BYTES = 53687091200000
ADMIN_PASSWORD_HASH: str = ""
ENABLE_LOGGING = True
KEEP_ALIVE_ENABLED = True
KEEP_ALIVE_MODE = "simple"
RELAY_BUF = 512 * 1024

# Notification store
notifications: deque = deque(maxlen=200)

# ============================================================
#  DATABASE LAYER
# ============================================================

if CONFIG["database_url"] and HAS_POSTGRES:
    DB_BACKEND = "postgresql"
    pg_pool: Optional[asyncpg.Pool] = None

    async def init_pg():
        global pg_pool
        pg_pool = await asyncpg.create_pool(CONFIG["database_url"], min_size=2, max_size=10)
        async with pg_pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    uid TEXT PRIMARY KEY, username TEXT NOT NULL,
                    password TEXT DEFAULT '', limit_bytes BIGINT DEFAULT 0,
                    used_bytes BIGINT DEFAULT 0, upload_bytes BIGINT DEFAULT 0,
                    download_bytes BIGINT DEFAULT 0,
                    max_connections INT DEFAULT 0, created_at TEXT NOT NULL,
                    active BOOLEAN DEFAULT TRUE, expires_at TEXT,
                    custom_path TEXT DEFAULT '', custom_sni TEXT DEFAULT '',
                    custom_host TEXT DEFAULT '', custom_fp TEXT DEFAULT 'chrome',
                    color TEXT DEFAULT '#39ff14', flag TEXT DEFAULT '',
                    fragment TEXT DEFAULT '', notes TEXT DEFAULT '',
                    tags TEXT DEFAULT '', speed_limit BIGINT DEFAULT 0,
                    priority INT DEFAULT 0, avatar TEXT DEFAULT '',
                    allowed_ips TEXT DEFAULT '', blocked_ips TEXT DEFAULT '',
                    allowed_countries TEXT DEFAULT '', allowed_protocols TEXT DEFAULT '',
                    custom_dns TEXT DEFAULT '', reset_cycle TEXT DEFAULT 'none',
                    max_devices INT DEFAULT 0,
                    total_connections INT DEFAULT 0, total_sessions INT DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS hourly_traffic (hour TEXT PRIMARY KEY, bytes BIGINT DEFAULT 0);
                CREATE TABLE IF NOT EXISTS daily_traffic (day TEXT PRIMARY KEY, bytes BIGINT DEFAULT 0);
                CREATE TABLE IF NOT EXISTS custom_addresses (id SERIAL PRIMARY KEY, address TEXT NOT NULL UNIQUE);
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE IF NOT EXISTS login_logs (
                    id SERIAL PRIMARY KEY, timestamp TEXT NOT NULL,
                    ip TEXT, success BOOLEAN DEFAULT TRUE,
                    user_agent TEXT DEFAULT '', path TEXT DEFAULT '',
                    country TEXT DEFAULT '', city TEXT DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS connection_logs (
                    id SERIAL PRIMARY KEY, timestamp TEXT NOT NULL,
                    uid TEXT, username TEXT, ip TEXT,
                    country TEXT DEFAULT '', city TEXT DEFAULT '',
                    isp TEXT DEFAULT '', device TEXT DEFAULT '',
                    browser TEXT DEFAULT '', os TEXT DEFAULT '',
                    upload BIGINT DEFAULT 0, download BIGINT DEFAULT 0,
                    duration INT DEFAULT 0, status TEXT DEFAULT 'active'
                );
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id SERIAL PRIMARY KEY, timestamp TEXT NOT NULL,
                    action TEXT, uid TEXT, username TEXT,
                    ip TEXT, details TEXT DEFAULT ''
                );
            """)

    async def db_execute(sqlite_q: str, pg_q: str, params: tuple = ()):
        if DB_BACKEND == "postgresql":
            async with pg_pool.acquire() as conn:
                await conn.execute(pg_q, *params)
        else:
            async with db_lock:
                await db_conn.execute(sqlite_q, params)
                await db_conn.commit()

    async def db_fetchall(sqlite_q: str, pg_q: str, params: tuple = ()) -> list:
        if DB_BACKEND == "postgresql":
            async with pg_pool.acquire() as conn:
                rows = await conn.fetch(pg_q, *params)
                return [dict(r) for r in rows]
        else:
            async with db_lock:
                cur = await db_conn.execute(sqlite_q, params)
                rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def db_fetchone(sqlite_q: str, pg_q: str, params: tuple = ()) -> Optional[dict]:
        if DB_BACKEND == "postgresql":
            async with pg_pool.acquire() as conn:
                row = await conn.fetchrow(pg_q, *params)
                return dict(row) if row else None
        else:
            async with db_lock:
                cur = await db_conn.execute(sqlite_q, params)
                row = await cur.fetchone()
            return dict(row) if row else None
else:
    DB_BACKEND = "sqlite"

    async def init_db():
        global db_conn
        db_path = CONFIG["db_path"]
        try:
            test_file = os.path.join(os.path.dirname(db_path), ".write_test")
            with open(test_file, "w") as f: f.write("ok")
            os.remove(test_file)
        except Exception:
            logger.warning(f"Cannot write to {db_path}, falling back to /tmp/panel.db")
            CONFIG["db_path"] = "/tmp/panel.db"
            db_path = "/tmp/panel.db"
        db_conn = await aiosqlite.connect(db_path)
        db_conn.row_factory = aiosqlite.Row
        await db_conn.execute("PRAGMA journal_mode=WAL")
        await db_conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                uid TEXT PRIMARY KEY, username TEXT NOT NULL,
                password TEXT DEFAULT '', limit_bytes INTEGER DEFAULT 0,
                used_bytes INTEGER DEFAULT 0, upload_bytes INTEGER DEFAULT 0,
                download_bytes INTEGER DEFAULT 0,
                max_connections INTEGER DEFAULT 0, created_at TEXT NOT NULL,
                active INTEGER DEFAULT 1, expires_at TEXT,
                custom_path TEXT DEFAULT '', custom_sni TEXT DEFAULT '',
                custom_host TEXT DEFAULT '', custom_fp TEXT DEFAULT 'chrome',
                color TEXT DEFAULT '#39ff14', flag TEXT DEFAULT '',
                fragment TEXT DEFAULT '', notes TEXT DEFAULT '',
                tags TEXT DEFAULT '', speed_limit INTEGER DEFAULT 0,
                priority INTEGER DEFAULT 0, avatar TEXT DEFAULT '',
                allowed_ips TEXT DEFAULT '', blocked_ips TEXT DEFAULT '',
                allowed_countries TEXT DEFAULT '', allowed_protocols TEXT DEFAULT '',
                custom_dns TEXT DEFAULT '', reset_cycle TEXT DEFAULT 'none',
                max_devices INTEGER DEFAULT 0,
                total_connections INTEGER DEFAULT 0, total_sessions INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS hourly_traffic (hour TEXT PRIMARY KEY, bytes INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS daily_traffic (day TEXT PRIMARY KEY, bytes INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS custom_addresses (id INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT NOT NULL UNIQUE);
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
                ip TEXT, success INTEGER DEFAULT 1,
                user_agent TEXT DEFAULT '', path TEXT DEFAULT '',
                country TEXT DEFAULT '', city TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS connection_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
                uid TEXT, username TEXT, ip TEXT,
                country TEXT DEFAULT '', city TEXT DEFAULT '',
                isp TEXT DEFAULT '', device TEXT DEFAULT '',
                browser TEXT DEFAULT '', os TEXT DEFAULT '',
                upload INTEGER DEFAULT 0, download INTEGER DEFAULT 0,
                duration INTEGER DEFAULT 0, status TEXT DEFAULT 'active'
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
                action TEXT, uid TEXT, username TEXT,
                ip TEXT, details TEXT DEFAULT ''
            );
        """)
        await db_conn.commit()

    async def db_execute(sqlite_q: str, pg_q: str = "", params: tuple = ()):
        async with db_lock:
            await db_conn.execute(sqlite_q, params)
            await db_conn.commit()

    async def db_fetchall(sqlite_q: str, pg_q: str = "", params: tuple = ()) -> list:
        async with db_lock:
            cur = await db_conn.execute(sqlite_q, params)
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def db_fetchone(sqlite_q: str, pg_q: str = "", params: tuple = ()) -> Optional[dict]:
        async with db_lock:
            cur = await db_conn.execute(sqlite_q, params)
            row = await cur.fetchone()
        return dict(row) if row else None

# ============================================================
#  HELPER FUNCTIONS
# ============================================================

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def create_jwt_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=CONFIG["jwt_expire_minutes"]))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, CONFIG["secret_key"], algorithm=CONFIG["jwt_algorithm"])

def decode_jwt_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, CONFIG["secret_key"], algorithms=[CONFIG["jwt_algorithm"]])
    except JWTError:
        return None

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token or not decode_jwt_token(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

def get_domain() -> str:
    domain = (
        os.environ.get("DOMAIN") or
        os.environ.get("RENDER_EXTERNAL_URL") or
        os.environ.get("RAILWAY_PUBLIC_DOMAIN") or
        "localhost"
    )
    return domain.replace("https://", "").replace("http://", "")

def validate_address(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr.strip("[]"))
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(addr.strip("[]"), strict=False)
        return True
    except ValueError:
        pass
    return re.match(r'^[a-zA-Z0-9\-_.%]+$', addr) is not None

def code_to_flag(code: str) -> str:
    if not code or len(code) != 2: return ""
    code = code.upper()
    try:
        return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
    except:
        return ""

def generate_vless_link(uid: str, remark: str = "BestPanel", address: str = None, extra: dict = None) -> str:
    cache_key = f"{uid}:{remark}:{address}:{json.dumps(extra) if extra else ''}"
    if cache_key in link_cache and link_cache[cache_key]["expires"] > time.time():
        return link_cache[cache_key]["link"]
    domain = get_domain()
    addr = address if address else domain
    path = (extra.get("custom_path") or f"/ws/{uid}") if extra else f"/ws/{uid}"
    sni = (extra.get("custom_sni") or domain) if extra else domain
    host = (extra.get("custom_host") or domain) if extra else domain
    fp = (extra.get("custom_fp") or "chrome") if extra else "chrome"
    fragment = extra.get("fragment", "") if extra else ""
    params = {
        "encryption": "none", "security": "tls", "type": "ws",
        "host": host, "path": path, "sni": sni, "fp": fp, "alpn": "http/1.1"
    }
    if fragment: params["fragment"] = fragment
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    host_port = addr
    try:
        ipaddress.IPv6Address(addr.strip("[]"))
        host_port = f"[{addr}]:443"
    except:
        host_port = f"{addr}:443"
    link = f"vless://{uid}@{host_port}?{query}#{quote(remark)}"
    link_cache[cache_key] = {"link": link, "expires": time.time() + CACHE_TTL}
    return link

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    u = unit.upper()
    if u == "TB": return int(value * 1024**4)
    if u == "GB": return int(value * 1024**3)
    if u == "MB": return int(value * 1024**2)
    if u == "KB": return int(value * 1024)
    return int(value)

def parse_expires_at(raw: Optional[str]) -> Optional[datetime]:
    if not raw: return None
    try:
        s = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    except Exception:
        return None

def seconds_until_expiry(expires_at_str: Optional[str]) -> Optional[int]:
    exp = parse_expires_at(expires_at_str)
    if exp is None: return None
    return max(0, int((exp - datetime.now(timezone.utc)).total_seconds()))

def _fmt_bytes(b: int) -> str:
    if b >= 1_073_741_824: return f"{b/1_073_741_824:.1f}GB"
    if b >= 1_048_576: return f"{b/1_048_576:.1f}MB"
    return f"{b/1024:.1f}KB"

def _fmt_duration(seconds: int) -> str:
    h, m, s = seconds // 3600, (seconds % 3600) // 60, seconds % 60
    if h > 0: return f"{h}h {m}m"
    if m > 0: return f"{m}m {s}s"
    return f"{s}s"

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded: return forwarded.split(",")[0].strip()
    if websocket.client: return websocket.client.host
    return "unknown"

async def get_country(ip: str) -> tuple:
    """Get country and city from IP via ip-api.com"""
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=country,city,isp,countryCode")
            if resp.status_code == 200:
                data = resp.json()
                return data.get("country", ""), data.get("city", ""), data.get("isp", ""), data.get("countryCode", "")
    except:
        pass
    return "", "", "", ""

async def add_notification(title: str, message: str, ntype: str = "info", uid: str = ""):
    notifications.appendleft({
        "id": secrets.token_hex(6),
        "title": title,
        "message": message,
        "type": ntype,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uid": uid,
        "read": False
    })

def log_event(etype: str, message: str, ip: str = "", ua: str = ""):
    error_logs.append({
        "time": datetime.now(timezone.utc).isoformat(),
        "type": etype,
        "error": message or "(no detail)",
        "ip": ip, "ua": ua,
    })

async def audit_log(action: str, uid: str = "", username: str = "", ip: str = "", details: str = ""):
    try:
        await db_execute(
            "INSERT INTO audit_logs (timestamp, action, uid, username, ip, details) VALUES (?,?,?,?,?,?)",
            "INSERT INTO audit_logs (timestamp, action, uid, username, ip, details) VALUES ($1,$2,$3,$4,$5,$6)",
            (datetime.now(timezone.utc).isoformat(), action, uid, username, ip, details)
        )
    except Exception:
        pass

# ============================================================
#  USER MANAGEMENT HELPERS
# ============================================================

async def count_connections_for_user(uid: str) -> int:
    async with connections_lock:
        return sum(1 for info in connections.values() if info.get("uuid") == uid)

async def close_connections_for_user(uid: str, reason: str = "user deleted/blocked"):
    async with connections_lock:
        to_close = [(cid, info) for cid, info in connections.items() if info.get("uuid") == uid]
    for cid, _ in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try: await ws.close(code=1000, reason=reason)
            except Exception: pass
        async with connections_lock:
            connections.pop(cid, None)
            connection_sockets.pop(cid, None)
    async with connections_lock:
        link_ip_map.pop(uid, None)

# ============================================================
#  BACKGROUND TASKS
# ============================================================

async def flush_traffic_buffer():
    while True:
        await asyncio.sleep(10)
        try:
            async with traffic_buffer_lock:
                if not traffic_buffer["hourly"] and not traffic_buffer["daily"]:
                    continue
                for hour, bytes_val in traffic_buffer["hourly"].items():
                    await db_execute(
                        "INSERT INTO hourly_traffic (hour, bytes) VALUES (?,?) ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?",
                        "INSERT INTO hourly_traffic (hour, bytes) VALUES ($1,$2) ON CONFLICT (hour) DO UPDATE SET bytes = hourly_traffic.bytes + $2",
                        (hour, bytes_val, bytes_val)
                    )
                for day, bytes_val in traffic_buffer["daily"].items():
                    await db_execute(
                        "INSERT INTO daily_traffic (day, bytes) VALUES (?,?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?",
                        "INSERT INTO daily_traffic (day, bytes) VALUES ($1,$2) ON CONFLICT (day) DO UPDATE SET bytes = daily_traffic.bytes + $2",
                        (day, bytes_val, bytes_val)
                    )
                traffic_buffer["hourly"].clear()
                traffic_buffer["daily"].clear()
        except Exception as e:
            logger.error(f"flush error: {e}")

async def add_traffic_to_buffer(hour: str, day: str, size: int):
    async with traffic_buffer_lock:
        traffic_buffer["hourly"][hour] += size
        traffic_buffer["daily"][day] += size

async def sync_usage_to_db():
    while True:
        await asyncio.sleep(30)
        try:
            async with USERS_LOCK:
                for uid, user in USERS.items():
                    await db_execute(
                        "UPDATE users SET used_bytes = ?, upload_bytes = ?, download_bytes = ? WHERE uid = ?",
                        "UPDATE users SET used_bytes = $1, upload_bytes = $2, download_bytes = $3 WHERE uid = $4",
                        (user["used_bytes"], user.get("upload_bytes", 0), user.get("download_bytes", 0), uid)
                    )
        except Exception as e:
            logger.error(f"sync error: {e}")

async def load_initial_data():
    """Load users, addresses, and settings from DB"""
    # Load users
    rows = await db_fetchall("SELECT * FROM users", "SELECT * FROM users")
    async with USERS_LOCK:
        for r in rows:
            USERS[r["uid"]] = dict(r)
    # Load addresses
    addr_rows = await db_fetchall("SELECT address FROM custom_addresses", "SELECT address FROM custom_addresses")
    async with CUSTOM_ADDRESSES_LOCK:
        CUSTOM_ADDRESSES[:] = [r["address"] for r in addr_rows]
        if not CUSTOM_ADDRESSES:
            CUSTOM_ADDRESSES.append("www.speedtest.net")
    # Create default user if no users
    if not USERS:
        default_uuid = str(uuid_lib.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        default_user = {
            "uid": default_uuid, "username": "Free Server", "password": "",
            "limit_bytes": 0, "used_bytes": 0, "upload_bytes": 0, "download_bytes": 0,
            "max_connections": 0, "created_at": now, "active": 1, "expires_at": None,
            "custom_path": "", "custom_sni": "", "custom_host": "", "custom_fp": "chrome",
            "color": "#39ff14", "flag": "", "fragment": "", "notes": "", "tags": "",
            "speed_limit": 0, "priority": 0, "avatar": "",
            "allowed_ips": "", "blocked_ips": "", "allowed_countries": "",
            "allowed_protocols": "", "custom_dns": "", "reset_cycle": "none",
            "max_devices": 0, "total_connections": 0, "total_sessions": 0
        }
        async with USERS_LOCK:
            USERS[default_uuid] = default_user
        await db_execute(
            "INSERT INTO users (uid, username, limit_bytes, max_connections, created_at, active) VALUES (?,?,?,?,?,1)",
            "INSERT INTO users (uid, username, limit_bytes, max_connections, created_at, active) VALUES ($1,$2,$3,$4,$5,TRUE)",
            (default_uuid, "Free Server", 0, 0, now)
        )
    total_usage = sum(u.get("used_bytes", 0) for u in USERS.values())
    stats["total_bytes"] = total_usage

async def _keepalive_simple_loop():
    global KEEP_ALIVE_INTERVAL, KEEP_ALIVE_ENABLED, KEEP_ALIVE_MODE
    while True:
        await asyncio.sleep(KEEP_ALIVE_INTERVAL)
        if not KEEP_ALIVE_ENABLED or KEEP_ALIVE_MODE != "simple": continue
        domain = get_domain()
        if domain == "localhost": continue
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"https://{domain}/health")
                if resp.status_code == 200:
                    logger.info(f"Keep-alive: {domain}/health OK")
        except: pass

async def _keepalive_advanced_loop():
    global KEEP_ALIVE_INTERVAL, KEEP_ALIVE_ENABLED, KEEP_ALIVE_MODE
    await asyncio.sleep(30)
    while True:
        if not KEEP_ALIVE_ENABLED or KEEP_ALIVE_MODE != "advanced":
            await asyncio.sleep(KEEP_ALIVE_INTERVAL)
            continue
        domain = os.environ.get("DOMAIN", "").strip()
        port = os.environ.get("PORT", "8000")
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,*/*", "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
        }
        target_urls = []
        if domain:
            d = domain if domain.startswith(("http://", "https://")) else f"https://{domain}"
            target_urls.append(f"{d}/login")
        target_urls.append(f"http://127.0.0.1:{port}/login")
        async with httpx.AsyncClient(verify=False, timeout=15.0, headers=headers) as client:
            success = False
            for url in target_urls:
                try:
                    u = url + ("&" if "?" in url else "?") + f"_={secrets.token_hex(4)}"
                    resp = await client.get(u, follow_redirects=True)
                    if resp.status_code == 200:
                        success = True; break
                except: pass
            if not success:
                logger.warning("Keep-alive: all attempts failed")
        await asyncio.sleep(KEEP_ALIVE_INTERVAL)

async def cleanup_idle_connections():
    while True:
        await asyncio.sleep(60)
        now = time.time()
        async with connections_lock:
            idle = [cid for cid, info in connections.items() if now - info.get("last_active", 0) > 300]
        for cid in idle:
            ws = connection_sockets.get(cid)
            if ws:
                try: await ws.close(code=1000, reason="idle timeout")
                except: pass
            async with connections_lock: connections.pop(cid, None)
            connection_sockets.pop(cid, None)

async def auto_disable_expired_users():
    while True:
        await asyncio.sleep(60)
        try:
            row = await db_fetchone("SELECT value FROM settings WHERE key='auto_disable_enabled'",
                                    "SELECT value FROM settings WHERE key='auto_disable_enabled'")
            if row and row["value"] != "1": continue
            now = datetime.now(timezone.utc)
            async with USERS_LOCK:
                for uid, user in USERS.items():
                    if user.get("active") and user.get("expires_at"):
                        exp = parse_expires_at(user["expires_at"])
                        if exp and exp < now:
                            user["active"] = 0
                            await db_execute("UPDATE users SET active = 0 WHERE uid = ?",
                                             "UPDATE users SET active = FALSE WHERE uid = $1", (uid,))
                            log_event("Auto", f"Expired user {user['username']} disabled")
                            await add_notification("User Expired", f"{user['username']} has been auto-disabled", "warning")
        except Exception as e:
            logger.error(f"auto_disable error: {e}")

async def cleanup_link_cache():
    while True:
        await asyncio.sleep(600)
        now = time.time()
        expired = [k for k, v in link_cache.items() if v["expires"] <= now]
        for k in expired: del link_cache[k]

async def telegram_reporter():
    while True:
        interval_hours = 1
        row = await db_fetchone("SELECT value FROM settings WHERE key = 'telegram_interval'",
                                "SELECT value FROM settings WHERE key = 'telegram_interval'")
        if row and row["value"]:
            try: interval_hours = float(row["value"])
            except: pass
        await asyncio.sleep(3600 * interval_hours)
        en_row = await db_fetchone("SELECT value FROM settings WHERE key='telegram_report_enabled'",
                                   "SELECT value FROM settings WHERE key='telegram_report_enabled'")
        if en_row and en_row["value"] != "1": continue
        try:
            token_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_bot_token'",
                                          "SELECT value FROM settings WHERE key = 'tg_bot_token'")
            chat_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_chat_id'",
                                         "SELECT value FROM settings WHERE key = 'tg_chat_id'")
            if token_row and chat_row and token_row["value"] and chat_row["value"]:
                async with connections_lock: conn_count = len(connections)
                msg = (
                    f"📊 Best Panel Stats\n"
                    f"🕒 Uptime: {uptime()}\n"
                    f"🔗 Connections: {conn_count}\n"
                    f"📦 Users: {len(USERS)}\n"
                    f"📡 Traffic: {_fmt_bytes(stats['total_bytes'])}\n"
                    f"📥 Requests: {stats['total_requests']}\n"
                    f"❌ Errors: {stats['total_errors']}"
                )
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.post(
                        f"https://api.telegram.org/bot{token_row['value']}/sendMessage",
                        json={"chat_id": chat_row["value"], "text": msg}
                    )
        except: pass

# ============================================================
#  VLESS TUNNEL
# ============================================================

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("VLESS header too small")
    pos = 1 + 16
    addon_len = first_chunk[pos]
    pos += 1 + addon_len
    if len(first_chunk) < pos + 3:
        raise ValueError("Malformed VLESS header")
    command = first_chunk[pos]; pos += 1
    port = int.from_bytes(first_chunk[pos:pos+2], "big"); pos += 2
    addr_type = first_chunk[pos]; pos += 1
    if addr_type == 1:
        if len(first_chunk) < pos + 4: raise ValueError("Incomplete IPv4")
        address = ".".join(str(b) for b in first_chunk[pos:pos+4]); pos += 4
    elif addr_type == 2:
        if len(first_chunk) < pos + 1: raise ValueError("Missing domain length")
        domain_len = first_chunk[pos]; pos += 1
        if len(first_chunk) < pos + domain_len: raise ValueError("Incomplete domain")
        address = first_chunk[pos:pos+domain_len].decode("utf-8", errors="ignore"); pos += domain_len
    elif addr_type == 3:
        if len(first_chunk) < pos + 16: raise ValueError("Incomplete IPv6")
        addr_bytes = first_chunk[pos:pos+16]; pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"Unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]

async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with USERS_LOCK:
        user = USERS.get(uid)
        if not user or not user["active"]: return False
        if user["limit_bytes"] == 0: return True
        return (user["used_bytes"] + extra_bytes) <= user["limit_bytes"]

async def add_usage(uid: str, n: int, is_upload: bool = True):
    async with USERS_LOCK:
        if uid in USERS:
            user = USERS[uid]
            user["used_bytes"] += n
            if is_upload:
                user["upload_bytes"] = user.get("upload_bytes", 0) + n
            else:
                user["download_bytes"] = user.get("download_bytes", 0) + n
            limit = user["limit_bytes"]
            if limit > 0 and user["used_bytes"] >= limit * 0.9 and (user["used_bytes"] - n) < limit * 0.9:
                log_event("Quota", f"User {user['username']} used 90% of quota")
                await add_notification("Quota Warning", f"{user['username']} has used 90% of traffic", "warning", uid)

async def ws_to_tcp(websocket, writer, conn_id, link_uid):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                log_event("Tunnel", f"Quota exceeded for {link_uid}")
                break
            stats["total_bytes"] += size; stats["upload_bytes"] += size
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
                    connections[conn_id]["upload"] += size
            local_now = datetime.now(timezone.utc) + timedelta(hours=TIMEZONE_OFFSET)
            hour = local_now.strftime("%Y-%m-%d %H:00")
            day = local_now.strftime("%Y-%m-%d")
            await add_traffic_to_buffer(hour, day, size)
            await add_usage(link_uid, size, True)
            try:
                writer.write(data); await writer.drain()
            except Exception: break
    except WebSocketDisconnect: pass
    except Exception as e:
        logger.error(f"ws_to_tcp error: {e}")
    finally:
        try:
            if writer and not writer.is_closing(): writer.write_eof()
        except: pass

async def tcp_to_ws(websocket, reader, conn_id, link_uid):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                log_event("Tunnel", f"Quota exceeded for {link_uid}")
                break
            stats["total_bytes"] += size; stats["download_bytes"] += size
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
                    connections[conn_id]["download"] += size
            local_now = datetime.now(timezone.utc) + timedelta(hours=TIMEZONE_OFFSET)
            hour = local_now.strftime("%Y-%m-%d %H:00")
            day = local_now.strftime("%Y-%m-%d")
            await add_traffic_to_buffer(hour, day, size)
            await add_usage(link_uid, size, False)
            try:
                await websocket.send_bytes((b"\x00\x00" + data) if first else data)
                first = False
            except Exception: break
    except Exception as e:
        logger.error(f"tcp_to_ws error: {e}")

# ============================================================
#  LIFESPAN & APP SETUP
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    global TIMEZONE_OFFSET, KEEP_ALIVE_ENABLED, KEEP_ALIVE_INTERVAL, KEEP_ALIVE_MODE
    if DB_BACKEND == "postgresql":
        await init_pg()
    else:
        await init_db()
    await load_initial_data()

    sk = await db_fetchone("SELECT value FROM settings WHERE key = 'jwt_secret_key'",
                           "SELECT value FROM settings WHERE key = 'jwt_secret_key'")
    if sk:
        CONFIG["secret_key"] = sk["value"]
    else:
        await db_execute("INSERT INTO settings (key, value) VALUES ('jwt_secret_key', ?)",
                         "INSERT INTO settings (key, value) VALUES ('jwt_secret_key', $1)",
                         (CONFIG["secret_key"],))

    hash_row = await db_fetchone("SELECT value FROM settings WHERE key = 'admin_password_hash'",
                                 "SELECT value FROM settings WHERE key = 'admin_password_hash'")
    global ADMIN_PASSWORD_HASH
    if hash_row:
        ADMIN_PASSWORD_HASH = hash_row["value"]
    else:
        ADMIN_PASSWORD_HASH = bcrypt.hashpw(CONFIG["admin_password"].encode(), bcrypt.gensalt()).decode()
        await db_execute("INSERT INTO settings (key, value) VALUES ('admin_password_hash', ?)",
                         "INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1)",
                         (ADMIN_PASSWORD_HASH,))

    log_row = await db_fetchone("SELECT value FROM settings WHERE key='log_enabled'",
                                "SELECT value FROM settings WHERE key='log_enabled'")
    global ENABLE_LOGGING
    ENABLE_LOGGING = (log_row and log_row["value"] == "1") if log_row else True

    tz_row = await db_fetchone("SELECT value FROM settings WHERE key='timezone_offset'",
                                "SELECT value FROM settings WHERE key='timezone_offset'")
    if tz_row and tz_row["value"]:
        try: TIMEZONE_OFFSET = float(tz_row["value"])
        except: TIMEZONE_OFFSET = 0.0

    ke_row = await db_fetchone("SELECT value FROM settings WHERE key='keep_alive_enabled'",
                                "SELECT value FROM settings WHERE key='keep_alive_enabled'")
    if ke_row and ke_row["value"] is not None:
        KEEP_ALIVE_ENABLED = (ke_row["value"] == "1")

    km_row = await db_fetchone("SELECT value FROM settings WHERE key='keep_alive_mode'",
                                "SELECT value FROM settings WHERE key='keep_alive_mode'")
    if km_row and km_row["value"]:
        KEEP_ALIVE_MODE = km_row["value"]

    interval_row = await db_fetchone("SELECT value FROM settings WHERE key='keep_alive_interval'",
                                      "SELECT value FROM settings WHERE key='keep_alive_interval'")
    if interval_row and interval_row["value"]:
        try: KEEP_ALIVE_INTERVAL = max(60, int(interval_row["value"]))
        except: pass

    asyncio.create_task(_keepalive_simple_loop())
    asyncio.create_task(_keepalive_advanced_loop())
    asyncio.create_task(cleanup_idle_connections())
    asyncio.create_task(telegram_reporter())
    asyncio.create_task(flush_traffic_buffer())
    asyncio.create_task(sync_usage_to_db())
    asyncio.create_task(auto_disable_expired_users())
    asyncio.create_task(cleanup_link_cache())
    yield
    if DB_BACKEND == "sqlite" and db_conn:
        await db_conn.close()

app = FastAPI(title="Best Panel", version="2.0.0", lifespan=lifespan, docs_url="/docs", redoc_url="/redoc")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ── Language System Variables ──────────────────────────────
LANG_CSS = '''\n/* RTL / PERSIAN LANGUAGE SUPPORT */\n@import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap');\n[dir="rtl"] { direction: rtl; text-align: right; font-family: 'Vazirmatn', 'Inter', sans-serif; }\n[dir="rtl"] .sidebar { right: 0; left: auto; }\n[dir="rtl"] .main-content { margin-left: 0; margin-right: 260px; }\n[dir="rtl"] .nav-item { flex-direction: row-reverse; }\n[dir="rtl"] .nav-item .nav-icon { margin-right: 0; margin-left: 12px; }\n[dir="rtl"] .stat-card, [dir="rtl"] .page-header,\n[dir="rtl"] .modal-content, [dir="rtl"] .form-group label,\n[dir="rtl"] .table th, [dir="rtl"] .table td,\n[dir="rtl"] .card-title, [dir="rtl"] .chart-title,\n[dir="rtl"] .settings-group { text-align: right; }\n[dir="rtl"] .topbar { flex-direction: row-reverse; }\n[dir="rtl"] .search-box { direction: rtl; }\n[dir="rtl"] .toast { direction: rtl; }\n.lang-btn {\n    background: none; border: 1px solid var(--border);\n    color: var(--text2); padding: 4px 10px; border-radius: 8px;\n    cursor: pointer; font-size: 0.75rem; font-weight: 700;\n    font-family: inherit; transition: all 0.2s; line-height: 1;\n    display: flex; align-items: center; gap: 2px;\n}\n.lang-btn:hover {\n    border-color: var(--primary); color: var(--text);\n    background: var(--primary-dim);\n}\n.lang-btn .lang-active { color: var(--primary); }\n'''

LANG_BTN_HTML = '''<button class="lang-btn" onclick="toggleLanguage()" id="langBtn" data-tooltip="Language" data-i18n-tooltip="language">\n            <span class="lang-active" id="langIndicator">FA</span> / EN\n        </button>'''

LANG_JS = '''\n// LANGUAGE SYSTEM\nconst LANGUAGES = {\n    fa: {\n        nav_dashboard: '\u062F\u0627\u0634\u0628\u0648\u0631\u062F', nav_monitor: '\u0645\u0627\u0646\u06CC\u062A\u0648\u0631',\n        nav_analytics: '\u062A\u062D\u0644\u06CC\u0644', nav_rankings: '\u0631\u062A\u0628\u0647\u200C\u0628\u0646\u062F\u06CC',\n        nav_logs: '\u0644\u0627\u06AF\u200C\u0647\u0627', nav_addresses: '\u0622\u062F\u0631\u0633\u200C\u0647\u0627', nav_settings: '\u062A\u0646\u0638\u06CC\u0645\u0627\u062A',\n        all_users: '\u0647\u0645\u0647 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646', traffic_overview: '\u0646\u0645\u0627\u06CC \u062A\u0631\u0627\u0641\u06CC\u06A9 (\u06F2\u06F4 \u0633\u0627\u0639\u062A)',\n        search_placeholder: '\u062C\u0633\u062A\u062C\u0648\u06CC \u06A9\u0627\u0631\u0628\u0631\u0627\u0646\u060C \u0627\u062A\u0635\u0627\u0644\u0627\u062A...',\n        login_title: '\u0648\u0631\u0648\u062F \u0628\u0647 \u067E\u0646\u0644', login_btn: '\u0648\u0631\u0648\u062F',\n        password: '\u0631\u0645\u0632 \u0639\u0628\u0648\u0631', logout: '\u062E\u0631\u0648\u062C',\n        create_user: '\u0627\u06CC\u062C\u0627\u062F \u06A9\u0627\u0631\u0628\u0631', edit_user: '\u0648\u06CC\u0631\u0627\u06CC\u0634 \u06A9\u0627\u0631\u0628\u0631',\n        delete_user: '\u062D\u0630\u0641 \u06A9\u0627\u0631\u0628\u0631', save: '\u0630\u062E\u06CC\u0631\u0647',\n        cancel: '\u0644\u063A\u0648', close: '\u0628\u0633\u062A\u0646',\n        activate: '\u0641\u0639\u0627\u0644', deactivate: '\u063A\u06CC\u0631\u0641\u0639\u0627\u0644',\n        reset_usage: '\u0628\u0627\u0632\u0646\u0634\u0627\u0646\u06CC \u0645\u0635\u0631\u0641',\n        export_users: '\u062E\u0631\u0648\u062C\u06CC', import_users: '\u0648\u0631\u0648\u062F\u06CC',\n        backup: '\u067E\u0634\u062A\u06CC\u0628\u0627\u0646', restore: '\u0628\u0627\u0632\u06CC\u0627\u0628\u06CC',\n        confirm_delete: '\u0627\u06CC\u0646 \u06A9\u0627\u0631\u0628\u0631 \u062D\u0630\u0641 \u0634\u0648\u062F\u061F',\n        notifications: '\u0627\u0639\u0644\u0627\u0646\u200C\u0647\u0627', no_notifications: '\u0627\u0639\u0644\u0627\u0646\u06CC \u0646\u06CC\u0633\u062A',\n        theme: '\u067E\u0648\u0633\u062A\u0647', language: '\u0632\u0628\u0627\u0646',\n        username: '\u0646\u0627\u0645 \u06A9\u0627\u0631\u0628\u0631\u06CC', uuid: 'UUID', traffic: '\u062A\u0631\u0627\u0641\u06CC\u06A9',\n        status: '\u0648\u0636\u0639\u06CC\u062A', active: '\u0641\u0639\u0627\u0644', disabled: '\u063A\u06CC\u0631\u0641\u0639\u0627\u0644',\n        expired: '\u0645\u0646\u0642\u0636\u06CC', connections: '\u0627\u062A\u0635\u0627\u0644\u0627\u062A',\n        devices: '\u062F\u0633\u062A\u06AF\u0627\u0647\u200C\u0647\u0627',\n        expires: '\u0627\u0646\u0642\u0636\u0627', created: '\u0627\u06CC\u062C\u0627\u062F',\n        edit: '\u0648\u06CC\u0631\u0627\u06CC\u0634', delete: '\u062D\u0630\u0641',\n        clone: '\u06A9\u067E\u06CC', disconnect: '\u0642\u0637\u0639 \u0627\u062A\u0635\u0627\u0644',\n        regenerate_uuid: 'UUID \u062C\u062F\u06CC\u062F',\n        copy_link: '\u06A9\u067E\u06CC \u0644\u06CC\u0646\u06A9', copy_sub: '\u06A9\u067E\u06CC \u0627\u0634\u062A\u0631\u0627\u06A9',\n        settings_title: '\u062A\u0646\u0638\u06CC\u0645\u0627\u062A', general: '\u0639\u0645\u0648\u0645\u06CC',\n        telegram: '\u062A\u0644\u06AF\u0631\u0627\u0645',\n        panel_name: '\u0646\u0627\u0645 \u067E\u0646\u0644', footer: '\u0645\u062A\u0646 \u0641\u0648\u062A\u0631',\n        timezone: '\u0645\u0646\u0637\u0642\u0647 \u0632\u0645\u0627\u0646\u06CC',\n        language_settings: '\u0632\u0628\u0627\u0646', persian: '\u0641\u0627\u0631\u0633\u06CC', english: '\u0627\u0646\u06AF\u0644\u06CC\u0633\u06CC',\n        add_address: '\u0627\u0641\u0632\u0648\u062F\u0646 \u0622\u062F\u0631\u0633', addresses_title: '\u0622\u062F\u0631\u0633\u200C\u0647\u0627',\n        scan_title: '\u0627\u0633\u06A9\u0646\u0631 IP', scan_btn: '\u0627\u0633\u06A9\u0646', scanning: '\u062F\u0631 \u062D\u0627\u0644 \u0627\u0633\u06A9\u0646...',\n        ranking_title: '\u0631\u062A\u0628\u0647\u200C\u0628\u0646\u062F\u06CC', by_traffic: '\u0628\u0631 \u0627\u0633\u0627\u0633 \u062A\u0631\u0627\u0641\u06CC\u06A9',\n        analytics_title: '\u062A\u062D\u0644\u06CC\u0644', daily_traffic: '\u062A\u0631\u0627\u0641\u06CC\u06A9 \u0631\u0648\u0632\u0627\u0646\u0647',\n        logs_title: '\u0644\u0627\u06AF\u200C\u0647\u0627', event_logs: '\u0631\u0648\u06CC\u062F\u0627\u062F\u0647\u0627', login_logs: '\u0648\u0631\u0648\u062F\u0647\u0627',\n        clear_logs: '\u067E\u0627\u06A9 \u06A9\u0631\u062F\u0646',\n        time: '\u0632\u0645\u0627\u0646', action: '\u0639\u0645\u0644\u06CC\u0627\u062A', details: '\u062C\u0632\u0626\u06CC\u0627\u062A',\n        ip: '\u0622\u06CC\u200C\u067E\u06CC', country: '\u06A9\u0634\u0648\u0631', city: '\u0634\u0647\u0631',\n        isp: '\u0627\u0631\u0627\u0626\u0647\u200C\u062F\u0647\u0646\u062F\u0647',\n        device: '\u062F\u0633\u062A\u06AF\u0627\u0647', browser: '\u0645\u0631\u0648\u0631\u06AF\u0631', os: '\u0633\u06CC\u0633\u062A\u0645\u200C\u0639\u0627\u0645\u0644',\n        duration: '\u0645\u062F\u062A', upload: '\u0622\u067E\u0644\u0648\u062F', download: '\u062F\u0627\u0646\u0644\u0648\u062F',\n        success: '\u0645\u0648\u0641\u0642', error: '\u062E\u0637\u0627', warning: '\u0647\u0634\u062F\u0627\u0631', info: '\u0627\u0637\u0644\u0627\u0639',\n        total_users: '\u06A9\u0644 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646', total_traffic: '\u06A9\u0644 \u062A\u0631\u0627\u0641\u06CC\u06A9',\n        today_traffic: '\u062A\u0631\u0627\u0641\u06CC\u06A9 \u0627\u0645\u0631\u0648\u0632', week_traffic: '\u062A\u0631\u0627\u0641\u06CC\u06A9 \u0647\u0641\u062A\u0647',\n        month_traffic: '\u062A\u0631\u0627\u0641\u06CC\u06A9 \u0645\u0627\u0647', uptime: '\u0622\u067E\u062A\u0627\u06CC\u0645',\n        cpu: '\u067E\u0631\u062F\u0627\u0632\u0646\u062F\u0647', memory: '\u062D\u0627\u0641\u0638\u0647', disk: '\u062F\u06CC\u0633\u06A9',\n        filter_all: '\u0647\u0645\u0647', filter_active: '\u0641\u0639\u0627\u0644', filter_disabled: '\u063A\u06CC\u0631\u0641\u0639\u0627\u0644',\n        sort_by: '\u0645\u0631\u062A\u0628\u200C\u0633\u0627\u0632\u06CC', rank: '\u0631\u062A\u0628\u0647', value: '\u0645\u0642\u062F\u0627\u0631',\n        monthly_limit: '\u0645\u062D\u062F\u0648\u062F\u06CC\u062A \u0645\u0627\u0647\u0627\u0646\u0647',\n        footer_text: '\u067E\u0646\u0644 \u0628\u0631\u062A\u0631 v2.0 - \u0645\u062F\u06CC\u0631\u06CC\u062A \u0627\u0634\u062A\u0631\u0627\u06A9 \u062D\u0631\u0641\u0647\u200C\u0627\u06CC',\n        general_settings: '\u062A\u0646\u0638\u06CC\u0645\u0627\u062A \u0639\u0645\u0648\u0645\u06CC',\n        auto_disable: '\u063A\u06CC\u0631\u0641\u0639\u0627\u0644\u200C\u0633\u0627\u0632\u06CC \u062E\u0648\u062F\u06A9\u0627\u0631 \u06A9\u0627\u0631\u0628\u0631\u0627\u0646 \u0645\u0646\u0642\u0636\u06CC',\n        search_users: '\u062C\u0633\u062A\u062C\u0648\u06CC \u06A9\u0627\u0631\u0628\u0631\u0627\u0646...',\n        yes: '\u0628\u0644\u0647', no: '\u062E\u06CC\u0631',\n        change_password: '\u062A\u063A\u06CC\u06CC\u0631 \u0631\u0645\u0632 \u0639\u0628\u0648\u0631',\n        current_password: '\u0631\u0645\u0632 \u0641\u0639\u0644\u06CC', new_password: '\u0631\u0645\u0632 \u062C\u062F\u06CC\u062F',\n        password_changed: '\u0631\u0645\u0632 \u0639\u0628\u0648\u0631 \u062A\u063A\u06CC\u06CC\u0631 \u06A9\u0631\u062F!',\n    },\n    en: {\n        nav_dashboard: 'Dashboard', nav_monitor: 'Monitor',\n        nav_analytics: 'Analytics', nav_rankings: 'Rankings',\n        nav_logs: 'Logs', nav_addresses: 'Addresses', nav_settings: 'Settings',\n        all_users: 'All Users', traffic_overview: 'Traffic Overview (24h)',\n        search_placeholder: 'Search users, connections...',\n        login_title: 'Best Panel Login', login_btn: 'Login',\n        password: 'Password', logout: 'Logout',\n        create_user: 'Create User', edit_user: 'Edit User',\n        delete_user: 'Delete User', save: 'Save',\n        cancel: 'Cancel', close: 'Close',\n        activate: 'Activate', deactivate: 'Deactivate',\n        reset_usage: 'Reset Usage',\n        export_users: 'Export', import_users: 'Import',\n        backup: 'Backup', restore: 'Restore',\n        confirm_delete: 'Delete this user?',\n        notifications: 'Notifications', no_notifications: 'No notifications',\n        theme: 'Theme', language: 'Language',\n        username: 'Username', uuid: 'UUID', traffic: 'Traffic',\n        status: 'Status', active: 'Active', disabled: 'Disabled',\n        expired: 'Expired', connections: 'Connections',\n        devices: 'Devices',\n        expires: 'Expires', created: 'Created',\n        edit: 'Edit', delete: 'Delete',\n        clone: 'Clone', disconnect: 'Disconnect',\n        regenerate_uuid: 'New UUID',\n        copy_link: 'Copy Link', copy_sub: 'Copy Subscription',\n        settings_title: 'Settings', general: 'General',\n        telegram: 'Telegram',\n        panel_name: 'Panel Name', footer: 'Footer Text',\n        timezone: 'Timezone',\n        language_settings: 'Language', persian: 'Persian', english: 'English',\n        add_address: 'Add Address', addresses_title: 'Addresses',\n        scan_title: 'IP Scanner', scan_btn: 'Scan', scanning: 'Scanning...',\n        ranking_title: 'Rankings', by_traffic: 'By Traffic',\n        analytics_title: 'Analytics', daily_traffic: 'Daily Traffic',\n        logs_title: 'Logs', event_logs: 'Events', login_logs: 'Logins',\n        clear_logs: 'Clear Logs',\n        time: 'Time', action: 'Action', details: 'Details',\n        ip: 'IP', country: 'Country', city: 'City',\n        isp: 'ISP',\n        device: 'Device', browser: 'Browser', os: 'OS',\n        duration: 'Duration', upload: 'Upload', download: 'Download',\n        success: 'Success', error: 'Error', warning: 'Warning', info: 'Info',\n        total_users: 'Total Users', total_traffic: 'Total Traffic',\n        today_traffic: "Today's Traffic", week_traffic: 'Weekly Traffic',\n        month_traffic: 'Monthly Traffic', uptime: 'Uptime',\n        cpu: 'CPU', memory: 'Memory', disk: 'Disk',\n        filter_all: 'All', filter_active: 'Active', filter_disabled: 'Disabled',\n        sort_by: 'Sort by', rank: 'Rank', value: 'Value',\n        monthly_limit: 'Monthly Limit',\n        footer_text: 'Best Panel v2.0 - Premium Subscription Management',\n        general_settings: 'General Settings',\n        auto_disable: 'Auto-disable expired users',\n        search_users: 'Search users...',\n        yes: 'Yes', no: 'No',\n        change_password: 'Change Password',\n        current_password: 'Current Password', new_password: 'New Password',\n        password_changed: 'Password changed!',\n    }\n};\n\nlet currentLang = localStorage.getItem('best_panel_lang') || 'fa';\n\nfunction __(key) {\n    return LANGUAGES[currentLang]?.[key] || LANGUAGES['fa']?.[key] || key;\n}\n\nfunction applyLanguage() {\n    document.querySelectorAll('[data-i18n]').forEach(el => {\n        const key = el.getAttribute('data-i18n');\n        el.textContent = __(key);\n    });\n    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {\n        const key = el.getAttribute('data-i18n-placeholder');\n        el.placeholder = __(key);\n    });\n    document.querySelectorAll('[data-i18n-tooltip]').forEach(el => {\n        const key = el.getAttribute('data-i18n-tooltip');\n        el.setAttribute('data-tooltip', __(key));\n    });\n    const isRtl = currentLang === 'fa';\n    document.documentElement.setAttribute('dir', isRtl ? 'rtl' : 'ltr');\n    document.documentElement.setAttribute('lang', currentLang === 'fa' ? 'fa' : 'en');\n    const li = document.getElementById('langIndicator');\n    if (li) li.textContent = currentLang === 'fa' ? 'FA' : 'EN';\n}\n\nfunction toggleLanguage() {\n    currentLang = currentLang === 'en' ? 'fa' : 'en';\n    localStorage.setItem('best_panel_lang', currentLang);\n    applyLanguage();\n}\n\nfunction initLanguage() { applyLanguage(); }\nif (document.readyState === 'loading') {\n    document.addEventListener('DOMContentLoaded', initLanguage);\n} else { initLanguage(); }\n'''

# ── Middleware + Language System Injector ────────────────────
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' https: data:; connect-src 'self' http: https: ws: wss:; frame-ancestors 'none'"
    # Inject language system into HTML responses
    try:
        ctype = response.headers.get("content-type", "")
        if "text/html" in ctype:
            body = getattr(response, 'body', None)
            if body:
                html = body.decode("utf-8", errors="replace")
                # Inject RTL CSS before </style>
                html = html.replace("</style>", LANG_CSS + "\n</style>", 1)
                # Inject language button after theme button + add i18n-tooltip
                old_theme_btn = '<button class="btn btn-ghost" onclick="openThemeSwitcher()" data-tooltip="Theme">🎨</button>'
                new_theme_btn = '<button class="btn btn-ghost" onclick="openThemeSwitcher()" data-i18n-tooltip="theme" data-tooltip="Theme">🎨</button>'
                html = html.replace(old_theme_btn, new_theme_btn + LANG_BTN_HTML, 1)
                # Inject language JS and loading screen fix before </body>
                # Fix: ensure loading screen hides even when checkAuth() silently fails
                loadfix = '<script>setTimeout(function(){var ls=document.getElementById("loadingScreen");if(ls&&!ls.classList.contains("hidden"))ls.classList.add("hidden");},1200)</script>'
                html = html.replace("</body>", '<script>' + LANG_JS + '</script>\n' + loadfix + '\n</body>', 1)
                # Add data-i18n to nav items
                pages = ['dashboard', 'monitor', 'analytics', 'rankings', 'logs', 'addresses', 'settings']
                for p in pages:
                    html = html.replace(f'data-page="{p}"', f'data-page="{p}" data-i18n="nav_{p}"')
                # Add data-i18n to stat titles
                html = html.replace(
                    '<span class="card-title">All Users</span>',
                    '<span class="card-title"><span data-i18n="all_users">All Users</span></span>'
                )
                html = html.replace(
                    '<span class="chart-title">Traffic Overview (24h)</span>',
                    '<span class="chart-title"><span data-i18n="traffic_overview">Traffic Overview (24h)</span></span>'
                )
                # Add data-i18n attributes to notification button
                html = html.replace(
                    'onclick="openNotifications()" id="notifBtn" data-tooltip="Notifications"',
                    'onclick="openNotifications()" id="notifBtn" data-i18n-tooltip="notifications" data-tooltip="Notifications"'
                )
                # Add data-i18n-placeholder to search input
                html = html.replace(
                    'id="searchInput" placeholder="',
                    'id="searchInput" data-i18n-placeholder="search_placeholder" placeholder="'
                )
                # Fix: ensure loading screen always hides after checkAuth (auth or not)
                old_auth_block = '  // Check if already authenticated\n  checkAuth();\n\n  // Create particles on login'
                new_auth_block = '  // Check if already authenticated\n  checkAuth();\n  // Always hide loading screen (auth or not)\n  if (typeof hideLoading === \"function\") setTimeout(hideLoading, 500);\n\n  // Create particles on login'
                html = html.replace(old_auth_block, new_auth_block, 1)
                # Remove the 1200ms fallback (replaced by faster 500ms direct version)
                old_loadfix = '<script>setTimeout(function(){var ls=document.getElementById("loadingScreen");if(ls&&!ls.classList.contains("hidden"))ls.classList.add("hidden");},1200)</script>'
                new_loadfix = ''
                html = html.replace(old_loadfix, new_loadfix, 1)
                # Update the response body in-place to preserve cookies/headers
                response.body = html.encode("utf-8")
                response.headers["content-length"] = str(len(response.body))
    except (AttributeError, RuntimeError):
        pass
    return response

# ============================================================
#  API ROUTES
# ============================================================

# ── Root & Health ──────────────────────────────────────────
@app.api_route("/", methods=["GET", "HEAD"])
async def root():
    return {"service": "Best Panel", "version": "2.0.0", "status": "active", "domain": get_domain()}

@app.get("/health")
async def health():
    async with connections_lock: cnt = len(connections)
    return {"status": "ok", "connections": cnt, "uptime": uptime()}

@app.get("/favicon.ico")
async def favicon():
    return Response(content=b"", media_type="image/x-icon", status_code=204)

@app.get("/api/public-settings")
async def public_settings():
    rows = await db_fetchall("SELECT key, value FROM settings WHERE key IN ('footer_text')",
                             "SELECT key, value FROM settings WHERE key IN ('footer_text')")
    return {r["key"]: r["value"] for r in rows}

# ── Authentication ─────────────────────────────────────────
@app.post("/api/login")
@limiter.limit("5/minute")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    ip = request.client.host
    user_agent = request.headers.get("user-agent", "")
    success = verify_password(password, ADMIN_PASSWORD_HASH)
    asyncio.create_task(_log_login(ip, success, user_agent, "/api/login"))
    if not success:
        log_event("Auth", f"Failed login from {ip}", ip, user_agent)
        raise HTTPException(status_code=401, detail="Invalid password")
    log_event("Auth", f"Panel login from {ip}", ip, user_agent)
    await add_notification("Login", f"New login from {ip}", "info")
    token = create_jwt_token({"sub": "admin"})
    resp = JSONResponse({"ok": True, "token": token})
    secure = get_domain() != "localhost"
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=CONFIG["jwt_expire_minutes"]*60,
                    httponly=True, samesite="lax", secure=secure, path="/")
    return resp

async def _log_login(ip: str, success: bool, ua: str, path: str):
    if not ENABLE_LOGGING: return
    country, city, _, _ = await get_country(ip)
    try:
        await db_execute(
            "INSERT INTO login_logs (timestamp, ip, success, user_agent, path, country, city) VALUES (?,?,?,?,?,?,?)",
            "INSERT INTO login_logs (timestamp, ip, success, user_agent, path, country, city) VALUES ($1,$2,$3,$4,$5,$6,$7)",
            (datetime.now(timezone.utc).isoformat(), ip, 1 if success else 0, ua, path, country, city)
        )
    except Exception as e:
        logger.error(f"log_login error: {e}")

@app.post("/api/logout")
async def api_logout(request: Request):
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(_=Depends(require_auth)):
    return {"authenticated": True}

@app.post("/api/change-password")
@limiter.limit("3/minute")
async def api_change_password(request: Request, _=Depends(require_auth)):
    global ADMIN_PASSWORD_HASH
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if not verify_password(current, ADMIN_PASSWORD_HASH):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not re.search(r'[A-Z]', new) or not re.search(r'[a-z]', new) or not re.search(r'[0-9]', new):
        raise HTTPException(status_code=400, detail="Password must contain uppercase, lowercase, and digit")
    new_hash = bcrypt.hashpw(new.encode(), bcrypt.gensalt()).decode()
    ADMIN_PASSWORD_HASH = new_hash
    await db_execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password_hash', ?)",
        "INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
        (new_hash,)
    )
    log_event("Security", "Admin password changed")
    await audit_log("password_change", uid="admin", ip=request.client.host)
    return {"ok": True}

# ── Dashboard Stats ────────────────────────────────────────
@app.get("/api/stats")
async def get_stats(_=Depends(require_auth)):
    global TIMEZONE_OFFSET
    async with connections_lock: conn_count = len(connections)
    async with USERS_LOCK:
        total_users = len(USERS)
        active_users = sum(1 for u in USERS.values() if u["active"])
        disabled_users = sum(1 for u in USERS.values() if not u["active"])
        now_utc = datetime.now(timezone.utc)
        expired_users = sum(1 for u in USERS.values() if u.get("expires_at") and parse_expires_at(u["expires_at"]) and parse_expires_at(u["expires_at"]) < now_utc)
    cpu = None
    try:
        cpu = await asyncio.to_thread(psutil.cpu_percent, 0.1)
        if cpu == 0.0:
            try:
                with open('/proc/loadavg', 'r') as f:
                    cpu = float(f.readline().split()[0]) * 10
            except: cpu = None
    except:
        try:
            with open('/proc/loadavg', 'r') as f:
                cpu = float(f.readline().split()[0]) * 10
        except: pass
    mem_percent = 0
    try: mem_percent = psutil.virtual_memory().percent
    except: pass
    disk_percent = 0; disk_free = 0.0; disk_total = 0.0
    try:
        disk = psutil.disk_usage("/")
        disk_percent = disk.percent
        disk_free = round(disk.free / (1024**3), 1)
        disk_total = round(disk.total / (1024**3), 1)
    except: pass
    now = datetime.now(timezone.utc) + timedelta(hours=TIMEZONE_OFFSET)
    today_str = now.strftime("%Y-%m-%d")
    week_start = (now - timedelta(days=now.weekday())).strftime("%Y-%m-%d")
    month_start = now.strftime("%Y-%m") + "-01"
    # Today's traffic
    today_row = await db_fetchone("SELECT bytes FROM daily_traffic WHERE day = ?",
                                   "SELECT bytes FROM daily_traffic WHERE day = $1", (today_str,))
    today_bytes = today_row["bytes"] if today_row else 0
    # Weekly traffic
    week_rows = await db_fetchall("SELECT SUM(bytes) as total FROM daily_traffic WHERE day >= ?",
                                   "SELECT SUM(bytes) as total FROM daily_traffic WHERE day >= $1", (week_start,))
    week_bytes = week_rows[0]["total"] if week_rows and week_rows[0]["total"] else 0
    # Monthly traffic
    month_rows = await db_fetchall("SELECT SUM(bytes) as total FROM daily_traffic WHERE day >= ?",
                                    "SELECT SUM(bytes) as total FROM daily_traffic WHERE day >= $1", (month_start,))
    month_bytes = month_rows[0]["total"] if month_rows and month_rows[0]["total"] else 0
    # Hourly data
    hourly_rows = await db_fetchall("SELECT hour, bytes FROM hourly_traffic WHERE hour LIKE ? ORDER BY hour ASC",
                                     "SELECT hour, bytes FROM hourly_traffic WHERE hour LIKE $1 ORDER BY hour ASC",
                                     (today_str + '%',))
    hourly_dict = {f"{h:02d}:00": 0 for h in range(24)}
    for r in hourly_rows:
        hour_part = r["hour"][-5:] if len(r["hour"]) >= 5 else r["hour"]
        if hour_part in hourly_dict:
            hourly_dict[hour_part] = r["bytes"]
    async with traffic_buffer_lock:
        for h_key, b_val in traffic_buffer["hourly"].items():
            hour_part = h_key[-5:] if len(h_key) >= 5 else h_key
            if hour_part in hourly_dict:
                hourly_dict[hour_part] += b_val
    sorted_hours = [f"{h:02d}:00" for h in range(24)]
    hourly_data = {h: hourly_dict[h] for h in sorted_hours}
    # Daily traffic for the week
    daily_rows = await db_fetchall(
        "SELECT day, bytes FROM daily_traffic WHERE day >= ? ORDER BY day ASC",
        "SELECT day, bytes FROM daily_traffic WHERE day >= $1 ORDER BY day ASC",
        (week_start,)
    )
    daily_traffic = {r["day"]: r["bytes"] for r in daily_rows}
    # Monthly limit
    monthly_limit = 0
    limit_row = await db_fetchone("SELECT value FROM settings WHERE key='monthly_limit_gb'",
                                   "SELECT value FROM settings WHERE key='monthly_limit_gb'")
    if limit_row and limit_row["value"]:
        try: monthly_limit = float(limit_row["value"]) * 1024**3
        except: pass
    # Railway health check
    railway_health = "unknown"
    try:
        domain = get_domain()
        if domain != "localhost":
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(f"https://{domain}/health")
                railway_health = "healthy" if r.status_code == 200 else "degraded"
    except:
        railway_health = "offline"
    return {
        "active_connections": conn_count,
        "total_traffic": stats["total_bytes"],
        "total_traffic_fmt": _fmt_bytes(stats["total_bytes"]),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "users_count": total_users,
        "active_users": active_users,
        "disabled_users": disabled_users,
        "expired_users": expired_users,
        "domain": get_domain(),
        "cpu_percent": cpu,
        "memory_percent": mem_percent,
        "disk_percent": disk_percent,
        "disk_free_gb": disk_free,
        "disk_total_gb": disk_total,
        "today_traffic": today_bytes,
        "today_traffic_fmt": _fmt_bytes(today_bytes),
        "week_traffic": week_bytes,
        "week_traffic_fmt": _fmt_bytes(week_bytes),
        "month_traffic": month_bytes,
        "month_traffic_fmt": _fmt_bytes(month_bytes),
        "monthly_limit_bytes": int(monthly_limit),
        "hourly_traffic": hourly_data,
        "hourly_labels": sorted_hours,
        "daily_traffic": daily_traffic,
        "upload_bytes": stats["upload_bytes"],
        "download_bytes": stats["download_bytes"],
        "railway_health": railway_health,
    }

# ── Users CRUD ─────────────────────────────────────────────
@app.post("/api/users")
@limiter.limit("20/minute")
async def create_user(request: Request, _=Depends(require_auth)):
    body = await request.json()
    username = (body.get("username") or "").strip()[:60]
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")
    uuid_input = (body.get("uuid") or "").strip()
    if uuid_input:
        try: uuid_lib.UUID(uuid_input)
        except ValueError: raise HTTPException(status_code=400, detail="Invalid UUID")
        uid = uuid_input
    else:
        uid = str(uuid_lib.uuid4())
    async with USERS_LOCK:
        if uid in USERS:
            raise HTTPException(status_code=400, detail="User with this UUID already exists")
        for u in USERS.values():
            if u["username"].lower() == username.lower():
                raise HTTPException(status_code=400, detail="Username already exists")
    password = body.get("password", "")
    limit_val = float(body.get("limit_value", body.get("limit_bytes", 0)) or 0)
    limit_unit = body.get("limit_unit", "GB")
    limit_bytes = 0 if limit_val <= 0 else parse_size_to_bytes(limit_val, limit_unit) if limit_val else 0
    max_conn = int(body.get("max_connections", 0))
    if max_conn < 0: max_conn = 0
    max_devices = int(body.get("max_devices", 0))
    if max_devices < 0: max_devices = 0
    days_valid = body.get("days_valid", body.get("expire_days", 0))
    expires_at = None
    expire_date = body.get("expire_date", body.get("expires_at", ""))
    if expire_date:
        try:
            dt = datetime.fromisoformat(expire_date.replace("Z", "+00:00"))
            expires_at = dt.isoformat()
        except: pass
    try:
        days_valid = int(days_valid)
        if days_valid > 0 and not expires_at:
            expires_at = (datetime.now(timezone.utc) + timedelta(days=days_valid)).isoformat()
    except (ValueError, TypeError): pass
    now = datetime.now(timezone.utc).isoformat()
    speed_limit = int(body.get("speed_limit", 0))
    priority = int(body.get("priority", 0))
    tags = str(body.get("tags", ""))
    notes = str(body.get("notes", ""))
    avatar = str(body.get("avatar", ""))
    allowed_ips = str(body.get("allowed_ips", ""))
    blocked_ips = str(body.get("blocked_ips", ""))
    allowed_countries = str(body.get("allowed_countries", ""))
    allowed_protocols = str(body.get("allowed_protocols", ""))
    custom_dns = str(body.get("custom_dns", ""))
    reset_cycle = str(body.get("reset_cycle", "none"))
    flag = str(body.get("flag", ""))[:2]
    if flag and re.match(r'^[a-zA-Z]{2}$', flag): flag = flag.upper()
    else: flag = ""
    color = str(body.get("color", "#39ff14"))
    fragment = str(body.get("fragment", ""))[:50]
    custom_path = str(body.get("custom_path", ""))
    custom_sni = str(body.get("custom_sni", ""))
    custom_host = str(body.get("custom_host", ""))
    custom_fp = str(body.get("custom_fp", "chrome"))
    user_data = {
        "uid": uid, "username": username, "password": password,
        "limit_bytes": limit_bytes, "used_bytes": 0, "upload_bytes": 0, "download_bytes": 0,
        "max_connections": max_conn, "created_at": now, "active": 1, "expires_at": expires_at,
        "custom_path": custom_path, "custom_sni": custom_sni, "custom_host": custom_host,
        "custom_fp": custom_fp, "color": color, "flag": flag, "fragment": fragment,
        "notes": notes, "tags": tags, "speed_limit": speed_limit, "priority": priority,
        "avatar": avatar, "allowed_ips": allowed_ips, "blocked_ips": blocked_ips,
        "allowed_countries": allowed_countries, "allowed_protocols": allowed_protocols,
        "custom_dns": custom_dns, "reset_cycle": reset_cycle, "max_devices": max_devices,
        "total_connections": 0, "total_sessions": 0,
    }
    async with USERS_LOCK:
        USERS[uid] = user_data
    await db_execute(
        "INSERT INTO users (uid, username, password, limit_bytes, max_connections, max_devices, created_at, active, expires_at, "
        "custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment, notes, tags, speed_limit, priority, "
        "avatar, allowed_ips, blocked_ips, allowed_countries, allowed_protocols, custom_dns, reset_cycle) "
        "VALUES (?,?,?,?,?,?,?,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        "INSERT INTO users (uid, username, password, limit_bytes, max_connections, max_devices, created_at, active, expires_at, "
        "custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment, notes, tags, speed_limit, priority, "
        "avatar, allowed_ips, blocked_ips, allowed_countries, allowed_protocols, custom_dns, reset_cycle) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,TRUE,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)",
        (uid, username, password, limit_bytes, max_conn, max_devices, now, expires_at,
         custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment,
         notes, tags, speed_limit, priority, avatar, allowed_ips, blocked_ips,
         allowed_countries, allowed_protocols, custom_dns, reset_cycle)
    )
    extra = {"custom_path": custom_path, "custom_sni": custom_sni, "custom_host": custom_host, "custom_fp": custom_fp, "fragment": fragment}
    log_event("User", f"Created user {username} ({uid})")
    await audit_log("create_user", uid, username, request.client.host, f"Created user {username}")
    await add_notification("User Created", f"User {username} created successfully", "success", uid)
    return {
        "uuid": uid, "username": username, "limit_bytes": limit_bytes, "used_bytes": 0,
        "max_connections": max_conn, "max_devices": max_devices, "active": True, "created_at": now,
        "expires_at": expires_at, "color": color, "flag": flag, "notes": notes, "tags": tags,
        "vless_link": generate_vless_link(uid, remark=f"Best-{username}", extra=extra),
        "subscription_url": f"https://{get_domain()}/sub/{uid}",
    }

@app.get("/api/users")
async def list_users(_=Depends(require_auth)):
    async with USERS_LOCK:
        items = list(USERS.values())
    items.sort(key=lambda x: x.get("priority", 0), reverse=True)
    result = []
    for row in items:
        uid = row["uid"]
        extra = {"custom_path": row.get("custom_path", ""), "custom_sni": row.get("custom_sni", ""),
                 "custom_host": row.get("custom_host", ""), "custom_fp": row.get("custom_fp", "chrome"),
                 "fragment": row.get("fragment", "")}
        result.append({
            "uuid": uid, "username": row["username"], "limit_bytes": row["limit_bytes"],
            "used_bytes": row["used_bytes"], "upload_bytes": row.get("upload_bytes", 0),
            "download_bytes": row.get("download_bytes", 0),
            "max_connections": row["max_connections"], "max_devices": row.get("max_devices", 0),
            "active": bool(row["active"]), "created_at": row["created_at"],
            "expires_at": row.get("expires_at"),
            "custom_path": extra["custom_path"], "custom_sni": extra["custom_sni"],
            "custom_host": extra["custom_host"], "custom_fp": extra["custom_fp"],
            "color": row.get("color", "#39ff14"), "flag": row.get("flag", ""),
            "notes": row.get("notes", ""), "tags": row.get("tags", ""),
            "speed_limit": row.get("speed_limit", 0), "priority": row.get("priority", 0),
            "avatar": row.get("avatar", ""),
            "current_connections": await count_connections_for_user(uid),
            "vless_link": generate_vless_link(uid, remark=f"Best-{row['username']}", extra=extra),
            "subscription_url": f"https://{get_domain()}/sub/{uid}",
        })
    return {"users": result}

@app.get("/api/export-users")
async def export_users(_=Depends(require_auth)):
    async with USERS_LOCK:
        users = list(USERS.values())
    return JSONResponse(content=users)

@app.post("/api/import-users")
async def import_users(request: Request, _=Depends(require_auth)):
    body = await request.json()
    imported = 0
    if not isinstance(body, list):
        raise HTTPException(status_code=400, detail="Expected a list of users")
    for item in body:
        if not isinstance(item, dict): continue
        uid_input = item.get("uid") or str(uuid_lib.uuid4())
        try: uuid_lib.UUID(uid_input)
        except ValueError: continue
        username = str(item.get("username", f"Imported-{uid_input[:8]}"))[:60]
        async with USERS_LOCK:
            if uid_input in USERS: continue
        limit_bytes = int(item.get("limit_bytes", 0))
        used_bytes = int(item.get("used_bytes", 0))
        max_conn = int(item.get("max_connections", 0))
        max_devices = int(item.get("max_devices", 0))
        created_at = item.get("created_at") or datetime.now(timezone.utc).isoformat()
        active = 1 if item.get("active", True) else 0
        expires_at = item.get("expires_at")
        user_data = {
            "uid": uid_input, "username": username, "password": item.get("password", ""),
            "limit_bytes": limit_bytes, "used_bytes": used_bytes,
            "upload_bytes": int(item.get("upload_bytes", 0)),
            "download_bytes": int(item.get("download_bytes", 0)),
            "max_connections": max_conn, "max_devices": max_devices,
            "created_at": created_at, "active": active, "expires_at": expires_at,
            "custom_path": item.get("custom_path", ""), "custom_sni": item.get("custom_sni", ""),
            "custom_host": item.get("custom_host", ""), "custom_fp": item.get("custom_fp", "chrome"),
            "color": item.get("color", "#39ff14"), "flag": item.get("flag", ""),
            "fragment": item.get("fragment", ""), "notes": item.get("notes", ""),
            "tags": item.get("tags", ""), "speed_limit": int(item.get("speed_limit", 0)),
            "priority": int(item.get("priority", 0)),
            "avatar": item.get("avatar", ""), "allowed_ips": item.get("allowed_ips", ""),
            "blocked_ips": item.get("blocked_ips", ""),
            "allowed_countries": item.get("allowed_countries", ""),
            "allowed_protocols": item.get("allowed_protocols", ""),
            "custom_dns": item.get("custom_dns", ""), "reset_cycle": item.get("reset_cycle", "none"),
            "total_connections": 0, "total_sessions": 0,
        }
        async with USERS_LOCK:
            USERS[uid_input] = user_data
        await db_execute(
            "INSERT INTO users (uid, username, password, limit_bytes, used_bytes, upload_bytes, download_bytes, "
            "max_connections, max_devices, created_at, active, expires_at, custom_path, custom_sni, custom_host, "
            "custom_fp, color, flag, fragment, notes, tags, speed_limit, priority, avatar, "
            "allowed_ips, blocked_ips, allowed_countries, allowed_protocols, custom_dns, reset_cycle) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            "INSERT INTO users (uid, username, password, limit_bytes, used_bytes, upload_bytes, download_bytes, "
            "max_connections, max_devices, created_at, active, expires_at, custom_path, custom_sni, custom_host, "
            "custom_fp, color, flag, fragment, notes, tags, speed_limit, priority, avatar, "
            "allowed_ips, blocked_ips, allowed_countries, allowed_protocols, custom_dns, reset_cycle) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30)",
            (uid_input, username, user_data["password"], limit_bytes, used_bytes,
             user_data["upload_bytes"], user_data["download_bytes"],
             max_conn, max_devices, created_at, active, expires_at,
             user_data["custom_path"], user_data["custom_sni"], user_data["custom_host"],
             user_data["custom_fp"], user_data["color"], user_data["flag"], user_data["fragment"],
             user_data["notes"], user_data["tags"], user_data["speed_limit"], user_data["priority"],
             user_data["avatar"], user_data["allowed_ips"], user_data["blocked_ips"],
             user_data["allowed_countries"], user_data["allowed_protocols"],
             user_data["custom_dns"], user_data["reset_cycle"])
        )
        imported += 1
    return {"ok": True, "imported": imported}

@app.post("/api/users/batch")
async def batch_users(request: Request, _=Depends(require_auth)):
    body = await request.json()
    uids = body.get("uids", [])
    action = body.get("action", "")
    async with USERS_LOCK:
        for uid in uids:
            user = USERS.get(uid)
            if not user: continue
            if action == "activate":
                user["active"] = 1
                await db_execute("UPDATE users SET active=1 WHERE uid=?", "UPDATE users SET active=TRUE WHERE uid=$1", (uid,))
            elif action == "deactivate":
                user["active"] = 0
                await db_execute("UPDATE users SET active=0 WHERE uid=?", "UPDATE users SET active=FALSE WHERE uid=$1", (uid,))
                await close_connections_for_user(uid)
            elif action == "reset_usage":
                user["used_bytes"] = 0
                user["upload_bytes"] = 0
                user["download_bytes"] = 0
                await db_execute("UPDATE users SET used_bytes=0, upload_bytes=0, download_bytes=0 WHERE uid=?",
                                 "UPDATE users SET used_bytes=0, upload_bytes=0, download_bytes=0 WHERE uid=$1", (uid,))
            elif action == "delete":
                if user.get("username") == "Free Server": continue
                await db_execute("DELETE FROM users WHERE uid=?", "DELETE FROM users WHERE uid=$1", (uid,))
                USERS.pop(uid, None)
                await close_connections_for_user(uid)
    return {"ok": True}

@app.get("/api/users/{uid}")
async def get_user(uid: str, _=Depends(require_auth)):
    async with USERS_LOCK:
        user = USERS.get(uid)
        if not user: raise HTTPException(status_code=404, detail="User not found")
        user = dict(user)
    extra = {"custom_path": user.get("custom_path", ""), "custom_sni": user.get("custom_sni", ""),
             "custom_host": user.get("custom_host", ""), "custom_fp": user.get("custom_fp", "chrome"),
             "fragment": user.get("fragment", "")}
    async with connections_lock:
        user_connections = [info for info in connections.values() if info.get("uuid") == uid]
    user["current_connections"] = len(user_connections)
    user["vless_link"] = generate_vless_link(uid, remark=f"Best-{user['username']}", extra=extra)
    user["subscription_url"] = f"https://{get_domain()}/sub/{uid}"
    user["connection_details"] = user_connections
    return user

@app.patch("/api/users/{uid}")
async def update_user(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with USERS_LOCK:
        user = USERS.get(uid)
        if not user: raise HTTPException(status_code=404, detail="User not found")
        if user.get("username") == "Free Server" and "username" in body:
            raise HTTPException(status_code=400, detail="Cannot rename the default user")
    updates = {}
    if "active" in body: updates["active"] = 1 if body["active"] else 0
    if "username" in body:
        new_name = str(body["username"])[:60]
        async with USERS_LOCK:
            for u in USERS.values():
                if u["username"].lower() == new_name.lower() and u["uid"] != uid:
                    raise HTTPException(status_code=400, detail="Username already exists")
        updates["username"] = new_name
    if "password" in body: updates["password"] = str(body["password"])
    if "limit_value" in body or "limit_bytes" in body:
        limit_val = float(body.get("limit_value", body.get("limit_bytes", 0)) or 0)
        unit = body.get("limit_unit", "GB")
        updates["limit_bytes"] = 0 if limit_val <= 0 else parse_size_to_bytes(limit_val, unit)
    if body.get("reset_usage"): updates["used_bytes"] = 0; updates["upload_bytes"] = 0; updates["download_bytes"] = 0
    if "max_connections" in body:
        mc = int(body["max_connections"] or 0)
        updates["max_connections"] = mc if mc >= 0 else 0
    if "max_devices" in body:
        md = int(body["max_devices"] or 0)
        updates["max_devices"] = md if md >= 0 else 0
    if "days_valid" in body or "expire_date" in body or "expires_at" in body:
        expire_date = body.get("expire_date", body.get("expires_at", body.get("days_valid")))
        try:
            dv = int(expire_date)
            if dv > 0: updates["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=dv)).isoformat()
            else: updates["expires_at"] = None
        except (ValueError, TypeError):
            if expire_date:
                try:
                    dt = datetime.fromisoformat(str(expire_date).replace("Z", "+00:00"))
                    updates["expires_at"] = dt.isoformat()
                except: pass
    if "notes" in body: updates["notes"] = str(body["notes"])
    if "tags" in body: updates["tags"] = str(body["tags"])
    if "speed_limit" in body: updates["speed_limit"] = int(body["speed_limit"])
    if "priority" in body: updates["priority"] = int(body["priority"])
    if "avatar" in body: updates["avatar"] = str(body["avatar"])
    if "allowed_ips" in body: updates["allowed_ips"] = str(body["allowed_ips"])
    if "blocked_ips" in body: updates["blocked_ips"] = str(body["blocked_ips"])
    if "allowed_countries" in body: updates["allowed_countries"] = str(body["allowed_countries"])
    if "allowed_protocols" in body: updates["allowed_protocols"] = str(body["allowed_protocols"])
    if "custom_dns" in body: updates["custom_dns"] = str(body["custom_dns"])
    if "reset_cycle" in body: updates["reset_cycle"] = str(body["reset_cycle"])
    if "custom_path" in body: updates["custom_path"] = str(body["custom_path"])[:100]
    if "custom_sni" in body: updates["custom_sni"] = str(body["custom_sni"])[:100]
    if "custom_host" in body: updates["custom_host"] = str(body["custom_host"])[:100]
    if "custom_fp" in body: updates["custom_fp"] = str(body["custom_fp"])[:20]
    if "color" in body: updates["color"] = str(body["color"])[:20]
    if "flag" in body:
        flag_val = str(body["flag"]).strip()[:2]
        flag_val = flag_val.upper() if re.match(r'^[a-zA-Z]{2}$', flag_val) else ""
        updates["flag"] = flag_val
    if "fragment" in body: updates["fragment"] = str(body["fragment"]).strip()[:50]
    if updates:
        async with USERS_LOCK:
            user.update(updates)
        if DB_BACKEND == "sqlite":
            set_str = ", ".join(f"{k} = ?" for k in updates)
            vals = list(updates.values()) + [uid]
            await db_execute(f"UPDATE users SET {set_str} WHERE uid = ?", "", tuple(vals))
        else:
            set_str = ", ".join(f"{k} = ${i+1}" for i, k in enumerate(updates))
            vals = list(updates.values()) + [uid]
            await db_execute("", f"UPDATE users SET {set_str} WHERE uid = ${len(vals)}", tuple(vals))
    log_event("User", f"Updated user {uid}")
    return {"ok": True}

@app.delete("/api/users/{uid}")
async def delete_user(uid: str, request: Request, _=Depends(require_auth)):
    async with USERS_LOCK:
        user = USERS.get(uid)
        if user and user.get("username") == "Free Server":
            raise HTTPException(status_code=400, detail="Default user cannot be deleted")
    await db_execute("DELETE FROM users WHERE uid = ?", "DELETE FROM users WHERE uid = $1", (uid,))
    async with USERS_LOCK:
        USERS.pop(uid, None)
    await close_connections_for_user(uid)
    log_event("User", f"Deleted user {uid}")
    await audit_log("delete_user", uid, ip=request.client.host)
    return {"ok": True}

@app.post("/api/users/{uid}/clone")
async def clone_user(uid: str, request: Request, _=Depends(require_auth)):
    async with USERS_LOCK:
        user = USERS.get(uid)
        if not user: raise HTTPException(status_code=404, detail="User not found")
        user = dict(user)
    new_uid = str(uuid_lib.uuid4())
    user["uid"] = new_uid
    user["username"] = f"{user['username']} (Copy)"
    user["used_bytes"] = 0
    user["upload_bytes"] = 0
    user["download_bytes"] = 0
    user["created_at"] = datetime.now(timezone.utc).isoformat()
    async with USERS_LOCK:
        USERS[new_uid] = user
    await db_execute(
        "INSERT INTO users (uid, username, password, limit_bytes, max_connections, max_devices, created_at, "
        "active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment, "
        "notes, tags, speed_limit, priority, avatar, allowed_ips, blocked_ips, allowed_countries, "
        "allowed_protocols, custom_dns, reset_cycle) "
        "VALUES (?,?,?,?,?,?,?,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        "INSERT INTO users (uid, username, password, limit_bytes, max_connections, max_devices, created_at, "
        "active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment, "
        "notes, tags, speed_limit, priority, avatar, allowed_ips, blocked_ips, allowed_countries, "
        "allowed_protocols, custom_dns, reset_cycle) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,TRUE,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)",
        (new_uid, user["username"], user["password"], user["limit_bytes"],
         user["max_connections"], user.get("max_devices", 0), user["created_at"],
         user["expires_at"], user["custom_path"], user["custom_sni"], user["custom_host"],
         user["custom_fp"], user["color"], user["flag"], user["fragment"],
         user["notes"], user["tags"], user["speed_limit"], user["priority"],
         user["avatar"], user["allowed_ips"], user["blocked_ips"],
         user["allowed_countries"], user["allowed_protocols"],
         user["custom_dns"], user["reset_cycle"])
    )
    return {"ok": True, "new_uuid": new_uid}

@app.post("/api/users/{uid}/new-uuid")
async def regenerate_uuid(uid: str, _=Depends(require_auth)):
    async with USERS_LOCK:
        if uid not in USERS: raise HTTPException(status_code=404, detail="User not found")
        if USERS[uid].get("username") == "Free Server":
            raise HTTPException(status_code=400, detail="Cannot regenerate UUID for default user")
        new_uid = str(uuid_lib.uuid4())
        while new_uid in USERS: new_uid = str(uuid_lib.uuid4())
        user = USERS.pop(uid)
        user["uid"] = new_uid
        USERS[new_uid] = user
        await db_execute("UPDATE users SET uid=? WHERE uid=?", "UPDATE users SET uid=$1 WHERE uid=$2", (new_uid, uid))
        async with connections_lock:
            for cid, info in connections.items():
                if info.get("uuid") == uid:
                    info["uuid"] = new_uid
            if uid in link_ip_map:
                link_ip_map[new_uid] = link_ip_map.pop(uid)
    return {"new_uuid": new_uid}

@app.post("/api/users/{uid}/disconnect")
async def disconnect_user(uid: str, _=Depends(require_auth)):
    await close_connections_for_user(uid)
    return {"ok": True}

# ── Addresses ──────────────────────────────────────────────
@app.get("/api/addresses")
async def list_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        return {"addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses")
@limiter.limit("10/minute")
async def add_address(request: Request, _=Depends(require_auth)):
    body = await request.json()
    addr = (body.get("address") or "").strip()
    if not addr or not validate_address(addr):
        raise HTTPException(status_code=400, detail="Invalid address")
    async with CUSTOM_ADDRESSES_LOCK:
        if addr in CUSTOM_ADDRESSES: raise HTTPException(status_code=400, detail="Already exists")
        CUSTOM_ADDRESSES.append(addr)
    try:
        await db_execute("INSERT INTO custom_addresses (address) VALUES (?)",
                         "INSERT INTO custom_addresses (address) VALUES ($1)", (addr,))
    except ADDRESS_INTEGRITY_ERRORS: pass
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            addr = CUSTOM_ADDRESSES.pop(index)
            await db_execute("DELETE FROM custom_addresses WHERE address = ?",
                             "DELETE FROM custom_addresses WHERE address = $1", (addr,))
        else:
            raise HTTPException(status_code=404, detail="Address not found")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses/batch")
async def add_addresses_batch(request: Request, _=Depends(require_auth)):
    body = await request.json()
    addresses = body.get("addresses", [])
    added = 0
    for addr in addresses:
        if isinstance(addr, str):
            addr = addr.strip()
            if not addr or not validate_address(addr): continue
            async with CUSTOM_ADDRESSES_LOCK:
                if addr not in CUSTOM_ADDRESSES:
                    CUSTOM_ADDRESSES.append(addr)
                    try: await db_execute("INSERT INTO custom_addresses (address) VALUES (?)",
                                          "INSERT INTO custom_addresses (address) VALUES ($1)", (addr,))
                    except: pass
                    added += 1
    return {"ok": True, "added": added}

@app.delete("/api/addresses")
async def delete_all_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        CUSTOM_ADDRESSES[:] = ["www.speedtest.net"]
    await db_execute("DELETE FROM custom_addresses", "DELETE FROM custom_addresses")
    return {"ok": True}

# ── Real-time Connections ──────────────────────────────────
@app.get("/api/connections")
async def get_connections(_=Depends(require_auth)):
    async with connections_lock:
        result = []
        for cid, info in connections.items():
            uid = info.get("uuid", "")
            username = ""
            async with USERS_LOCK:
                if uid in USERS:
                    username = USERS[uid]["username"]
            result.append({
                "id": cid, "uuid": uid, "username": username,
                "ip": info.get("ip", ""), "country": info.get("country", ""),
                "city": info.get("city", ""), "isp": info.get("isp", ""),
                "device": info.get("device", ""), "browser": info.get("browser", ""),
                "os": info.get("os", ""),
                "connected_at": info.get("connected_at", ""),
                "last_active": info.get("last_active", 0),
                "duration": int(time.time() - info.get("last_active", time.time())),
                "bytes": info.get("bytes", 0),
                "upload": info.get("upload", 0), "download": info.get("download", 0),
                "status": info.get("status", "active"),
            })
        return {"connections": result, "total": len(result)}

# ── Settings ───────────────────────────────────────────────
@app.get("/api/settings")
async def get_settings(_=Depends(require_auth)):
    keys = [
        'tg_bot_token', 'tg_chat_id', 'footer_text', 'log_enabled',
        'timezone_offset', 'keep_alive_interval', 'keep_alive_enabled',
        'keep_alive_mode', 'telegram_interval', 'telegram_lang',
        'auto_disable_enabled', 'telegram_report_enabled', 'telegram_notify_enabled',
        'monthly_limit_gb', 'theme', 'language', 'panel_name',
        'max_scan_ips', 'scanner_timeout', 'default_limit_bytes',
        'default_expiry_days', 'default_max_connections',
    ]
    result = {}
    for k in keys:
        row = await db_fetchone("SELECT value FROM settings WHERE key = ?",
                                "SELECT value FROM settings WHERE key = $1", (k,))
        result[k] = row["value"] if row else ""
    return result

@app.post("/api/settings")
async def save_settings(request: Request, _=Depends(require_auth)):
    global ENABLE_LOGGING, TIMEZONE_OFFSET, KEEP_ALIVE_ENABLED, KEEP_ALIVE_INTERVAL, KEEP_ALIVE_MODE
    body = await request.json()
    setting_keys = [
        'tg_bot_token', 'tg_chat_id', 'footer_text', 'log_enabled',
        'timezone_offset', 'keep_alive_interval', 'keep_alive_enabled',
        'keep_alive_mode', 'telegram_interval', 'telegram_lang',
        'auto_disable_enabled', 'telegram_report_enabled', 'telegram_notify_enabled',
        'monthly_limit_gb', 'theme', 'language', 'panel_name',
        'max_scan_ips', 'scanner_timeout', 'default_limit_bytes',
        'default_expiry_days', 'default_max_connections',
    ]
    for k in setting_keys:
        if k in body:
            val = str(body[k]).strip()
            await db_execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2",
                (k, val),
            )
    if 'log_enabled' in body: ENABLE_LOGGING = body['log_enabled'] == '1'
    if 'keep_alive_enabled' in body: KEEP_ALIVE_ENABLED = body['keep_alive_enabled'] == '1'
    if 'keep_alive_mode' in body: KEEP_ALIVE_MODE = body['keep_alive_mode']
    if 'keep_alive_interval' in body:
        try: KEEP_ALIVE_INTERVAL = max(60, int(body['keep_alive_interval']))
        except: pass
    if 'timezone_offset' in body:
        try: TIMEZONE_OFFSET = float(body['timezone_offset'])
        except: pass
    return {"ok": True}

@app.post("/api/settings/reset")
@limiter.limit("3/minute")
async def reset_settings(request: Request, _=Depends(require_auth)):
    PROTECTED_KEYS = {'jwt_secret_key', 'admin_password_hash'}
    all_keys = await db_fetchall("SELECT key FROM settings", "SELECT key FROM settings")
    for row in all_keys:
        k = row["key"]
        if k not in PROTECTED_KEYS:
            await db_execute("DELETE FROM settings WHERE key = ?",
                             "DELETE FROM settings WHERE key = $1", (k,))
    global ENABLE_LOGGING, KEEP_ALIVE_INTERVAL, TIMEZONE_OFFSET, KEEP_ALIVE_ENABLED, KEEP_ALIVE_MODE
    ENABLE_LOGGING = True; KEEP_ALIVE_INTERVAL = 300; TIMEZONE_OFFSET = 0.0
    KEEP_ALIVE_ENABLED = True; KEEP_ALIVE_MODE = "simple"
    return {"ok": True}

# ── Logs ───────────────────────────────────────────────────
@app.get("/api/logs")
async def get_logs(_=Depends(require_auth)):
    return {"logs": list(error_logs)}

@app.get("/api/logs/login")
async def get_login_logs(_=Depends(require_auth)):
    rows = await db_fetchall(
        "SELECT timestamp, ip, success, user_agent, path, country, city FROM login_logs ORDER BY timestamp DESC LIMIT 50",
        "SELECT timestamp, ip, success, user_agent, path, country, city FROM login_logs ORDER BY timestamp DESC LIMIT 50"
    )
    return {"logs": rows}

@app.get("/api/logs/audit")
async def get_audit_logs(_=Depends(require_auth), limit: int = Query(50, le=200)):
    rows = await db_fetchall(
        "SELECT timestamp, action, uid, username, ip, details FROM audit_logs ORDER BY timestamp DESC LIMIT ?",
        "SELECT timestamp, action, uid, username, ip, details FROM audit_logs ORDER BY timestamp DESC LIMIT $1",
        (limit,)
    )
    return {"logs": rows}

@app.get("/api/logs/connections")
async def get_connection_logs(_=Depends(require_auth), limit: int = Query(50, le=200)):
    rows = await db_fetchall(
        "SELECT * FROM connection_logs ORDER BY timestamp DESC LIMIT ?",
        "SELECT * FROM connection_logs ORDER BY timestamp DESC LIMIT $1", (limit,)
    )
    return {"logs": rows}

@app.delete("/api/logs/clear")
async def clear_logs(_=Depends(require_auth)):
    error_logs.clear()
    await db_execute("DELETE FROM login_logs", "DELETE FROM login_logs")
    await db_execute("DELETE FROM audit_logs", "DELETE FROM audit_logs")
    return {"ok": True}

# ── Notifications ──────────────────────────────────────────
@app.get("/api/notifications")
async def get_notifications(_=Depends(require_auth)):
    return {"notifications": list(notifications)}

@app.post("/api/notifications/read/{nid}")
async def mark_notification_read(nid: str, _=Depends(require_auth)):
    for n in notifications:
        if n["id"] == nid:
            n["read"] = True
            break
    return {"ok": True}

@app.post("/api/notifications/read-all")
async def mark_all_read(_=Depends(require_auth)):
    for n in notifications:
        n["read"] = True
    return {"ok": True}

# ── Search ─────────────────────────────────────────────────
@app.get("/api/search")
async def global_search(q: str = Query("", min_length=1), _=Depends(require_auth)):
    results = []
    q_lower = q.lower()
    async with USERS_LOCK:
        for uid, user in USERS.items():
            if (q_lower in user["username"].lower() or q_lower in uid.lower() or
                q_lower in user.get("tags", "").lower() or q_lower in user.get("notes", "").lower()):
                results.append({
                    "type": "user", "uid": uid, "username": user["username"],
                    "active": bool(user["active"]),
                })
    async with connections_lock:
        for cid, info in connections.items():
            if q_lower in info.get("ip", "").lower() or q_lower in info.get("uuid", "").lower():
                results.append({
                    "type": "connection", "id": cid, "ip": info.get("ip", ""),
                    "uuid": info.get("uuid", ""),
                })
    return {"results": results[:50]}

# ── Rankings ───────────────────────────────────────────────
@app.get("/api/rankings")
async def get_rankings(_=Depends(require_auth)):
    async with USERS_LOCK:
        users = list(USERS.values())
    # By traffic
    by_traffic = sorted(users, key=lambda x: x.get("used_bytes", 0), reverse=True)[:100]
    by_upload = sorted(users, key=lambda x: x.get("upload_bytes", 0), reverse=True)[:100]
    by_download = sorted(users, key=lambda x: x.get("download_bytes", 0), reverse=True)[:100]
    async with connections_lock:
        conn_counts = defaultdict(int)
        for info in connections.values():
            conn_counts[info.get("uuid", "")] += 1
    by_sessions = sorted(users, key=lambda x: conn_counts.get(x["uid"], 0), reverse=True)[:100]
    return {
        "by_traffic": [{"rank": i+1, "username": u["username"], "uid": u["uid"], "value": u.get("used_bytes", 0), "value_fmt": _fmt_bytes(u.get("used_bytes", 0))} for i, u in enumerate(by_traffic)],
        "by_upload": [{"rank": i+1, "username": u["username"], "uid": u["uid"], "value": u.get("upload_bytes", 0), "value_fmt": _fmt_bytes(u.get("upload_bytes", 0))} for i, u in enumerate(by_upload)],
        "by_download": [{"rank": i+1, "username": u["username"], "uid": u["uid"], "value": u.get("download_bytes", 0), "value_fmt": _fmt_bytes(u.get("download_bytes", 0))} for i, u in enumerate(by_download)],
        "by_sessions": [{"rank": i+1, "username": u["username"], "uid": u["uid"], "value": conn_counts.get(u["uid"], 0), "value_fmt": str(conn_counts.get(u["uid"], 0))} for i, u in enumerate(by_sessions)],
    }

# ── Backup ─────────────────────────────────────────────────
@app.get("/api/backup")
async def create_backup(_=Depends(require_auth)):
    async with USERS_LOCK:
        users = list(USERS.values())
    async with CUSTOM_ADDRESSES_LOCK:
        addrs = list(CUSTOM_ADDRESSES)
    rows = await db_fetchall("SELECT key, value FROM settings", "SELECT key, value FROM settings")
    settings = {r["key"]: r["value"] for r in rows}
    backup = {
        "version": "2.0.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "users": users, "addresses": addrs, "settings": settings,
    }
    return backup

@app.post("/api/restore")
async def restore_backup(request: Request, _=Depends(require_auth)):
    MAX_RESTORE_SIZE = 10 * 1024 * 1024
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_RESTORE_SIZE:
        raise HTTPException(status_code=413, detail="Backup file too large")
    body = await request.json()
    if "settings" in body:
        for k, v in body["settings"].items():
            if k in ('jwt_secret_key', 'admin_password_hash'): continue
            await db_execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                             "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2",
                             (k, str(v)))
    if "addresses" in body:
        await db_execute("DELETE FROM custom_addresses", "DELETE FROM custom_addresses")
        async with CUSTOM_ADDRESSES_LOCK:
            CUSTOM_ADDRESSES[:] = []
            for a in body["addresses"]:
                addr = str(a).strip()
                if addr and validate_address(addr):
                    CUSTOM_ADDRESSES.append(addr)
                    try: await db_execute("INSERT INTO custom_addresses (address) VALUES (?)",
                                          "INSERT INTO custom_addresses (address) VALUES ($1)", (addr,))
                    except: pass
    if "users" in body:
        await db_execute("DELETE FROM users", "DELETE FROM users")
        async with USERS_LOCK: USERS.clear()
        for user in body["users"]:
            uid = user.get("uid") or str(uuid_lib.uuid4())
            username = str(user.get("username", "Restored"))[:60]
            limit_bytes = int(user.get("limit_bytes", 0))
            used_bytes = int(user.get("used_bytes", 0))
            upload_bytes = int(user.get("upload_bytes", 0))
            download_bytes = int(user.get("download_bytes", 0))
            max_conn = int(user.get("max_connections", 0))
            max_devices = int(user.get("max_devices", 0))
            created_at = user.get("created_at", datetime.now(timezone.utc).isoformat())
            active = 1 if user.get("active", True) else 0
            expires_at = user.get("expires_at")
            user_data = {
                "uid": uid, "username": username, "password": user.get("password", ""),
                "limit_bytes": limit_bytes, "used_bytes": used_bytes,
                "upload_bytes": upload_bytes, "download_bytes": download_bytes,
                "max_connections": max_conn, "max_devices": max_devices,
                "created_at": created_at, "active": active, "expires_at": expires_at,
                "custom_path": user.get("custom_path", ""), "custom_sni": user.get("custom_sni", ""),
                "custom_host": user.get("custom_host", ""), "custom_fp": user.get("custom_fp", "chrome"),
                "color": user.get("color", "#39ff14"), "flag": user.get("flag", ""),
                "fragment": user.get("fragment", ""), "notes": user.get("notes", ""),
                "tags": user.get("tags", ""), "speed_limit": int(user.get("speed_limit", 0)),
                "priority": int(user.get("priority", 0)), "avatar": user.get("avatar", ""),
                "allowed_ips": user.get("allowed_ips", ""), "blocked_ips": user.get("blocked_ips", ""),
                "allowed_countries": user.get("allowed_countries", ""),
                "allowed_protocols": user.get("allowed_protocols", ""),
                "custom_dns": user.get("custom_dns", ""), "reset_cycle": user.get("reset_cycle", "none"),
                "total_connections": 0, "total_sessions": 0,
            }
            async with USERS_LOCK: USERS[uid] = user_data
            await db_execute(
                "INSERT INTO users (uid, username, password, limit_bytes, used_bytes, upload_bytes, download_bytes, "
                "max_connections, max_devices, created_at, active, expires_at, custom_path, custom_sni, custom_host, "
                "custom_fp, color, flag, fragment, notes, tags, speed_limit, priority, avatar, "
                "allowed_ips, blocked_ips, allowed_countries, allowed_protocols, custom_dns, reset_cycle) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "INSERT INTO users (uid, username, password, limit_bytes, used_bytes, upload_bytes, download_bytes, "
                "max_connections, max_devices, created_at, active, expires_at, custom_path, custom_sni, custom_host, "
                "custom_fp, color, flag, fragment, notes, tags, speed_limit, priority, avatar, "
                "allowed_ips, blocked_ips, allowed_countries, allowed_protocols, custom_dns, reset_cycle) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30)",
                (uid, username, user_data["password"], limit_bytes, used_bytes, upload_bytes, download_bytes,
                 max_conn, max_devices, created_at, active, expires_at,
                 user_data["custom_path"], user_data["custom_sni"], user_data["custom_host"],
                 user_data["custom_fp"], user_data["color"], user_data["flag"], user_data["fragment"],
                 user_data["notes"], user_data["tags"], user_data["speed_limit"], user_data["priority"],
                 user_data["avatar"], user_data["allowed_ips"], user_data["blocked_ips"],
                 user_data["allowed_countries"], user_data["allowed_protocols"],
                 user_data["custom_dns"], user_data["reset_cycle"])
            )
    return {"ok": True}

# ── Analytics ──────────────────────────────────────────────
@app.get("/api/analytics")
async def get_analytics(_=Depends(require_auth), days: int = Query(30, le=365)):
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days)
    start_str = start_date.strftime("%Y-%m-%d")
    daily_rows = await db_fetchall(
        "SELECT day, bytes FROM daily_traffic WHERE day >= ? ORDER BY day ASC",
        "SELECT day, bytes FROM daily_traffic WHERE day >= $1 ORDER BY day ASC",
        (start_str,)
    )
    traffic_data = {r["day"]: r["bytes"] for r in daily_rows}
    # User growth
    async with USERS_LOCK:
        total_users = len(USERS)
        active_users = sum(1 for u in USERS.values() if u["active"])
        expired = sum(1 for u in USERS.values() if u.get("expires_at") and parse_expires_at(u["expires_at"]) and parse_expires_at(u["expires_at"]) < end_date)
    # Countries
    countries = defaultdict(int)
    async with connections_lock:
        for info in connections.values():
            c = info.get("country", "Unknown")
            countries[c] += 1
    async with USERS_LOCK:
        top_traffic = sorted(USERS.values(), key=lambda x: x.get("used_bytes", 0), reverse=True)[:10]
    return {
        "daily_traffic": traffic_data,
        "total_users": total_users,
        "active_users": active_users,
        "expired_users": expired,
        "countries": dict(countries),
        "top_users": [{"username": u["username"], "used_bytes": u.get("used_bytes", 0), "used_fmt": _fmt_bytes(u.get("used_bytes", 0))} for u in top_traffic],
    }

# ── WebSocket: Real-time Monitor ───────────────────────────
@app.websocket("/ws/monitor")
async def monitor_ws(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            async with connections_lock:
                data = {
                    "type": "connections",
                    "connections": len(connections),
                    "users": len(USERS),
                    "total_traffic": stats["total_bytes"],
                    "total_traffic_fmt": _fmt_bytes(stats["total_bytes"]),
                    "cpu": None,
                    "memory": None,
                }
                try:
                    data["cpu"] = psutil.cpu_percent(0.1)
                    data["memory"] = psutil.virtual_memory().percent
                except: pass
                conn_list = []
                for cid, info in connections.items():
                    uid = info.get("uuid", "")
                    username = ""
                    async with USERS_LOCK:
                        if uid in USERS: username = USERS[uid]["username"]
                    conn_list.append({
                        "id": cid, "uuid": uid, "username": username,
                        "ip": info.get("ip", ""), "country": info.get("country", ""),
                        "city": info.get("city", ""), "isp": info.get("isp", ""),
                        "device": info.get("device", ""), "browser": info.get("browser", ""),
                        "os": info.get("os", ""),
                        "connected_at": info.get("connected_at", ""),
                        "duration": int(time.time() - info.get("last_active", time.time())),
                        "bytes": info.get("bytes", 0),
                        "upload": info.get("upload", 0), "download": info.get("download", 0),
                        "status": info.get("status", "active"),
                    })
                data["connection_list"] = conn_list
            await websocket.send_json(data)
            await asyncio.sleep(3)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass

# ── WebSocket: Scanner ─────────────────────────────────────
@app.websocket("/ws/scanner")
async def scanner_ws(websocket: WebSocket):
    await websocket.accept()
    tasks = []
    try:
        data = await websocket.receive_json()
        items = data.get("ips", [])
        if not isinstance(items, list) or len(items) == 0:
            await websocket.close(); return
        max_ips = 256
        max_row = await db_fetchone("SELECT value FROM settings WHERE key='max_scan_ips'",
                                    "SELECT value FROM settings WHERE key='max_scan_ips'")
        if max_row and max_row["value"]:
            try: max_ips = int(max_row["value"])
            except: pass
        if len(items) > max_ips:
            await websocket.send_json({"done": True, "error": f"Max {max_ips} IPs"})
            return
        timeout_str = "4"
        row = await db_fetchone("SELECT value FROM settings WHERE key='scanner_timeout'",
                                "SELECT value FROM settings WHERE key='scanner_timeout'")
        if row and row["value"]: timeout_str = row["value"]
        try: timeout = float(timeout_str)
        except: timeout = 4
        sem = asyncio.Semaphore(20)

        async def scan_one(item):
            async with sem:
                ip_str = str(item).strip()
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                        await websocket.send_json({"ip": ip_str, "ok": False, "latency": None})
                        return
                except ValueError: pass
                try:
                    start = time.time()
                    try:
                        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                            resp = await client.get(f"https://{ip_str}:443", follow_redirects=True)
                        latency = round((time.time() - start) * 1000)
                        await websocket.send_json({"ip": ip_str, "ok": True, "latency": latency})
                    except:
                        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip_str, 443), timeout=timeout)
                        latency = round((time.time() - start) * 1000)
                        writer.close()
                        await websocket.send_json({"ip": ip_str, "ok": True, "latency": latency})
                except:
                    await websocket.send_json({"ip": ip_str, "ok": False, "latency": None})

        tasks = [asyncio.create_task(scan_one(item)) for item in items]
        await asyncio.gather(*tasks)
        await websocket.send_json({"done": True})
    except WebSocketDisconnect: pass
    except Exception as e:
        logger.error(f"Scanner error: {e}")
    finally:
        for t in tasks:
            if not t.done(): t.cancel()
        try: await websocket.close()
        except: pass

# ── WebSocket: VLESS Tunnel ────────────────────────────────
@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await websocket.accept()
    logger.info(f"WS tunnel accepted: {uuid}")
    writer = None; conn_id = None; client_ip = get_client_ip(websocket)
    try:
        async with USERS_LOCK:
            user = USERS.get(uuid)
            if not user or not user["active"]:
                await websocket.close(code=1008, reason="not found or disabled")
                log_event("Tunnel", f"Inactive user {uuid}", ip=client_ip)
                return
            max_conn = user.get("max_connections", 0)
        expires = parse_expires_at(user.get("expires_at"))
        if expires and expires < datetime.now(timezone.utc):
            await websocket.close(code=1008, reason="expired")
            log_event("Tunnel", f"Expired user {uuid}", ip=client_ip)
            return
        # Check concurrent connection limit
        if max_conn > 0:
            current_count = await count_connections_for_user(uuid)
            if current_count >= max_conn:
                await websocket.close(code=1008, reason="connection limit reached")
                log_event("Limit", f"Connection limit reached for {uuid} (max: {max_conn})", ip=client_ip)
                await add_notification("Connection Rejected", f"User {user['username']} exceeded connection limit", "warning", uuid)
                return
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect": return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk: return
        try: command, address, port, initial_payload = await parse_vless_header(first_chunk)
        except ValueError as e:
            logger.warning(f"Invalid VLESS header from {client_ip}: {e}")
            await websocket.close(code=1008, reason="invalid header")
            return
        conn_id = secrets.token_urlsafe(8)
        now_time = time.time()
        async with connections_lock:
            connections[conn_id] = {
                "uuid": uuid, "ip": client_ip, "country": "", "city": "", "isp": "",
                "device": "", "browser": "", "os": "",
                "connected_at": datetime.now(timezone.utc).isoformat(),
                "bytes": 0, "upload": 0, "download": 0,
                "last_active": now_time, "status": "active",
            }
            connection_sockets[conn_id] = websocket
            link_ip_map[uuid].add(client_ip)
        stats["total_requests"] += 1
        # Get geo info async
        asyncio.create_task(_update_conn_geo(conn_id, client_ip))
        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size; stats["upload_bytes"] += p_size
            await add_usage(uuid, p_size, True)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        sock = writer.get_extra_info('socket')
        if sock: sock.setsockopt(6, 1, 1)
        if initial_payload:
            try: writer.write(initial_payload); await writer.drain()
            except: pass
        up_task = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        down_task = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({up_task, down_task}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel(); await t
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": f"Tunnel {uuid}: {exc}", "type": "WebSocket"})
    finally:
        if writer:
            try: writer.close(); await writer.wait_closed()
            except: pass
        if conn_id:
            async with connections_lock:
                info = connections.pop(conn_id, None)
                connection_sockets.pop(conn_id, None)
                if info:
                    uid = info.get("uuid"); ip = info.get("ip")
                    if uid and ip and uid in link_ip_map:
                        link_ip_map[uid].discard(ip)
                        if not link_ip_map[uid]: link_ip_map.pop(uid, None)

async def _update_conn_geo(conn_id: str, ip: str):
    """Update connection geo info in background"""
    country, city, isp, cc = await get_country(ip)
    async with connections_lock:
        if conn_id in connections:
            connections[conn_id]["country"] = country
            connections[conn_id]["city"] = city
            connections[conn_id]["isp"] = isp
            connections[conn_id]["country_code"] = cc

#
# ═══════════════════════════════════════════════════════════
#  FRONTEND — EMBEDDED HTML/CSS/JS
#  (The entire premium UI will be served here)
# ═══════════════════════════════════════════════════════════
#  For Railway compatibility, everything is in this single file.
#  The frontend is a complete SPA with 7 themes, glassmorphism,
#  animations, and all premium features.
# ═══════════════════════════════════════════════════════════
#

FRONTEND_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Best Panel</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
/* ═══════════════════════════════════════════════════════════════
   THEME SYSTEM — 7 Complete Themes
   ═══════════════════════════════════════════════════════════════ */

/* ── Midnight (default) ── */
[data-theme="midnight"] {
  --primary: #6366f1; --primary-light: #818cf8; --primary-dark: #4f46e5;
  --primary-glow: rgba(99,102,241,0.35); --primary-dim: rgba(99,102,241,0.12);
  --bg: #0b0d15; --bg2: #11131e; --bg3: #181b2a;
  --surface: rgba(17,19,30,0.75); --surface2: rgba(24,27,42,0.85); --surface3: rgba(30,34,54,0.9);
  --border: rgba(99,102,241,0.10); --border2: rgba(99,102,241,0.22);
  --text: #e2e4f0; --text2: #9498b8; --text3: #5c6080;
  --success: #34d399; --warning: #fbbf24; --danger: #f87171;
  --chart-grid: rgba(99,102,241,0.08); --chart-line: #6366f1;
  --header-bg: rgba(11,13,21,0.8);
  --gradient-1: linear-gradient(135deg, #6366f1, #8b5cf6);
  --gradient-2: linear-gradient(135deg, #4f46e5, #7c3aed);
  --gradient-bg: radial-gradient(ellipse at top, rgba(99,102,241,0.08), transparent 60%),
                  radial-gradient(ellipse at bottom, rgba(139,92,246,0.05), transparent 60%);
  --shadow: 0 4px 20px rgba(0,0,0,0.3);
  --shadow-lg: 0 8px 40px rgba(0,0,0,0.4);
  --glow: 0 0 20px rgba(99,102,241,0.15);
}

/* ── Cyberpunk ── */
[data-theme="cyberpunk"] {
  --primary: #f706cf; --primary-light: #ff3ae0; --primary-dark: #d005b0;
  --primary-glow: rgba(247,6,207,0.4); --primary-dim: rgba(247,6,207,0.12);
  --bg: #0a0010; --bg2: #120019; --bg3: #1c0028;
  --surface: rgba(18,0,25,0.75); --surface2: rgba(28,0,40,0.85); --surface3: rgba(40,0,55,0.9);
  --border: rgba(247,6,207,0.12); --border2: rgba(247,6,207,0.25);
  --text: #f0e0ff; --text2: #c0a0d0; --text3: #806090;
  --success: #00ff88; --warning: #ffcc00; --danger: #ff0044;
  --chart-grid: rgba(247,6,207,0.1); --chart-line: #f706cf;
  --header-bg: rgba(10,0,16,0.85);
  --gradient-1: linear-gradient(135deg, #f706cf, #ff6b35);
  --gradient-2: linear-gradient(135deg, #d005b0, #ff4400);
  --gradient-bg: radial-gradient(ellipse at top, rgba(247,6,207,0.12), transparent 60%),
                  radial-gradient(ellipse at bottom, rgba(255,107,53,0.08), transparent 60%);
  --shadow: 0 4px 20px rgba(247,6,207,0.2);
  --shadow-lg: 0 8px 40px rgba(247,6,207,0.3);
  --glow: 0 0 25px rgba(247,6,207,0.25);
}

/* ── Ocean ── */
[data-theme="ocean"] {
  --primary: #06b6d4; --primary-light: #22d3ee; --primary-dark: #0891b2;
  --primary-glow: rgba(6,182,212,0.3); --primary-dim: rgba(6,182,212,0.12);
  --bg: #042030; --bg2: #062a3d; --bg3: #0a3450;
  --surface: rgba(6,42,61,0.75); --surface2: rgba(10,52,80,0.85); --surface3: rgba(14,65,95,0.9);
  --border: rgba(6,182,212,0.10); --border2: rgba(6,182,212,0.22);
  --text: #d0ecf5; --text2: #80b8cc; --text3: #4a8096;
  --success: #2dd4bf; --warning: #fbbf24; --danger: #f87171;
  --chart-grid: rgba(6,182,212,0.08); --chart-line: #06b6d4;
  --header-bg: rgba(4,32,48,0.85);
  --gradient-1: linear-gradient(135deg, #06b6d4, #0891b2);
  --gradient-2: linear-gradient(135deg, #0891b2, #065f7a);
  --gradient-bg: radial-gradient(ellipse at top, rgba(6,182,212,0.1), transparent 60%),
                  radial-gradient(ellipse at bottom, rgba(6,182,212,0.05), transparent 60%);
  --shadow: 0 4px 20px rgba(0,0,0,0.3);
  --shadow-lg: 0 8px 40px rgba(0,0,0,0.4);
  --glow: 0 0 20px rgba(6,182,212,0.15);
}

/* ── Aurora ── */
[data-theme="aurora"] {
  --primary: #10b981; --primary-light: #34d399; --primary-dark: #059669;
  --primary-glow: rgba(16,185,129,0.3); --primary-dim: rgba(16,185,129,0.12);
  --bg: #051510; --bg2: #0a2018; --bg3: #0f2c20;
  --surface: rgba(10,32,24,0.75); --surface2: rgba(15,44,32,0.85); --surface3: rgba(20,55,40,0.9);
  --border: rgba(16,185,129,0.10); --border2: rgba(16,185,129,0.22);
  --text: #d0f0e0; --text2: #80b8a0; --text3: #4a8068;
  --success: #34d399; --warning: #fbbf24; --danger: #f87171;
  --chart-grid: rgba(16,185,129,0.08); --chart-line: #10b981;
  --header-bg: rgba(5,21,16,0.85);
  --gradient-1: linear-gradient(135deg, #10b981, #06b6d4);
  --gradient-2: linear-gradient(135deg, #059669, #0891b2);
  --gradient-bg: radial-gradient(ellipse at top, rgba(16,185,129,0.1), transparent 60%),
                  radial-gradient(ellipse at bottom, rgba(6,182,212,0.06), transparent 60%);
  --shadow: 0 4px 20px rgba(0,0,0,0.3);
  --shadow-lg: 0 8px 40px rgba(0,0,0,0.4);
  --glow: 0 0 20px rgba(16,185,129,0.15);
}

/* ── Neon ── */
[data-theme="neon"] {
  --primary: #39ff14; --primary-light: #6aff4a; --primary-dark: #2ed10e;
  --primary-glow: rgba(57,255,20,0.4); --primary-dim: rgba(57,255,20,0.12);
  --bg: #050a05; --bg2: #0a140a; --bg3: #0f1e0f;
  --surface: rgba(10,20,10,0.75); --surface2: rgba(15,30,15,0.85); --surface3: rgba(20,40,20,0.9);
  --border: rgba(57,255,20,0.10); --border2: rgba(57,255,20,0.22);
  --text: #d0f5d0; --text2: #80c080; --text3: #4a804a;
  --success: #39ff14; --warning: #ffff00; --danger: #ff4444;
  --chart-grid: rgba(57,255,20,0.08); --chart-line: #39ff14;
  --header-bg: rgba(5,10,5,0.85);
  --gradient-1: linear-gradient(135deg, #39ff14, #00ff88);
  --gradient-2: linear-gradient(135deg, #2ed10e, #00cc66);
  --gradient-bg: radial-gradient(ellipse at top, rgba(57,255,20,0.1), transparent 60%),
                  radial-gradient(ellipse at bottom, rgba(57,255,20,0.05), transparent 60%);
  --shadow: 0 4px 20px rgba(57,255,20,0.15);
  --shadow-lg: 0 8px 40px rgba(57,255,20,0.25);
  --glow: 0 0 25px rgba(57,255,20,0.2);
}

/* ── Purple Galaxy ── */
[data-theme="purple-galaxy"] {
  --primary: #a855f7; --primary-light: #c084fc; --primary-dark: #9333ea;
  --primary-glow: rgba(168,85,247,0.35); --primary-dim: rgba(168,85,247,0.12);
  --bg: #0a0515; --bg2: #120820; --bg3: #1a0c30;
  --surface: rgba(18,8,32,0.75); --surface2: rgba(26,12,48,0.85); --surface3: rgba(35,18,60,0.9);
  --border: rgba(168,85,247,0.10); --border2: rgba(168,85,247,0.22);
  --text: #e0d0f5; --text2: #a888c8; --text3: #685890;
  --success: #34d399; --warning: #fbbf24; --danger: #f87171;
  --chart-grid: rgba(168,85,247,0.08); --chart-line: #a855f7;
  --header-bg: rgba(10,5,21,0.85);
  --gradient-1: linear-gradient(135deg, #a855f7, #d946ef);
  --gradient-2: linear-gradient(135deg, #9333ea, #c026d3);
  --gradient-bg: radial-gradient(ellipse at top, rgba(168,85,247,0.12), transparent 60%),
                  radial-gradient(ellipse at bottom, rgba(217,70,239,0.08), transparent 60%);
  --shadow: 0 4px 20px rgba(0,0,0,0.3);
  --shadow-lg: 0 8px 40px rgba(0,0,0,0.4);
  --glow: 0 0 20px rgba(168,85,247,0.2);
}

/* ── Pure White ── */
[data-theme="pure-white"] {
  --primary: #6366f1; --primary-light: #818cf8; --primary-dark: #4f46e5;
  --primary-glow: rgba(99,102,241,0.15); --primary-dim: rgba(99,102,241,0.08);
  --bg: #f8fafc; --bg2: #ffffff; --bg3: #f1f5f9;
  --surface: rgba(255,255,255,0.85); --surface2: rgba(255,255,255,0.95); --surface3: rgba(248,250,252,0.95);
  --border: rgba(0,0,0,0.06); --border2: rgba(0,0,0,0.12);
  --text: #1e293b; --text2: #64748b; --text3: #94a3b8;
  --success: #10b981; --warning: #f59e0b; --danger: #ef4444;
  --chart-grid: rgba(0,0,0,0.06); --chart-line: #6366f1;
  --header-bg: rgba(255,255,255,0.85);
  --gradient-1: linear-gradient(135deg, #6366f1, #8b5cf6);
  --gradient-2: linear-gradient(135deg, #4f46e5, #7c3aed);
  --gradient-bg: radial-gradient(ellipse at top, rgba(99,102,241,0.04), transparent 60%);
  --shadow: 0 4px 20px rgba(0,0,0,0.06);
  --shadow-lg: 0 8px 40px rgba(0,0,0,0.08);
  --glow: 0 0 15px rgba(99,102,241,0.08);
}

/* ═══════════════════════════════════════════════════════════════
   BASE STYLES
   ═══════════════════════════════════════════════════════════════ */

* { margin: 0; padding: 0; box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  font-family: 'Inter', sans-serif;
  background: var(--bg);
  color: var(--text);
  transition: background 0.4s ease, color 0.4s ease;
  overflow-x: hidden;
  min-height: 100vh;
  background-image: var(--gradient-bg);
  background-attachment: fixed;
}

/* Scrollbar */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--primary); }

/* ═══════════════════════════════════════════════════════════════
   ANIMATIONS
   ═══════════════════════════════════════════════════════════════ */

@keyframes fadeIn { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
@keyframes fadeInUp { from { opacity: 0; transform: translateY(24px); } to { opacity: 1; transform: translateY(0); } }
@keyframes slideIn { from { opacity: 0; transform: translateX(-20px); } to { opacity: 1; transform: translateX(0); } }
@keyframes slideDown { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
@keyframes scaleIn { from { opacity: 0; transform: scale(0.95); } to { opacity: 1; transform: scale(1); } }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
@keyframes shimmer { 0% { background-position: -200% 0; } 100% { background-position: 200% 0; } }
@keyframes float { 0%, 100% { transform: translateY(0px); } 50% { transform: translateY(-6px); } }
@keyframes glow { 0%, 100% { box-shadow: 0 0 5px var(--primary-dim); } 50% { box-shadow: 0 0 20px var(--primary-glow); } }
@keyframes spin { to { transform: rotate(360deg); } }
@keyframes progressPulse { 0%, 100% { opacity: 0.8; } 50% { opacity: 1; } }
@keyframes countUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

.animate-fadeIn { animation: fadeIn 0.5s ease forwards; }
.animate-fadeInUp { animation: fadeInUp 0.6s ease forwards; }
.animate-slideIn { animation: slideIn 0.4s ease forwards; }
.animate-scaleIn { animation: scaleIn 0.3s ease forwards; }
.animate-float { animation: float 3s ease-in-out infinite; }

.stagger-1 { animation-delay: 0.05s; }
.stagger-2 { animation-delay: 0.1s; }
.stagger-3 { animation-delay: 0.15s; }
.stagger-4 { animation-delay: 0.2s; }
.stagger-5 { animation-delay: 0.25s; }
.stagger-6 { animation-delay: 0.3s; }
.stagger-7 { animation-delay: 0.35s; }
.stagger-8 { animation-delay: 0.4s; }

/* ═══════════════════════════════════════════════════════════════
   LOGIN PAGE
   ═══════════════════════════════════════════════════════════════ */

.login-container {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
  position: relative;
  overflow: hidden;
}

.login-particles {
  position: fixed;
  top: 0; left: 0; width: 100%; height: 100%;
  pointer-events: none;
  z-index: 0;
}

.particle {
  position: absolute;
  width: 4px; height: 4px;
  background: var(--primary);
  border-radius: 50%;
  opacity: 0.3;
  animation: float 4s ease-in-out infinite;
}

.login-card {
  position: relative;
  z-index: 1;
  width: 100%;
  max-width: 420px;
  padding: 48px 40px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 24px;
  backdrop-filter: blur(24px);
  box-shadow: var(--shadow-lg);
  animation: scaleIn 0.5s ease;
}

.login-logo {
  text-align: center;
  margin-bottom: 32px;
}

.login-logo h1 {
  font-size: 2rem;
  font-weight: 900;
  background: var(--gradient-1);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  letter-spacing: -0.02em;
}

.login-logo p {
  color: var(--text3);
  font-size: 0.9rem;
  margin-top: 6px;
}

.login-input {
  width: 100%;
  padding: 14px 16px;
  background: var(--bg3);
  border: 1px solid var(--border);
  border-radius: 12px;
  color: var(--text);
  font-size: 0.95rem;
  font-family: inherit;
  transition: all 0.3s;
  margin-bottom: 16px;
  outline: none;
}

.login-input:focus {
  border-color: var(--primary);
  box-shadow: 0 0 0 3px var(--primary-dim);
}

.login-btn {
  width: 100%;
  padding: 14px;
  background: var(--gradient-1);
  border: none;
  border-radius: 12px;
  color: white;
  font-size: 1rem;
  font-weight: 700;
  font-family: inherit;
  cursor: pointer;
  transition: all 0.3s;
  position: relative;
  overflow: hidden;
}

.login-btn:hover {
  transform: translateY(-2px);
  box-shadow: var(--glow);
}

.login-btn:active { transform: translateY(0); }

.login-btn.loading {
  pointer-events: none;
  opacity: 0.8;
}

.login-btn .spinner {
  display: none;
  width: 20px; height: 20px;
  border: 2px solid rgba(255,255,255,0.3);
  border-top-color: white;
  border-radius: 50%;
  animation: spin 0.6s linear infinite;
  margin: 0 auto;
}

.login-btn.loading .spinner { display: block; }
.login-btn.loading .btn-text { display: none; }

.login-error {
  background: rgba(248,113,113,0.1);
  border: 1px solid rgba(248,113,113,0.2);
  color: var(--danger);
  padding: 10px 14px;
  border-radius: 10px;
  font-size: 0.85rem;
  margin-bottom: 16px;
  display: none;
}

.login-footer {
  text-align: center;
  margin-top: 24px;
  color: var(--text3);
  font-size: 0.8rem;
}

/* ═══════════════════════════════════════════════════════════════
   LAYOUT — SIDEBAR + MAIN
   ═══════════════════════════════════════════════════════════════ */

.app-layout {
  display: flex;
  min-height: 100vh;
}

/* Sidebar */
.sidebar {
  width: 260px;
  background: var(--header-bg);
  border-right: 1px solid var(--border);
  backdrop-filter: blur(20px);
  padding: 20px 0;
  position: fixed;
  top: 0; left: 0;
  height: 100vh;
  z-index: 100;
  display: flex;
  flex-direction: column;
  transition: all 0.3s;
  overflow-y: auto;
}

.sidebar.collapsed {
  width: 72px;
}

.sidebar-brand {
  padding: 0 20px;
  margin-bottom: 24px;
  display: flex;
  align-items: center;
  gap: 12px;
}

.sidebar.collapsed .sidebar-brand {
  padding: 0 16px;
  justify-content: center;
}

.sidebar-brand-icon {
  width: 36px; height: 36px;
  background: var(--gradient-1);
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 900;
  font-size: 1rem;
  color: white;
  flex-shrink: 0;
}

.sidebar-brand-text {
  font-weight: 800;
  font-size: 1.1rem;
  background: var(--gradient-1);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  white-space: nowrap;
  overflow: hidden;
}

.sidebar.collapsed .sidebar-brand-text { display: none; }

.sidebar-nav {
  flex: 1;
  padding: 0 12px;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 14px;
  margin-bottom: 2px;
  border-radius: 10px;
  color: var(--text3);
  text-decoration: none;
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.25s;
  white-space: nowrap;
  border: none;
  background: none;
  width: 100%;
  font-family: inherit;
  text-align: left;
}

.nav-item:hover {
  color: var(--text);
  background: var(--surface3);
}

.nav-item.active {
  color: var(--primary);
  background: var(--primary-dim);
  font-weight: 600;
}

.nav-item .nav-icon {
  width: 20px;
  text-align: center;
  font-size: 1.1rem;
  flex-shrink: 0;
}

.sidebar.collapsed .nav-item {
  justify-content: center;
  padding: 10px;
}

.sidebar.collapsed .nav-item .nav-label { display: none; }

.sidebar-footer {
  padding: 12px;
  border-top: 1px solid var(--border);
}

/* Main Content */
.main-content {
  margin-left: 260px;
  flex: 1;
  padding: 24px;
  min-height: 100vh;
  transition: margin-left 0.3s;
}

.main-content.expanded {
  margin-left: 72px;
}

/* Top Bar */
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 24px;
  gap: 12px;
}

.topbar-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.toggle-sidebar {
  background: none;
  border: 1px solid var(--border);
  color: var(--text3);
  width: 40px; height: 40px;
  border-radius: 10px;
  cursor: pointer;
  font-size: 1.2rem;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s;
}

.toggle-sidebar:hover {
  color: var(--primary);
  border-color: var(--border2);
}

.topbar-title {
  font-size: 1.3rem;
  font-weight: 700;
}

.topbar-right {
  display: flex;
  align-items: center;
  gap: 8px;
}

/* Command Palette (Ctrl+K) */
.cmd-palette-overlay {
  position: fixed;
  top: 0; left: 0; width: 100%; height: 100%;
  background: rgba(0,0,0,0.5);
  backdrop-filter: blur(4px);
  z-index: 1000;
  display: none;
  align-items: flex-start;
  justify-content: center;
  padding-top: 80px;
}

.cmd-palette-overlay.open { display: flex; }

.cmd-palette {
  width: 100%;
  max-width: 560px;
  background: var(--surface2);
  border: 1px solid var(--border2);
  border-radius: 16px;
  overflow: hidden;
  box-shadow: var(--shadow-lg);
  animation: scaleIn 0.15s ease;
}

.cmd-input {
  width: 100%;
  padding: 16px 20px;
  background: transparent;
  border: none;
  border-bottom: 1px solid var(--border);
  color: var(--text);
  font-size: 1rem;
  font-family: inherit;
  outline: none;
}

.cmd-input::placeholder { color: var(--text3); }

.cmd-results {
  max-height: 320px;
  overflow-y: auto;
  padding: 8px;
}

.cmd-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.15s;
}

.cmd-item:hover, .cmd-item.active {
  background: var(--primary-dim);
}

.cmd-item-icon {
  width: 28px; height: 28px;
  background: var(--surface3);
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.cmd-item-text { flex: 1; font-size: 0.9rem; }
.cmd-item-desc { color: var(--text3); font-size: 0.8rem; }

/* ═══════════════════════════════════════════════════════════════
   PAGES
   ═══════════════════════════════════════════════════════════════ */

.page { display: none; }
.page.active { display: block; }
.page { animation: fadeInUp 0.4s ease; }

/* ── Dashboard Stats Grid ── */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}

.stat-card {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 20px;
  transition: all 0.3s;
  position: relative;
  overflow: hidden;
}

.stat-card:hover {
  border-color: var(--border2);
  transform: translateY(-2px);
  box-shadow: var(--glow);
}

.stat-card::before {
  content: '';
  position: absolute;
  top: 0; left: 0;
  width: 100%; height: 3px;
  background: var(--gradient-1);
  opacity: 0;
  transition: opacity 0.3s;
}

.stat-card:hover::before { opacity: 1; }

.stat-icon {
  width: 40px; height: 40px;
  background: var(--primary-dim);
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.2rem;
  margin-bottom: 12px;
}

.stat-label {
  font-size: 0.75rem;
  color: var(--text3);
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  margin-bottom: 4px;
}

.stat-value {
  font-size: 1.6rem;
  font-weight: 800;
  color: var(--text);
  line-height: 1.2;
}

.stat-sub {
  font-size: 0.8rem;
  color: var(--text3);
  margin-top: 4px;
}

/* ── Charts ── */
.chart-card {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 20px;
  margin-bottom: 16px;
}

.chart-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}

.chart-title {
  font-size: 1rem;
  font-weight: 600;
}

.chart-container {
  height: 280px;
  position: relative;
}

.chart-container-sm { height: 200px; }

/* ── Cards (general) ── */
.glass-card {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 20px;
  margin-bottom: 16px;
  transition: all 0.3s;
  backdrop-filter: blur(10px);
}

.glass-card:hover {
  border-color: var(--border2);
}

.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}

.card-title {
  font-size: 1rem;
  font-weight: 600;
}

/* ── Buttons ── */
.btn {
  font-family: inherit;
  font-size: 0.85rem;
  font-weight: 600;
  padding: 8px 16px;
  border-radius: 10px;
  border: none;
  cursor: pointer;
  transition: all 0.25s;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  text-decoration: none;
}

.btn-primary {
  background: var(--gradient-1);
  color: white;
  box-shadow: 0 2px 10px var(--primary-dim);
}

.btn-primary:hover {
  transform: translateY(-1px);
  box-shadow: var(--glow);
}

.btn-secondary {
  background: var(--surface3);
  color: var(--text);
  border: 1px solid var(--border);
}

.btn-secondary:hover {
  border-color: var(--border2);
  background: var(--bg3);
}

.btn-ghost {
  background: transparent;
  color: var(--text3);
  padding: 8px;
}

.btn-ghost:hover { color: var(--text); background: var(--surface3); }

.btn-danger {
  background: rgba(248,113,113,0.1);
  color: var(--danger);
  border: 1px solid rgba(248,113,113,0.2);
}

.btn-danger:hover {
  background: rgba(248,113,113,0.2);
}

.btn-sm { padding: 6px 12px; font-size: 0.8rem; }
.btn-xs { padding: 4px 8px; font-size: 0.75rem; border-radius: 6px; }

/* ── Tables ── */
.table-wrap {
  overflow-x: auto;
  border-radius: 12px;
}

table {
  width: 100%;
  border-collapse: collapse;
}

table th {
  text-align: left;
  padding: 12px 14px;
  font-size: 0.75rem;
  font-weight: 700;
  color: var(--text3);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  border-bottom: 1px solid var(--border);
  background: var(--surface3);
}

table td {
  padding: 12px 14px;
  font-size: 0.85rem;
  border-bottom: 1px solid var(--border);
  transition: background 0.2s;
}

table tr:hover td {
  background: var(--primary-dim);
}

/* ── Status Badges ── */
.badge {
  display: inline-flex;
  align-items: center;
  padding: 3px 8px;
  border-radius: 6px;
  font-size: 0.7rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.badge-active { background: rgba(52,211,153,0.1); color: var(--success); border: 1px solid rgba(52,211,153,0.2); }
.badge-inactive { background: rgba(248,113,113,0.1); color: var(--danger); border: 1px solid rgba(248,113,113,0.2); }
.badge-warning { background: rgba(251,191,36,0.1); color: var(--warning); border: 1px solid rgba(251,191,36,0.2); }

/* ── Progress ── */
.progress-bar {
  height: 6px;
  background: var(--border);
  border-radius: 3px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  border-radius: 3px;
  transition: width 0.6s ease;
  background: var(--gradient-1);
}

/* ── Toggle Switch ── */
.toggle {
  width: 42px; height: 24px;
  border-radius: 12px;
  background: var(--surface3);
  border: 2px solid var(--border);
  cursor: pointer;
  position: relative;
  transition: all 0.3s;
  flex-shrink: 0;
}

.toggle::after {
  content: '';
  position: absolute;
  width: 16px; height: 16px;
  border-radius: 50%;
  background: var(--text3);
  top: 2px; left: 2px;
  transition: all 0.3s;
}

.toggle.on {
  background: var(--success);
  border-color: var(--success);
}

.toggle.on::after {
  left: 20px;
  background: white;
}

/* ── Modal ── */
.modal-overlay {
  position: fixed;
  top: 0; left: 0; width: 100%; height: 100%;
  background: rgba(0,0,0,0.6);
  backdrop-filter: blur(8px);
  z-index: 500;
  display: none;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.modal-overlay.open { display: flex; }

.modal {
  width: 100%;
  max-width: 560px;
  max-height: 80vh;
  overflow-y: auto;
  background: var(--surface2);
  border: 1px solid var(--border2);
  border-radius: 20px;
  padding: 28px;
  box-shadow: var(--shadow-lg);
  animation: scaleIn 0.2s ease;
}

.modal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 20px;
}

.modal-title {
  font-size: 1.2rem;
  font-weight: 700;
}

.modal-close {
  background: none;
  border: none;
  color: var(--text3);
  font-size: 1.5rem;
  cursor: pointer;
  padding: 4px;
  border-radius: 8px;
  transition: all 0.2s;
}

.modal-close:hover { color: var(--text); background: var(--surface3); }

.modal-body .form-group {
  margin-bottom: 16px;
}

.form-label {
  display: block;
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--text2);
  margin-bottom: 6px;
}

.form-input, .form-select, .form-textarea {
  width: 100%;
  padding: 10px 14px;
  background: var(--bg3);
  border: 1px solid var(--border);
  border-radius: 10px;
  color: var(--text);
  font-size: 0.9rem;
  font-family: inherit;
  outline: none;
  transition: all 0.2s;
}

.form-input:focus, .form-select:focus, .form-textarea:focus {
  border-color: var(--primary);
  box-shadow: 0 0 0 3px var(--primary-dim);
}

.form-textarea { resize: vertical; min-height: 80px; }

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}

/* ── Toast Notifications ── */
.toast-container {
  position: fixed;
  bottom: 24px;
  right: 24px;
  z-index: 2000;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.toast {
  background: var(--surface2);
  border: 1px solid var(--border2);
  border-radius: 12px;
  padding: 14px 18px;
  min-width: 300px;
  max-width: 400px;
  box-shadow: var(--shadow-lg);
  animation: slideIn 0.3s ease;
  display: flex;
  align-items: flex-start;
  gap: 12px;
  backdrop-filter: blur(20px);
}

.toast-icon { font-size: 1.2rem; flex-shrink: 0; }
.toast-content { flex: 1; }
.toast-title { font-weight: 700; font-size: 0.9rem; margin-bottom: 2px; }
.toast-message { font-size: 0.8rem; color: var(--text2); }
.toast-close { cursor: pointer; color: var(--text3); font-size: 1rem; }

.toast.success .toast-icon { color: var(--success); }
.toast.warning .toast-icon { color: var(--warning); }
.toast.error .toast-icon { color: var(--danger); }
.toast.info .toast-icon { color: var(--primary); }

/* ── Skeleton Loader ── */
.skeleton {
  background: linear-gradient(90deg, var(--surface3) 25%, var(--surface2) 50%, var(--surface3) 75%);
  background-size: 200% 100%;
  animation: shimmer 1.5s ease infinite;
  border-radius: 8px;
}

.skeleton-card {
  height: 120px;
}

.skeleton-text {
  height: 16px;
  margin-bottom: 8px;
  width: 60%;
}

.skeleton-text.short { width: 40%; }

/* ── Notification Badge ── */
.notif-badge {
  position: absolute;
  top: -4px;
  right: -4px;
  background: var(--danger);
  color: white;
  font-size: 0.6rem;
  font-weight: 800;
  min-width: 16px;
  height: 16px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0 4px;
}

/* ── Connection Monitor ── */
.conn-row {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  transition: background 0.2s;
}

.conn-row:hover { background: var(--primary-dim); }
.conn-row:last-child { border-bottom: none; }

.conn-status-dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.conn-status-dot.active { background: var(--success); box-shadow: 0 0 6px var(--success); }
.conn-status-dot.idle { background: var(--warning); }

/* ── Rankings ── */
.rank-medal {
  font-size: 1.2rem;
}

.rank-row {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
}

.rank-row:first-child { background: linear-gradient(135deg, rgba(255,215,0,0.05), transparent); }
.rank-row:nth-child(2) { background: linear-gradient(135deg, rgba(192,192,192,0.05), transparent); }
.rank-row:nth-child(3) { background: linear-gradient(135deg, rgba(205,127,50,0.05), transparent); }

/* ── Theme Switcher ── */
.theme-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
  gap: 12px;
}

.theme-card {
  padding: 16px;
  border-radius: 12px;
  border: 2px solid var(--border);
  cursor: pointer;
  text-align: center;
  transition: all 0.3s;
  font-size: 0.8rem;
  font-weight: 600;
}

.theme-card:hover { border-color: var(--border2); transform: translateY(-2px); }
.theme-card.active { border-color: var(--primary); box-shadow: var(--glow); }

.theme-preview {
  width: 100%;
  height: 60px;
  border-radius: 8px;
  margin-bottom: 8px;
}

/* ── Search ── */
.search-overlay {
  position: fixed;
  top: 0; left: 0; width: 100%; height: 100%;
  background: rgba(0,0,0,0.5);
  backdrop-filter: blur(4px);
  z-index: 800;
  display: none;
  align-items: flex-start;
  justify-content: center;
  padding-top: 60px;
}

.search-overlay.open { display: flex; }

.search-box {
  width: 100%;
  max-width: 520px;
  background: var(--surface2);
  border: 1px solid var(--border2);
  border-radius: 16px;
  overflow: hidden;
  box-shadow: var(--shadow-lg);
}

/* Responsive */
@media (max-width: 1024px) {
  .stats-grid { grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); }
}

@media (max-width: 768px) {
  .sidebar {
    width: 72px;
  }
  .sidebar .sidebar-brand-text,
  .sidebar .nav-label { display: none; }
  .sidebar .sidebar-brand { justify-content: center; }
  .sidebar .nav-item { justify-content: center; padding: 10px; }
  .main-content {
    margin-left: 72px;
    padding: 16px;
  }
  .stats-grid { grid-template-columns: repeat(2, 1fr); }
  .form-row { grid-template-columns: 1fr; }
  .modal { padding: 20px; }
}

@media (max-width: 480px) {
  .stats-grid { grid-template-columns: 1fr; }
  .topbar-title { font-size: 1rem; }
  .main-content { padding: 12px; }
  .login-card { padding: 32px 24px; }
}

/* ── Tooltip ── */
[data-tooltip] {
  position: relative;
}

[data-tooltip]::after {
  content: attr(data-tooltip);
  position: absolute;
  bottom: calc(100% + 6px);
  left: 50%;
  transform: translateX(-50%) scale(0.9);
  background: var(--surface3);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 500;
  white-space: nowrap;
  opacity: 0;
  pointer-events: none;
  transition: all 0.2s;
}

[data-tooltip]:hover::after {
  opacity: 1;
  transform: translateX(-50%) scale(1);
}

/* ── Context Menu ── */
.context-menu {
  position: fixed;
  background: var(--surface2);
  border: 1px solid var(--border2);
  border-radius: 10px;
  padding: 4px;
  min-width: 160px;
  box-shadow: var(--shadow-lg);
  z-index: 900;
  display: none;
}

.context-menu.open { display: block; }

.context-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 12px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 0.85rem;
  transition: background 0.15s;
}

.context-item:hover { background: var(--primary-dim); }
.context-item.danger { color: var(--danger); }
.context-divider { height: 1px; background: var(--border); margin: 4px 0; }

/* ── Responsive table fixes ── */
@media (max-width: 768px) {
  table th, table td { padding: 8px 10px; font-size: 0.75rem; }
}

/* ── Empty State ── */
.empty-state {
  text-align: center;
  padding: 40px 20px;
  color: var(--text3);
}

.empty-state-icon { font-size: 3rem; margin-bottom: 12px; opacity: 0.5; }
.empty-state-text { font-size: 1rem; margin-bottom: 4px; }
.empty-state-sub { font-size: 0.85rem; }

/* ── Ping indicator for connections ── */
.ping-dot {
  display: inline-block;
  width: 8px; height: 8px;
  border-radius: 50%;
  margin-right: 6px;
}

.ping-dot.good { background: var(--success); }
.ping-dot.fair { background: var(--warning); }
.ping-dot.poor { background: var(--danger); }

/* ── Live Timer ── */
.live-timer {
  font-variant-numeric: tabular-nums;
  font-weight: 600;
}

/* ── Keyboard shortcut hint ── */
.kbd {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 2px 6px;
  background: var(--bg3);
  border: 1px solid var(--border);
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 700;
  color: var(--text3);
  font-family: inherit;
  min-width: 22px;
}

/* ── Loading Screen ── */
.loading-screen {
  position: fixed;
  top: 0; left: 0; width: 100%; height: 100%;
  background: var(--bg);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 9999;
  transition: opacity 0.5s;
}

.loading-screen.hidden { opacity: 0; pointer-events: none; }

.loading-logo {
  text-align: center;
}

.loading-logo h1 {
  font-size: 2.5rem;
  font-weight: 900;
  background: var(--gradient-1);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.loading-bar {
  width: 200px; height: 3px;
  background: var(--border);
  border-radius: 2px;
  margin: 20px auto 0;
  overflow: hidden;
}

.loading-bar-fill {
  height: 100%;
  width: 30%;
  background: var(--gradient-1);
  border-radius: 2px;
  animation: loadingProgress 1.2s ease-in-out infinite;
}

@keyframes loadingProgress {
  0% { transform: translateX(-100%); width: 30%; }
  50% { width: 60%; }
  100% { transform: translateX(400%); width: 30%; }
}
</style>
</head>
<body>

<div class="loading-screen" id="loadingScreen">
  <div class="loading-logo">
    <h1>Best Panel</h1>
    <div class="loading-bar"><div class="loading-bar-fill"></div></div>
  </div>
</div>

<div id="loginPage" class="login-container">
  <div class="login-particles" id="loginParticles"></div>
  <div class="login-card">
    <div class="login-logo">
      <h1>Best Panel</h1>
      <p>Premium Subscription Management</p>
    </div>
    <div class="login-error" id="loginError"></div>
    <form id="loginForm" onsubmit="handleLogin(event)">
      <input type="password" class="login-input" id="passwordInput" placeholder="Enter password" autofocus required>
      <button type="submit" class="login-btn" id="loginBtn">
        <span class="btn-text">Sign In</span>
        <div class="spinner"></div>
      </button>
    </form>
    <div class="login-footer">
      <span id="loginDomain"></span>
    </div>
  </div>
</div>

<div id="app" class="app-layout" style="display:none;">
  <!-- Sidebar -->
  <nav class="sidebar" id="sidebar">
    <div class="sidebar-brand">
      <div class="sidebar-brand-icon">B</div>
      <span class="sidebar-brand-text">Best Panel</span>
    </div>
    <div class="sidebar-nav">
      <button class="nav-item active" onclick="navigate('dashboard')" data-page="dashboard">
        <span class="nav-icon">📊</span>
        <span class="nav-label">Dashboard</span>
      </button>
      <button class="nav-item" onclick="navigate('users')" data-page="users">
        <span class="nav-icon">👥</span>
        <span class="nav-label">Users</span>
      </button>
      <button class="nav-item" onclick="navigate('monitor')" data-page="monitor">
        <span class="nav-icon">🔗</span>
        <span class="nav-label">Live Monitor</span>
      </button>
      <button class="nav-item" onclick="navigate('analytics')" data-page="analytics">
        <span class="nav-icon">📈</span>
        <span class="nav-label">Analytics</span>
      </button>
      <button class="nav-item" onclick="navigate('rankings')" data-page="rankings">
        <span class="nav-icon">🏆</span>
        <span class="nav-label">Rankings</span>
      </button>
      <button class="nav-item" onclick="navigate('logs')" data-page="logs">
        <span class="nav-icon">📋</span>
        <span class="nav-label">Logs</span>
      </button>
      <button class="nav-item" onclick="navigate('addresses')" data-page="addresses">
        <span class="nav-icon">🌐</span>
        <span class="nav-label">Addresses</span>
      </button>
      <button class="nav-item" onclick="navigate('settings')" data-page="settings">
        <span class="nav-icon">⚙️</span>
        <span class="nav-label">Settings</span>
      </button>
    </div>
    <div class="sidebar-footer">
      <button class="nav-item" onclick="handleLogout()" style="color:var(--danger);">
        <span class="nav-icon">🚪</span>
        <span class="nav-label">Logout</span>
      </button>
    </div>
  </nav>

  <!-- Main Content -->
  <main class="main-content" id="mainContent">
    <!-- Top Bar -->
    <div class="topbar">
      <div class="topbar-left">
        <button class="toggle-sidebar" onclick="toggleSidebar()" data-tooltip="Toggle sidebar">☰</button>
        <span class="topbar-title" id="pageTitle">Dashboard</span>
      </div>
      <div class="topbar-right">
        <button class="btn btn-ghost" onclick="openSearch()" data-tooltip="Search (Ctrl+K)">🔍</button>
        <button class="btn btn-ghost" onclick="openNotifications()" id="notifBtn" data-tooltip="Notifications" style="position:relative;">
          🔔 <span class="notif-badge" id="notifBadge" style="display:none;">0</span>
        </button>
        <button class="btn btn-ghost" onclick="openThemeSwitcher()" data-tooltip="Theme">🎨</button>
      </div>
    </div>

    <!-- Pages -->

    <!-- Dashboard -->
    <div class="page active" id="pageDashboard">
      <div class="stats-grid" id="dashboardStats">
        <div class="stat-card"><div class="skeleton skeleton-card"></div></div>
        <div class="stat-card"><div class="skeleton skeleton-card"></div></div>
        <div class="stat-card"><div class="skeleton skeleton-card"></div></div>
        <div class="stat-card"><div class="skeleton skeleton-card"></div></div>
        <div class="stat-card"><div class="skeleton skeleton-card"></div></div>
        <div class="stat-card"><div class="skeleton skeleton-card"></div></div>
      </div>
      <div class="chart-card">
        <div class="chart-header">
          <span class="chart-title">Traffic Overview (24h)</span>
        </div>
        <div class="chart-container" id="trafficChart"><canvas id="trafficCanvas"></canvas></div>
      </div>
      <div class="chart-card">
        <div class="chart-header">
          <span class="chart-title">System Resources</span>
        </div>
        <div class="chart-container-sm" id="sysChart"><canvas id="sysCanvas"></canvas></div>
      </div>
    </div>

    <!-- Users -->
    <div class="page" id="pageUsers">
      <div class="glass-card">
        <div class="card-header">
          <span class="card-title">All Users</span>
          <div style="display:flex;gap:8px;">
            <button class="btn btn-primary btn-sm" onclick="openCreateUser()">+ New User</button>
            <button class="btn btn-secondary btn-sm" onclick="exportUsers()">Export</button>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th style="width:30px;"><input type="checkbox" id="selectAllUsers" onchange="toggleSelectAll(this)"></th>
                <th>User</th>
                <th>Usage</th>
                <th>Traffic</th>
                <th>Connections</th>
                <th>Status</th>
                <th>Expires</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="usersTableBody">
              <tr><td colspan="8"><div class="skeleton skeleton-text" style="width:100%;"></div></td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Live Monitor -->
    <div class="page" id="pageMonitor">
      <div class="glass-card">
        <div class="card-header">
          <span class="card-title">Live Connections <span id="connCount" style="color:var(--primary);font-weight:700;">0</span></span>
          <div style="display:flex;gap:8px;align-items:center;">
            <span class="badge badge-active" id="monitorStatus">● Live</span>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>IP</th>
                <th>Location</th>
                <th>Duration</th>
                <th>Upload</th>
                <th>Download</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody id="monitorTableBody">
              <tr><td colspan="7"><div class="empty-state"><div class="empty-state-icon">🔗</div><div class="empty-state-text">Waiting for connections...</div></div></td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Analytics -->
    <div class="page" id="pageAnalytics">
      <div class="glass-card">
        <div class="card-header">
          <span class="card-title">Daily Traffic (30 days)</span>
        </div>
        <div class="chart-container" id="analyticsChart"><canvas id="analyticsCanvas"></canvas></div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
        <div class="glass-card">
          <div class="card-header"><span class="card-title">Top Users</span></div>
          <div id="topUsersList"></div>
        </div>
        <div class="glass-card">
          <div class="card-header"><span class="card-title">Countries</span></div>
          <div id="countriesList"></div>
        </div>
      </div>
    </div>

    <!-- Rankings -->
    <div class="page" id="pageRankings">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
        <div class="glass-card">
          <div class="card-header"><span class="card-title">Top Traffic</span></div>
          <div id="rankTraffic"></div>
        </div>
        <div class="glass-card">
          <div class="card-header"><span class="card-title">Top Upload</span></div>
          <div id="rankUpload"></div>
        </div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px;">
        <div class="glass-card">
          <div class="card-header"><span class="card-title">Top Download</span></div>
          <div id="rankDownload"></div>
        </div>
        <div class="glass-card">
          <div class="card-header"><span class="card-title">Top Sessions</span></div>
          <div id="rankSessions"></div>
        </div>
      </div>
    </div>

    <!-- Logs -->
    <div class="page" id="pageLogs">
      <div class="glass-card">
        <div class="card-header">
          <span class="card-title">Activity Logs</span>
          <div style="display:flex;gap:8px;">
            <button class="btn btn-danger btn-sm" onclick="clearLogs()">Clear</button>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Time</th><th>Type</th><th>Message</th><th>IP</th></tr>
            </thead>
            <tbody id="logsTableBody"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Addresses -->
    <div class="page" id="pageAddresses">
      <div class="glass-card">
        <div class="card-header">
          <span class="card-title">Clean IP Addresses</span>
          <button class="btn btn-primary btn-sm" onclick="addAddress()">+ Add</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>#</th><th>Address</th><th>Actions</th></tr></thead>
            <tbody id="addressesTableBody"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Settings -->
    <div class="page" id="pageSettings">
      <div class="glass-card">
        <div class="card-header"><span class="card-title">Theme</span></div>
        <div class="theme-grid" id="themeGrid">
          <div class="theme-card" data-theme-name="midnight" onclick="setTheme('midnight')">
            <div class="theme-preview" style="background:linear-gradient(135deg,#6366f1,#11131e);"></div>
            Midnight
          </div>
          <div class="theme-card" data-theme-name="cyberpunk" onclick="setTheme('cyberpunk')">
            <div class="theme-preview" style="background:linear-gradient(135deg,#f706cf,#0a0010);"></div>
            Cyberpunk
          </div>
          <div class="theme-card" data-theme-name="ocean" onclick="setTheme('ocean')">
            <div class="theme-preview" style="background:linear-gradient(135deg,#06b6d4,#042030);"></div>
            Ocean
          </div>
          <div class="theme-card" data-theme-name="aurora" onclick="setTheme('aurora')">
            <div class="theme-preview" style="background:linear-gradient(135deg,#10b981,#051510);"></div>
            Aurora
          </div>
          <div class="theme-card" data-theme-name="neon" onclick="setTheme('neon')">
            <div class="theme-preview" style="background:linear-gradient(135deg,#39ff14,#050a05);"></div>
            Neon
          </div>
          <div class="theme-card" data-theme-name="purple-galaxy" onclick="setTheme('purple-galaxy')">
            <div class="theme-preview" style="background:linear-gradient(135deg,#a855f7,#0a0515);"></div>
            Purple Galaxy
          </div>
          <div class="theme-card" data-theme-name="pure-white" onclick="setTheme('pure-white')">
            <div class="theme-preview" style="background:linear-gradient(135deg,#6366f1,#f8fafc);"></div>
            Pure White
          </div>
        </div>
      </div>
      <div class="glass-card">
        <div class="card-header">
          <span class="card-title">Panel Settings</span>
          <button class="btn btn-primary btn-sm" onclick="savePanelSettings()">Save</button>
        </div>
        <div id="settingsForm"></div>
      </div>
    </div>
  </main>
</div>

<!-- Search Overlay -->
<div class="cmd-palette-overlay" id="searchOverlay" onclick="if(event.target===this)closeSearch()">
  <div class="cmd-palette">
    <input class="cmd-input" id="searchInput" placeholder="Search users, IPs, UUIDs..." autofocus oninput="handleSearch(this.value)" onkeydown="if(event.key==='Escape')closeSearch();if(event.key==='Enter'&&this.value)handleSearch(this.value)">
    <div class="cmd-results" id="searchResults"></div>
  </div>
</div>

<!-- Notifications Panel -->
<div class="cmd-palette-overlay" id="notifOverlay" onclick="if(event.target===this)closeNotifications()">
  <div class="cmd-palette" style="max-width:400px;">
    <div style="padding:14px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">
      <strong>Notifications</strong>
      <button class="btn btn-xs btn-ghost" onclick="markAllRead()">Mark all read</button>
    </div>
    <div class="cmd-results" id="notifList"></div>
  </div>
</div>

<!-- Theme Switcher Panel -->
<div class="cmd-palette-overlay" id="themeOverlay" onclick="if(event.target===this)closeThemeSwitcher()">
  <div class="cmd-palette" style="max-width:500px;">
    <div style="padding:14px 16px;border-bottom:1px solid var(--border);">
      <strong>Choose Theme</strong>
    </div>
    <div style="padding:16px;">
      <div class="theme-grid">
        <div class="theme-card" data-theme-name="midnight" onclick="setTheme('midnight');closeThemeSwitcher();">
          <div class="theme-preview" style="background:linear-gradient(135deg,#6366f1,#11131e);"></div>
          Midnight
        </div>
        <div class="theme-card" data-theme-name="cyberpunk" onclick="setTheme('cyberpunk');closeThemeSwitcher();">
          <div class="theme-preview" style="background:linear-gradient(135deg,#f706cf,#0a0010);"></div>
          Cyberpunk
        </div>
        <div class="theme-card" data-theme-name="ocean" onclick="setTheme('ocean');closeThemeSwitcher();">
          <div class="theme-preview" style="background:linear-gradient(135deg,#06b6d4,#042030);"></div>
          Ocean
        </div>
        <div class="theme-card" data-theme-name="aurora" onclick="setTheme('aurora');closeThemeSwitcher();">
          <div class="theme-preview" style="background:linear-gradient(135deg,#10b981,#051510);"></div>
          Aurora
        </div>
        <div class="theme-card" data-theme-name="neon" onclick="setTheme('neon');closeThemeSwitcher();">
          <div class="theme-preview" style="background:linear-gradient(135deg,#39ff14,#050a05);"></div>
          Neon
        </div>
        <div class="theme-card" data-theme-name="purple-galaxy" onclick="setTheme('purple-galaxy');closeThemeSwitcher();">
          <div class="theme-preview" style="background:linear-gradient(135deg,#a855f7,#0a0515);"></div>
          Purple Galaxy
        </div>
        <div class="theme-card" data-theme-name="pure-white" onclick="setTheme('pure-white');closeThemeSwitcher();">
          <div class="theme-preview" style="background:linear-gradient(135deg,#6366f1,#f8fafc);"></div>
          Pure White
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Create User Modal -->
<div class="modal-overlay" id="createUserModal">
  <div class="modal">
    <div class="modal-header">
      <span class="modal-title">Create New User</span>
      <button class="modal-close" onclick="closeModal('createUserModal')">✕</button>
    </div>
    <div class="modal-body">
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">Username *</label>
          <input class="form-input" id="cuUsername" placeholder="Enter username">
        </div>
        <div class="form-group">
          <label class="form-label">Password</label>
          <input class="form-input" id="cuPassword" type="password" placeholder="Optional">
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">Traffic Limit</label>
          <div style="display:flex;gap:8px;">
            <input class="form-input" id="cuLimitVal" type="number" placeholder="0" style="flex:1;">
            <select class="form-select" id="cuLimitUnit" style="width:80px;">
              <option>MB</option><option selected>GB</option><option>TB</option>
            </select>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Unlimited Traffic</label>
          <div class="toggle" id="cuUnlimited" onclick="this.classList.toggle('on');document.getElementById('cuLimitVal').disabled=this.classList.contains('on')"></div>
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">Expire Days</label>
          <input class="form-input" id="cuDays" type="number" placeholder="0 = never">
        </div>
        <div class="form-group">
          <label class="form-label">Max Connections</label>
          <input class="form-input" id="cuMaxConn" type="number" placeholder="0 = unlimited">
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">Max Devices</label>
          <input class="form-input" id="cuMaxDev" type="number" placeholder="0 = unlimited">
        </div>
        <div class="form-group">
          <label class="form-label">Priority</label>
          <input class="form-input" id="cuPriority" type="number" placeholder="0" value="0">
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">Tags (comma separated)</label>
        <input class="form-input" id="cuTags" placeholder="vip, test, etc">
      </div>
      <div class="form-group">
        <label class="form-label">Notes</label>
        <textarea class="form-textarea" id="cuNotes" placeholder="Optional notes"></textarea>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">Color</label>
          <input class="form-input" id="cuColor" type="color" value="#6366f1">
        </div>
        <div class="form-group">
          <label class="form-label">Flag (2-letter country code)</label>
          <input class="form-input" id="cuFlag" placeholder="US" maxlength="2" style="text-transform:uppercase;">
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">Custom Path</label>
        <input class="form-input" id="cuPath" placeholder="/ws/auto">
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">Custom SNI</label>
          <input class="form-input" id="cuSni" placeholder="Auto">
        </div>
        <div class="form-group">
          <label class="form-label">Custom Host</label>
          <input class="form-input" id="cuHost" placeholder="Auto">
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">Fingerprint</label>
          <select class="form-select" id="cuFp">
            <option>chrome</option><option>firefox</option><option>safari</option><option>random</option><option>none</option>
          </select>
        </div>
        <div class="form-group">
          <label class="form-label">Fragment</label>
          <input class="form-input" id="cuFragment" placeholder="e.g. 1000-2000">
        </div>
      </div>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:20px;">
        <button class="btn btn-secondary" onclick="closeModal('createUserModal')">Cancel</button>
        <button class="btn btn-primary" onclick="createUser()">Create User</button>
      </div>
    </div>
  </div>
</div>

<!-- Edit User Modal -->
<div class="modal-overlay" id="editUserModal">
  <div class="modal">
    <div class="modal-header">
      <span class="modal-title">Edit User</span>
      <button class="modal-close" onclick="closeModal('editUserModal')">✕</button>
    </div>
    <div class="modal-body" id="editUserBody"></div>
  </div>
</div>

<!-- User Detail Modal -->
<div class="modal-overlay" id="userDetailModal">
  <div class="modal" style="max-width:640px;">
    <div class="modal-header">
      <span class="modal-title" id="userDetailTitle">User Details</span>
      <button class="modal-close" onclick="closeModal('userDetailModal')">✕</button>
    </div>
    <div class="modal-body" id="userDetailBody"></div>
  </div>
</div>

<!-- Toast Container -->
<div class="toast-container" id="toastContainer"></div>

<!-- Context Menu -->
<div class="context-menu" id="contextMenu"></div>

<script>
/* ═══════════════════════════════════════════════════════════════
   APPLICATION STATE
   ═══════════════════════════════════════════════════════════════ */

let state = {
  stats: {},
  users: [],
  connections: [],
  logs: [],
  addresses: [],
  settings: {},
  notifCount: 0,
  chartInstance: null,
  analyticsChart: null,
  sysChart: null,
  monitorWs: null,
  currentUser: null,
};

const $ = (id) => document.getElementById(id);

/* ═══════════════════════════════════════════════════════════════
   THEME SYSTEM
   ═══════════════════════════════════════════════════════════════ */

function getTheme() { return localStorage.getItem('best-panel-theme') || 'midnight'; }
function setTheme(name) {
  document.documentElement.setAttribute('data-theme', name);
  localStorage.setItem('best-panel-theme', name);
  document.querySelectorAll('.theme-card').forEach(c => c.classList.toggle('active', c.dataset.themeName === name));
  // Save to server
  fetch('/api/settings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ theme: name }) });
}

// Init theme
document.documentElement.setAttribute('data-theme', getTheme());

/* ═══════════════════════════════════════════════════════════════
   TOAST NOTIFICATIONS
   ═══════════════════════════════════════════════════════════════ */

function showToast(title, message, type = 'info') {
  const container = $('toastContainer');
  const icons = { success: '✅', warning: '⚠️', error: '❌', info: 'ℹ️' };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span class="toast-icon">${icons[type] || 'ℹ️'}</span>
    <div class="toast-content"><div class="toast-title">${title}</div><div class="toast-message">${message}</div></div>
    <span class="toast-close" onclick="this.parentElement.remove()">✕</span>`;
  container.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 300); }, 4000);
}

/* ═══════════════════════════════════════════════════════════════
   AUTH
   ═══════════════════════════════════════════════════════════════ */

async function handleLogin(e) {
  e.preventDefault();
  const btn = $('loginBtn');
  const err = $('loginError');
  btn.classList.add('loading');
  err.style.display = 'none';
  try {
    const resp = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: $('passwordInput').value }),
    });
    if (resp.ok) {
      $('loginPage').style.display = 'none';
      $('app').style.display = 'flex';
      initApp();
    } else {
      const data = await resp.json();
      err.textContent = data.detail || 'Invalid password';
      err.style.display = 'block';
    }
  } catch (e) {
    err.textContent = 'Connection error';
    err.style.display = 'block';
  }
  btn.classList.remove('loading');
}

async function handleLogout() {
  await fetch('/api/logout', { method: 'POST' });
  $('app').style.display = 'none';
  $('loginPage').style.display = 'flex';
  $('passwordInput').value = '';
  if (state.monitorWs) { state.monitorWs.close(); state.monitorWs = null; }
}

async function checkAuth() {
  try {
    const resp = await fetch('/api/me');
    if (resp.ok) {
      $('loginPage').style.display = 'none';
      $('app').style.display = 'flex';
      initApp();
    }
  } catch(e) {}
}

/* ═══════════════════════════════════════════════════════════════
   NAVIGATION
   ═══════════════════════════════════════════════════════════════ */

const pageTitles = {
  dashboard: 'Dashboard', users: 'Users', monitor: 'Live Monitor',
  analytics: 'Analytics', rankings: 'Rankings', logs: 'Logs',
  addresses: 'Addresses', settings: 'Settings',
};

function navigate(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const pg = $('page' + page.charAt(0).toUpperCase() + page.slice(1));
  if (pg) pg.classList.add('active');
  const nav = document.querySelector(`.nav-item[data-page="${page}"]`);
  if (nav) nav.classList.add('active');
  $('pageTitle').textContent = pageTitles[page] || page;
  // Load page data
  if (page === 'dashboard') loadDashboard();
  if (page === 'users') loadUsers();
  if (page === 'monitor') startMonitor();
  if (page === 'analytics') loadAnalytics();
  if (page === 'rankings') loadRankings();
  if (page === 'logs') loadLogs();
  if (page === 'addresses') loadAddresses();
  if (page === 'settings') loadSettings();
  closeSearch(); closeNotifications();
}

/* ═══════════════════════════════════════════════════════════════
   SIDEBAR
   ═══════════════════════════════════════════════════════════════ */

function toggleSidebar() {
  const sidebar = $('sidebar');
  const main = $('mainContent');
  sidebar.classList.toggle('collapsed');
  main.classList.toggle('expanded');
}

/* ═══════════════════════════════════════════════════════════════
   MODALS
   ═══════════════════════════════════════════════════════════════ */

function openModal(id) { $(id).classList.add('open'); }
function closeModal(id) { $(id).classList.remove('open'); }

/* ═══════════════════════════════════════════════════════════════
   SEARCH (Ctrl+K)
   ═══════════════════════════════════════════════════════════════ */

function openSearch() { $('searchOverlay').classList.add('open'); setTimeout(() => $('searchInput').focus(), 100); }
function closeSearch() { $('searchOverlay').classList.remove('open'); $('searchInput').value = ''; $('searchResults').innerHTML = ''; }

async function handleSearch(q) {
  if (!q || q.length < 2) { $('searchResults').innerHTML = ''; return; }
  try {
    const resp = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
    const data = await resp.json();
    const results = data.results || [];
    if (results.length === 0) {
      $('searchResults').innerHTML = '<div class="empty-state"><div class="empty-state-text">No results</div></div>';
      return;
    }
    $('searchResults').innerHTML = results.map(r => {
      if (r.type === 'user') {
        return `<div class="cmd-item" onclick="closeSearch();showUserDetail('${r.uid}')">
          <span class="cmd-item-icon">👤</span>
          <div class="cmd-item-text">${r.username} ${r.active ? '' : '(inactive)'}</div>
        </div>`;
      }
      return `<div class="cmd-item"><span class="cmd-item-icon">🔗</span>
        <div class="cmd-item-text">${r.ip} — ${r.uuid?.slice(0,8)}...</div></div>`;
    }).join('');
  } catch(e) {}
}

/* ═══════════════════════════════════════════════════════════════
   NOTIFICATIONS
   ═══════════════════════════════════════════════════════════════ */

function openNotifications() { loadNotifications(); $('notifOverlay').classList.add('open'); }
function closeNotifications() { $('notifOverlay').classList.remove('open'); }

async function loadNotifications() {
  try {
    const resp = await fetch('/api/notifications');
    const data = await resp.json();
    const notifs = data.notifications || [];
    state.notifCount = notifs.filter(n => !n.read).length;
    $('notifBadge').textContent = state.notifCount;
    $('notifBadge').style.display = state.notifCount > 0 ? 'flex' : 'none';
    $('notifList').innerHTML = notifs.length === 0
      ? '<div class="empty-state"><div class="empty-state-text">No notifications</div></div>'
      : notifs.map(n => `<div class="cmd-item" style="${n.read ? 'opacity:0.5;' : ''}">
          <span class="cmd-item-icon">${n.type === 'warning' ? '⚠️' : n.type === 'success' ? '✅' : n.type === 'error' ? '❌' : 'ℹ️'}</span>
          <div class="cmd-item-text"><strong>${n.title}</strong><br><span style="font-size:0.8rem;color:var(--text3)">${n.message}</span></div>
        </div>`).join('');
  } catch(e) {}
}

async function markAllRead() {
  await fetch('/api/notifications/read-all', { method: 'POST' });
  loadNotifications();
}

/* ═══════════════════════════════════════════════════════════════
   THEME SWITCHER
   ═══════════════════════════════════════════════════════════════ */

function openThemeSwitcher() { $('themeOverlay').classList.add('open'); }
function closeThemeSwitcher() { $('themeOverlay').classList.remove('open'); }

/* ═══════════════════════════════════════════════════════════════
   KEYBOARD SHORTCUTS
   ═══════════════════════════════════════════════════════════════ */

document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); openSearch(); }
  if (e.key === 'Escape') { closeSearch(); closeNotifications(); }
});

/* ═══════════════════════════════════════════════════════════════
   LOADING SCREEN
   ═══════════════════════════════════════════════════════════════ */

function hideLoading() {
  setTimeout(() => $('loadingScreen').classList.add('hidden'), 500);
}

/* ═══════════════════════════════════════════════════════════════
   DASHBOARD
   ═══════════════════════════════════════════════════════════════ */

async function loadDashboard() {
  try {
    const resp = await fetch('/api/stats');
    state.stats = await resp.json();
    renderDashboardStats();
    renderTrafficChart();
    renderSysChart();
  } catch(e) {}
}

function renderDashboardStats() {
  const s = state.stats;
  const cards = [
    { icon: '🔗', label: 'Active Connections', value: s.active_connections || 0, sub: `${s.users_count || 0} total users` },
    { icon: '📡', label: 'Traffic Today', value: s.today_traffic_fmt || '0B', sub: `${s.total_requests || 0} requests` },
    { icon: '📊', label: 'Total Traffic', value: s.total_traffic_fmt || '0B', sub: `Uptime: ${s.uptime || '00:00:00'}` },
    { icon: '👥', label: 'Active Users', value: s.active_users || 0, sub: `${s.disabled_users || 0} disabled` },
    { icon: '💻', label: 'CPU', value: s.cpu_percent != null ? `${s.cpu_percent.toFixed(1)}%` : 'N/A', sub: `RAM: ${s.memory_percent != null ? s.memory_percent.toFixed(0) + '%' : 'N/A'}` },
    { icon: '💾', label: 'Storage', value: s.disk_percent != null ? `${s.disk_percent.toFixed(0)}%` : 'N/A', sub: `${s.disk_free_gb || 0}GB free` },
  ];
  $('dashboardStats').innerHTML = cards.map(c => `
    <div class="stat-card animate-fadeIn">
      <div class="stat-icon">${c.icon}</div>
      <div class="stat-label">${c.label}</div>
      <div class="stat-value">${c.value}</div>
      <div class="stat-sub">${c.sub}</div>
    </div>
  `).join('');
}

function renderTrafficChart() {
  const labels = state.stats.hourly_labels || [];
  const values = labels.map(h => state.stats.hourly_traffic?.[h] || 0);
  const ctx = $('trafficCanvas')?.getContext('2d');
  if (!ctx) return;
  if (state.chartInstance) state.chartInstance.destroy();
  const isDark = getTheme() !== 'pure-white';
  state.chartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Traffic (bytes)',
        data: values,
        backgroundColor: 'var(--primary-dim)',
        borderColor: 'var(--chart-line)',
        borderWidth: 1,
        borderRadius: 4,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'var(--chart-grid)' }, ticks: { color: 'var(--text3)', font: { size: 10 } } },
        y: { grid: { color: 'var(--chart-grid)' }, ticks: { color: 'var(--text3)', font: { size: 10 }, callback: v => v > 1073741824 ? (v/1073741824).toFixed(1)+'GB' : v > 1048576 ? (v/1048576).toFixed(0)+'MB' : v > 1024 ? (v/1024).toFixed(0)+'KB' : v+'B' } }
      }
    }
  });
}

function renderSysChart() {
  const ctx = $('sysCanvas')?.getContext('2d');
  if (!ctx) return;
  if (state.sysChart) state.sysChart.destroy();
  const s = state.stats;
  state.sysChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['CPU', 'RAM', 'Storage Used', 'Free'],
      datasets: [{
        data: [
          s.cpu_percent || 0,
          s.memory_percent || 0,
          s.disk_percent || 0,
          s.disk_percent != null ? 100 - s.disk_percent : 0
        ],
        backgroundColor: ['#6366f1', '#10b981', '#f59e0b', '#e2e4f0'],
        borderWidth: 0,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { color: 'var(--text3)', padding: 16 } } },
      cutout: '60%',
    }
  });
}

/* ═══════════════════════════════════════════════════════════════
   USERS
   ═══════════════════════════════════════════════════════════════ */

async function loadUsers() {
  try {
    const resp = await fetch('/api/users');
    const data = await resp.json();
    state.users = data.users || [];
    renderUsersTable();
  } catch(e) {}
}

function renderUsersTable() {
  const tbody = $('usersTableBody');
  if (!state.users.length) {
    tbody.innerHTML = '<tr><td colspan="8"><div class="empty-state"><div class="empty-state-icon">👤</div><div class="empty-state-text">No users yet</div></div></td></tr>';
    return;
  }
  tbody.innerHTML = state.users.map(u => {
    const used = u.used_bytes || 0;
    const limit = u.limit_bytes || 0;
    const pct = limit > 0 ? Math.min(100, (used / limit * 100)).toFixed(0) : 0;
    const expired = u.expires_at && new Date(u.expires_at) < new Date();
    const status = u.active ? (expired ? 'Expired' : 'Active') : 'Disabled';
    const statusClass = u.active ? (expired ? 'badge-warning' : 'badge-active') : 'badge-inactive';
    return `<tr>
      <td><input type="checkbox" class="user-select" data-uid="${u.uuid}" onchange="updateBatchActions()"></td>
      <td><strong>${u.username}</strong><br><span style="font-size:0.75rem;color:var(--text3);">${u.uuid.slice(0,8)}...</span></td>
      <td>
        <div style="display:flex;align-items:center;gap:8px;">
          <span style="font-size:0.8rem;font-weight:600;">${_fmtBytes(used)}</span>
          <div class="progress-bar" style="flex:1;min-width:60px;"><div class="progress-fill" style="width:${pct}%;"></div></div>
        </div>
      </td>
      <td>${limit > 0 ? _fmtBytes(limit) : '∞'}</td>
      <td>${u.current_connections || 0}${u.max_connections > 0 ? `/${u.max_connections}` : ''}</td>
      <td><span class="badge ${statusClass}">${status}</span></td>
      <td style="font-size:0.8rem;">${u.expires_at ? new Date(u.expires_at).toLocaleDateString() : 'Never'}</td>
      <td>
        <div style="display:flex;gap:4px;">
          <button class="btn btn-xs btn-ghost" onclick="showUserDetail('${u.uuid}')" data-tooltip="Details">👁️</button>
          <button class="btn btn-xs btn-ghost" onclick="editUser('${u.uuid}')" data-tooltip="Edit">✏️</button>
          <button class="btn btn-xs btn-ghost" onclick="toggleUser('${u.uuid}')" data-tooltip="Toggle">${u.active ? '🔴' : '🟢'}</button>
          <button class="btn btn-xs btn-ghost" onclick="cloneUser('${u.uuid}')" data-tooltip="Clone">📋</button>
          <button class="btn btn-xs btn-danger" onclick="deleteUser('${u.uuid}')" data-tooltip="Delete">🗑️</button>
        </div>
      </td>
    </tr>`;
  }).join('');
}

function updateBatchActions() {
  const selected = document.querySelectorAll('.user-select:checked');
  // Could add batch action bar here
}

function toggleSelectAll(checkbox) {
  document.querySelectorAll('.user-select').forEach(c => c.checked = checkbox.checked);
  updateBatchActions();
}

async function toggleUser(uid) {
  const user = state.users.find(u => u.uuid === uid);
  if (!user) return;
  try {
    await fetch(`/api/users/${uid}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ active: !user.active })
    });
    showToast('User Updated', `${user.username} is now ${user.active ? 'disabled' : 'active'}`, user.active ? 'warning' : 'success');
    loadUsers();
  } catch(e) {}
}

async function deleteUser(uid) {
  const user = state.users.find(u => u.uuid === uid);
  if (!user || !confirm(`Delete user "${user.username}"?`)) return;
  try {
    await fetch(`/api/users/${uid}`, { method: 'DELETE' });
    showToast('User Deleted', `${user.username} deleted`, 'error');
    loadUsers();
  } catch(e) {}
}

async function cloneUser(uid) {
  try {
    const resp = await fetch(`/api/users/${uid}/clone`, { method: 'POST' });
    if (resp.ok) { showToast('User Cloned', 'User duplicated successfully', 'success'); loadUsers(); }
  } catch(e) {}
}

async function exportUsers() {
  try {
    const resp = await fetch('/api/export-users');
    const data = await resp.json();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'best-panel-users.json'; a.click();
    URL.revokeObjectURL(url);
  } catch(e) {}
}

function _fmtBytes(b) {
  if (!b) return '0B';
  if (b >= 1073741824) return (b/1073741824).toFixed(1)+'GB';
  if (b >= 1048576) return (b/1048576).toFixed(1)+'MB';
  if (b >= 1024) return (b/1024).toFixed(0)+'KB';
  return b+'B';
}

/* ── Create User ── */
function openCreateUser() { openModal('createUserModal'); }

async function createUser() {
  const body = {
    username: $('cuUsername').value,
    password: $('cuPassword').value,
    limit_value: $('cuUnlimited').classList.contains('on') ? 0 : parseFloat($('cuLimitVal').value || 0),
    limit_unit: $('cuLimitUnit').value,
    days_valid: parseInt($('cuDays').value || 0),
    max_connections: parseInt($('cuMaxConn').value || 0),
    max_devices: parseInt($('cuMaxDev').value || 0),
    priority: parseInt($('cuPriority').value || 0),
    tags: $('cuTags').value,
    notes: $('cuNotes').value,
    color: $('cuColor').value,
    flag: $('cuFlag').value,
    custom_path: $('cuPath').value,
    custom_sni: $('cuSni').value,
    custom_host: $('cuHost').value,
    custom_fp: $('cuFp').value,
    fragment: $('cuFragment').value,
  };
  if (!body.username) { showToast('Error', 'Username is required', 'error'); return; }
  try {
    const resp = await fetch('/api/users', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    });
    if (resp.ok) {
      showToast('Success', `User "${body.username}" created`, 'success');
      closeModal('createUserModal');
      // Clear form
      ['cuUsername','cuPassword','cuLimitVal','cuDays','cuMaxConn','cuMaxDev','cuPriority','cuTags','cuNotes','cuFlag','cuPath','cuSni','cuHost','cuFragment'].forEach(id => $(id).value = '');
      $('cuUnlimited').classList.remove('on');
      $('cuColor').value = '#6366f1';
      $('cuFp').value = 'chrome';
      loadUsers();
    } else {
      const err = await resp.json();
      showToast('Error', err.detail || 'Failed to create user', 'error');
    }
  } catch(e) { showToast('Error', 'Connection error', 'error'); }
}

/* ── User Detail ── */
async function showUserDetail(uid) {
  try {
    const resp = await fetch(`/api/users/${uid}`);
    const user = await resp.json();
    const extra = user.custom_path || user.custom_sni || user.custom_host ? 'Yes' : 'Default';
    const expires = user.expires_at ? new Date(user.expires_at).toLocaleDateString() : 'Never';
    const remaining = user.expires_at ? Math.max(0, Math.ceil((new Date(user.expires_at) - new Date()) / 86400000)) : '∞';
    $('userDetailTitle').textContent = user.username;
    $('userDetailBody').innerHTML = `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
        <div><strong>UUID:</strong><br><span style="font-size:0.8rem;word-break:break-all;">${user.uid}</span></div>
        <div><strong>Status:</strong><br><span class="badge ${user.active ? 'badge-active' : 'badge-inactive'}">${user.active ? 'Active' : 'Inactive'}</span></div>
        <div><strong>Traffic Used:</strong><br>${_fmtBytes(user.used_bytes || 0)}</div>
        <div><strong>Traffic Limit:</strong><br>${user.limit_bytes > 0 ? _fmtBytes(user.limit_bytes) : '∞'}</div>
        <div><strong>Upload:</strong><br>${_fmtBytes(user.upload_bytes || 0)}</div>
        <div><strong>Download:</strong><br>${_fmtBytes(user.download_bytes || 0)}</div>
        <div><strong>Connections:</strong><br>${user.current_connections || 0}${user.max_connections > 0 ? ` / ${user.max_connections}` : ''}</div>
        <div><strong>Expires:</strong><br>${expires} (${remaining}d remaining)</div>
        <div style="grid-column:span 2;"><strong>Subscription:</strong><br>
          <a href="${user.subscription_url || '#'}" target="_blank" style="color:var(--primary);font-size:0.85rem;">${user.subscription_url || 'N/A'}</a>
        </div>
        <div style="grid-column:span 2;"><strong>VLESS Link:</strong><br>
          <div style="font-size:0.75rem;word-break:break-all;color:var(--text2);">${user.vless_link || 'N/A'}</div>
        </div>
        <div><strong>Notes:</strong><br>${user.notes || '—'}</div>
        <div><strong>Tags:</strong><br>${user.tags || '—'}</div>
        <div><strong>Custom Path:</strong><br>${user.custom_path || 'Default'}</div>
        <div><strong>Custom SNI:</strong><br>${user.custom_sni || 'Default'}</div>
      </div>
      <div style="display:flex;gap:8px;margin-top:20px;justify-content:flex-end;">
        <button class="btn btn-secondary btn-sm" onclick="closeModal('userDetailModal')">Close</button>
        <button class="btn btn-primary btn-sm" onclick="closeModal('userDetailModal');editUser('${user.uid}')">Edit</button>
      </div>
    `;
    openModal('userDetailModal');
  } catch(e) {}
}

/* ── Edit User (simplified) ── */
async function editUser(uid) {
  const user = state.users.find(u => u.uuid === uid);
  if (!user) return;
  const newLimit = prompt('New traffic limit (GB, 0 = unlimited):', user.limit_bytes > 0 ? (user.limit_bytes / 1073741824).toFixed(0) : '0');
  if (newLimit === null) return;
  const newDays = prompt('New expire days (0 = never):', '30');
  if (newDays === null) return;
  try {
    await fetch(`/api/users/${uid}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ limit_value: parseFloat(newLimit) || 0, limit_unit: 'GB', days_valid: parseInt(newDays) || 0 })
    });
    showToast('Updated', 'User updated successfully', 'success');
    loadUsers();
  } catch(e) {}
}

/* ═══════════════════════════════════════════════════════════════
   LIVE MONITOR (WebSocket)
   ═══════════════════════════════════════════════════════════════ */

function startMonitor() {
  if (state.monitorWs) { state.monitorWs.close(); }
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  state.monitorWs = new WebSocket(`${proto}//${location.host}/ws/monitor`);
  state.monitorWs.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (data.type === 'connections') {
      $('connCount').textContent = data.connections || 0;
      state.connections = data.connection_list || [];
      renderMonitorTable();
    }
  };
  state.monitorWs.onclose = () => {
    $('monitorStatus').className = 'badge badge-inactive';
    $('monitorStatus').textContent = '● Disconnected';
    setTimeout(startMonitor, 3000);
  };
}

function renderMonitorTable() {
  const tbody = $('monitorTableBody');
  if (!state.connections.length) {
    tbody.innerHTML = '<tr><td colspan="7"><div class="empty-state"><div class="empty-state-text">No active connections</div></div></td></tr>';
    return;
  }
  tbody.innerHTML = state.connections.map(c => {
    const dur = c.duration || 0;
    const h = Math.floor(dur / 3600), m = Math.floor((dur % 3600) / 60), s = dur % 60;
    const durStr = h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${s}s` : `${s}s`;
    const loc = [c.country, c.city].filter(Boolean).join(', ') || 'Unknown';
    return `<tr>
      <td><strong>${c.username || 'Unknown'}</strong></td>
      <td style="font-size:0.8rem;">${c.ip}</td>
      <td style="font-size:0.8rem;">${loc}</td>
      <td class="live-timer">${durStr}</td>
      <td style="font-size:0.8rem;">${_fmtBytes(c.upload || 0)}</td>
      <td style="font-size:0.8rem;">${_fmtBytes(c.download || 0)}</td>
      <td><span class="ping-dot good"></span>Active</td>
    </tr>`;
  }).join('');
}

/* ═══════════════════════════════════════════════════════════════
   ANALYTICS
   ═══════════════════════════════════════════════════════════════ */

async function loadAnalytics() {
  try {
    const resp = await fetch('/api/analytics');
    const data = await resp.json();
    renderAnalyticsChart(data.daily_traffic || {});
    renderAnalyticsSidebar(data);
  } catch(e) {}
}

function renderAnalyticsChart(dailyTraffic) {
  const ctx = $('analyticsCanvas')?.getContext('2d');
  if (!ctx) return;
  if (state.analyticsChart) state.analyticsChart.destroy();
  const labels = Object.keys(dailyTraffic).slice(-30);
  const values = labels.map(l => dailyTraffic[l] || 0);
  state.analyticsChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Daily Traffic',
        data: values,
        borderColor: 'var(--chart-line)',
        backgroundColor: 'var(--primary-dim)',
        fill: true,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 6,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'var(--chart-grid)' }, ticks: { color: 'var(--text3)', font: { size: 10 }, maxTicksLimit: 10 } },
        y: { grid: { color: 'var(--chart-grid)' }, ticks: { color: 'var(--text3)', font: { size: 10 }, callback: v => v > 1073741824 ? (v/1073741824).toFixed(1)+'GB' : v > 1048576 ? (v/1048576).toFixed(0)+'MB' : v+'B' } }
      }
    }
  });
}

function renderAnalyticsSidebar(data) {
  $('topUsersList').innerHTML = (data.top_users || []).slice(0, 10).map((u, i) =>
    `<div class="rank-row"><span style="width:24px;font-weight:700;color:var(--text3);">${i+1}.</span>
     <span style="flex:1;">${u.username}</span>
     <span style="font-weight:600;">${_fmtBytes(u.used_bytes || 0)}</span></div>`
  ).join('') || '<div class="empty-state-text">No data</div>';

  const countries = data.countries || {};
  const sorted = Object.entries(countries).sort((a,b) => b[1] - a[1]);
  $('countriesList').innerHTML = sorted.map(([c, n]) =>
    `<div class="rank-row"><span style="flex:1;">${c || 'Unknown'}</span><span style="font-weight:600;">${n}</span></div>`
  ).join('') || '<div class="empty-state-text">No connection data</div>';
}

/* ═══════════════════════════════════════════════════════════════
   RANKINGS
   ═══════════════════════════════════════════════════════════════ */

async function loadRankings() {
  try {
    const resp = await fetch('/api/rankings');
    const data = await resp.json();
    renderRanking('rankTraffic', data.by_traffic || [], '📊');
    renderRanking('rankUpload', data.by_upload || [], '⬆️');
    renderRanking('rankDownload', data.by_download || [], '⬇️');
    renderRanking('rankSessions', data.by_sessions || [], '🔗');
  } catch(e) {}
}

function renderRanking(id, items, icon) {
  const medals = ['🥇', '🥈', '🥉'];
  const html = items.slice(0, 10).map((r, i) =>
    `<div class="rank-row">
      <span class="rank-medal">${medals[i] || `${i+1}.`}</span>
      <span style="flex:1;font-weight:600;">${r.username}</span>
      <span style="font-size:0.85rem;color:var(--text2);">${r.value_fmt || r.value}</span>
    </div>`
  ).join('') || '<div class="empty-state-text">No data</div>';
  $(id).innerHTML = html;
}

/* ═══════════════════════════════════════════════════════════════
   LOGS
   ═══════════════════════════════════════════════════════════════ */

async function loadLogs() {
  try {
    const resp = await fetch('/api/logs');
    const data = await resp.json();
    state.logs = data.logs || [];
    renderLogs();
  } catch(e) {}
}

function renderLogs() {
  $('logsTableBody').innerHTML = state.logs.slice(0, 100).map(l =>
    `<tr>
      <td style="font-size:0.75rem;white-space:nowrap;">${l.time ? new Date(l.time).toLocaleString() : ''}</td>
      <td><span class="badge badge-active" style="font-size:0.65rem;">${l.type || '—'}</span></td>
      <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;">${l.error || '—'}</td>
      <td style="font-size:0.75rem;">${l.ip || '—'}</td>
    </tr>`
  ).join('') || '<tr><td colspan="4"><div class="empty-state"><div class="empty-state-text">No logs</div></div></td></tr>';
}

async function clearLogs() {
  if (!confirm('Clear all logs?')) return;
  await fetch('/api/logs/clear', { method: 'DELETE' });
  showToast('Cleared', 'All logs cleared', 'success');
  loadLogs();
}

/* ═══════════════════════════════════════════════════════════════
   ADDRESSES
   ═══════════════════════════════════════════════════════════════ */

async function loadAddresses() {
  try {
    const resp = await fetch('/api/addresses');
    const data = await resp.json();
    state.addresses = data.addresses || [];
    renderAddresses();
  } catch(e) {}
}

function renderAddresses() {
  $('addressesTableBody').innerHTML = state.addresses.map((a, i) =>
    `<tr>
      <td style="color:var(--text3);font-weight:600;">${i+1}</td>
      <td><code style="font-size:0.85rem;">${a}</code></td>
      <td><button class="btn btn-xs btn-danger" onclick="deleteAddress(${i})">Delete</button></td>
    </tr>`
  ).join('') || '<tr><td colspan="3"><div class="empty-state-text">No addresses</div></td></tr>';
}

async function addAddress() {
  const addr = prompt('Enter IP address or domain:');
  if (!addr) return;
  try {
    const resp = await fetch('/api/addresses', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address: addr })
    });
    if (resp.ok) { showToast('Added', 'Address added', 'success'); loadAddresses(); }
    else { const d = await resp.json(); showToast('Error', d.detail || 'Failed', 'error'); }
  } catch(e) {}
}

async function deleteAddress(index) {
  try {
    await fetch(`/api/addresses/${index}`, { method: 'DELETE' });
    loadAddresses();
  } catch(e) {}
}

/* ═══════════════════════════════════════════════════════════════
   SETTINGS
   ═══════════════════════════════════════════════════════════════ */

async function loadSettings() {
  try {
    const resp = await fetch('/api/settings');
    state.settings = await resp.json();
    renderSettingsForm();
    // Highlight current theme
    const currentTheme = getTheme();
    document.querySelectorAll('.theme-card').forEach(c => c.classList.toggle('active', c.dataset.themeName === currentTheme));
  } catch(e) {}
}

function renderSettingsForm() {
  const s = state.settings;
  const fields = [
    { key: 'tg_bot_token', label: 'Telegram Bot Token', type: 'password' },
    { key: 'tg_chat_id', label: 'Telegram Chat ID', type: 'text' },
    { key: 'footer_text', label: 'Footer Text', type: 'text' },
    { key: 'monthly_limit_gb', label: 'Monthly Traffic Limit (GB)', type: 'number' },
    { key: 'keep_alive_enabled', label: 'Keep Alive Enabled', type: 'toggle' },
    { key: 'keep_alive_interval', label: 'Keep Alive Interval (seconds)', type: 'number' },
    { key: 'timezone_offset', label: 'Timezone Offset (hours)', type: 'number' },
    { key: 'auto_disable_enabled', label: 'Auto Disable Expired', type: 'toggle' },
    { key: 'telegram_report_enabled', label: 'Telegram Reports', type: 'toggle' },
    { key: 'telegram_notify_enabled', label: 'Telegram Notifications', type: 'toggle' },
    { key: 'telegram_interval', label: 'Report Interval (hours)', type: 'number' },
  ];
  $('settingsForm').innerHTML = fields.map(f => {
    if (f.type === 'toggle') {
      const val = s[f.key] === '1';
      return `<div class="sl-item">
        <span class="sl-k">${f.label}</span>
        <div class="toggle ${val ? 'on' : ''}" id="setting_${f.key}" onclick="this.classList.toggle('on')" data-key="${f.key}"></div>
      </div>`;
    }
    return `<div class="form-group">
      <label class="form-label">${f.label}</label>
      <input class="form-input" id="setting_${f.key}" type="${f.type}" value="${s[f.key] || ''}" data-key="${f.key}">
    </div>`;
  }).join('');
}

async function savePanelSettings() {
  const body = {};
  document.querySelectorAll('[data-key]').forEach(el => {
    const key = el.dataset.key;
    if (el.classList.contains('toggle')) {
      body[key] = el.classList.contains('on') ? '1' : '0';
    } else {
      body[key] = el.value;
    }
  });
  try {
    await fetch('/api/settings', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    });
    showToast('Saved', 'Settings saved successfully', 'success');
  } catch(e) { showToast('Error', 'Failed to save settings', 'error'); }
}

/* ═══════════════════════════════════════════════════════════════
   PARTICLE BACKGROUND (login)
   ═══════════════════════════════════════════════════════════════ */

function createParticles() {
  const container = $('loginParticles');
  for (let i = 0; i < 40; i++) {
    const p = document.createElement('div');
    p.className = 'particle';
    p.style.left = Math.random() * 100 + '%';
    p.style.top = Math.random() * 100 + '%';
    p.style.animationDelay = Math.random() * 4 + 's';
    p.style.animationDuration = (3 + Math.random() * 3) + 's';
    p.style.width = (2 + Math.random() * 4) + 'px';
    p.style.height = p.style.width;
    container.appendChild(p);
  }
}

/* ═══════════════════════════════════════════════════════════════
   INIT
   ═══════════════════════════════════════════════════════════════ */

function initApp() {
  hideLoading();
  $('loginDomain').textContent = `📍 ${location.host}`;
  loadDashboard();
  loadNotifications();
  // Periodic dashboard refresh
  setInterval(() => {
    if ($('pageDashboard').classList.contains('active')) loadDashboard();
  }, 60000);
  // Periodic notifications
  setInterval(loadNotifications, 30000);
}

// Check if already authenticated
checkAuth();

// Create particles on login
createParticles();

</script>
</body>
</html>"""

# ═══════════════════════════════════════════════════════════════
#  SUBSCRIPTION / USER PAGE
# ═══════════════════════════════════════════════════════════════

@app.get("/user/{uid}")
async def user_dashboard(uid: str, request: Request):
    async with USERS_LOCK:
        user = USERS.get(uid)
        if not user or not user["active"]:
            raise HTTPException(status_code=404, detail="User not found or disabled")
        user = dict(user)
    expires = parse_expires_at(user.get("expires_at"))
    if expires and expires < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="User expired")
    status = "Active"
    if user.get("limit_bytes", 0) > 0 and user["used_bytes"] >= user["limit_bytes"]:
        status = "Quota Exceeded"
    elif expires and expires < datetime.now(timezone.utc):
        status = "Expired"
    elif not user["active"]:
        status = "Blocked"
    used = user["used_bytes"]; limit = user["limit_bytes"]
    usage_pct = 0 if limit == 0 else min(100, round(used / limit * 100, 1))
    bar_color = "#4ade80" if usage_pct < 80 else ("#fbbf24" if usage_pct < 95 else "#f87171")
    vless_link = generate_vless_link(uid, remark=user["username"])
    sub_url = f"https://{get_domain()}/sub/{uid}"
    qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=250x250&data={quote(sub_url)}"
    expiry_str = "Unlimited" if not expires else expires.strftime("%Y-%m-%d %H:%M (UTC)")
    remaining_days = "∞"
    if expires:
        rem = (expires - datetime.now(timezone.utc)).days
        remaining_days = str(max(0, rem))
    upload = user.get("upload_bytes", 0); download = user.get("download_bytes", 0)
    remaining_traffic = "∞" if limit == 0 else _fmt_bytes(max(0, limit - used))

    return HTMLResponse(content=f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{user['username']} — Best Panel</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;800;900&display=swap" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Inter',sans-serif;background:#0b0d15;color:#e2e4f0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;
  background-image:radial-gradient(ellipse at top,rgba(99,102,241,0.08),transparent 60%),radial-gradient(ellipse at bottom,rgba(139,92,246,0.05),transparent 60%);}}
.card{{background:rgba(17,19,30,0.8);border:1px solid rgba(99,102,241,0.12);border-radius:24px;padding:36px 28px;max-width:440px;width:100%;
  backdrop-filter:blur(24px);box-shadow:0 8px 40px rgba(0,0,0,0.4);animation:scaleIn 0.5s ease;}}
@keyframes scaleIn{{from{{opacity:0;transform:scale(0.95)}}to{{opacity:1;transform:none}}}}
@keyframes countUp{{from{{opacity:0;transform:translateY(10px)}}to{{opacity:1;transform:none}}}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:0.5}}}}
.header{{text-align:center;margin-bottom:28px;}}
.avatar{{width:64px;height:64px;border-radius:16px;background:linear-gradient(135deg,#6366f1,#8b5cf6);display:flex;align-items:center;justify-content:center;font-size:1.8rem;font-weight:900;color:white;margin:0 auto 12px;box-shadow:0 0 30px rgba(99,102,241,0.3);}}
h1{{font-size:1.5rem;font-weight:800;background:linear-gradient(135deg,#6366f1,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}}
.status{{display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:20px;font-size:0.8rem;font-weight:700;margin-top:8px;}}
.status-active{{background:rgba(52,211,153,0.1);color:#34d399;border:1px solid rgba(52,211,153,0.2);}}
.status-exceeded{{background:rgba(248,113,113,0.1);color:#f87171;border:1px solid rgba(248,113,113,0.2);}}
.info-grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px;}}
.info-item{{background:rgba(30,34,54,0.5);border-radius:12px;padding:14px;text-align:center;}}
.info-label{{font-size:0.7rem;color:#5c6080;font-weight:700;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:4px;}}
.info-value{{font-size:1.1rem;font-weight:800;}}
.progress-ring-container{{display:flex;justify-content:center;margin-bottom:20px;}}
.progress-ring{{width:160px;height:160px;position:relative;}}
.progress-ring svg{{transform:rotate(-90deg);}}
.progress-ring-bg{{fill:none;stroke:rgba(255,255,255,0.06);stroke-width:8;}}
.progress-ring-fill{{fill:none;stroke:url(#grad);stroke-width:8;stroke-linecap:round;transition:stroke-dashoffset 1s ease;}}
.progress-ring-text{{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;}}
.progress-ring-pct{{font-size:1.8rem;font-weight:900;}}
.progress-ring-label{{font-size:0.7rem;color:#5c6080;}}
.qr-section{{text-align:center;margin-bottom:20px;}}
.qr-section img{{border-radius:12px;background:white;padding:8px;}}
.btn{{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;padding:12px;border-radius:12px;font-size:0.9rem;font-weight:700;font-family:inherit;cursor:pointer;border:none;transition:all 0.25s;margin-bottom:10px;}}
.btn-primary{{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:white;box-shadow:0 2px 10px rgba(99,102,241,0.3);}}
.btn-primary:hover{{transform:translateY(-2px);box-shadow:0 0 20px rgba(99,102,241,0.4);}}
.btn-secondary{{background:rgba(30,34,54,0.8);color:#e2e4f0;border:1px solid rgba(99,102,241,0.15);}}
.btn-secondary:hover{{border-color:rgba(99,102,241,0.3);}}
.timer{{font-variant-numeric:tabular-nums;font-weight:700;color:#6366f1;}}
#toast{{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#6366f1;color:white;padding:10px 20px;border-radius:30px;font-weight:700;opacity:0;transition:opacity 0.3s;pointer-events:none;z-index:100;}}
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <div class="avatar">{user['username'][0].upper()}</div>
    <h1>{user['username']}</h1>
    <span class="status status-{'active' if status == 'Active' else 'exceeded'}">{status}</span>
  </div>
  <div class="progress-ring-container">
    <div class="progress-ring">
      <svg width="160" height="160">
        <defs><linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#6366f1"/><stop offset="100%" stop-color="#8b5cf6"/></linearGradient></defs>
        <circle class="progress-ring-bg" cx="80" cy="80" r="68"/>
        <circle class="progress-ring-fill" id="progressCircle" cx="80" cy="80" r="68" stroke-dasharray="427.26" stroke-dashoffset="427.26"/>
      </svg>
      <div class="progress-ring-text">
        <div class="progress-ring-pct" id="usagePct">{usage_pct}%</div>
        <div class="progress-ring-label">Used</div>
      </div>
    </div>
  </div>
  <div class="info-grid">
    <div class="info-item"><div class="info-label">Download</div><div class="info-value" style="color:#34d399;">{_fmt_bytes(download)}</div></div>
    <div class="info-item"><div class="info-label">Upload</div><div class="info-value" style="color:#818cf8;">{_fmt_bytes(upload)}</div></div>
    <div class="info-item"><div class="info-label">Remaining</div><div class="info-value" style="color:#fbbf24;">{remaining_traffic}</div></div>
    <div class="info-item"><div class="info-label">Expires</div><div class="info-value" style="font-size:0.9rem;">{expiry_str}</div></div>
  </div>
  <div class="qr-section">
    <img src="{qr_url}" alt="QR Code" width="180" height="180">
  </div>
  <button class="btn btn-primary" onclick="copyText('{sub_url}', 'Subscription link copied!')">🔗 Copy Subscription</button>
  <button class="btn btn-secondary" onclick="copyText('{vless_link}', 'VLESS link copied!')">📋 Copy VLESS Config</button>
</div>
<div id="toast">Copied!</div>
<script>
setTimeout(() => {{
  const circle = document.getElementById('progressCircle');
  const circumference = 427.26;
  const offset = circumference - (circumference * {usage_pct} / 100);
  circle.style.strokeDashoffset = offset;
}}, 100);
function copyText(text, msg) {{
  navigator.clipboard.writeText(text).then(() => {{
    const t = document.getElementById('toast'); t.textContent = msg;
    t.style.opacity = '1'; setTimeout(() => t.style.opacity = '0', 2500);
  }});
}}
</script>
</body>
</html>""")

@app.get("/user/{uid}/sub")
@limiter.limit("10/minute")
async def user_subscription(uid: str, request: Request):
    async with USERS_LOCK:
        user = USERS.get(uid)
        if not user or not user["active"]:
            raise HTTPException(status_code=404, detail="User not found or disabled")
        user = dict(user)
    expires = parse_expires_at(user.get("expires_at"))
    if expires and expires < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="User expired")
    status = "active"
    if user.get("limit_bytes", 0) > 0 and user["used_bytes"] >= user["limit_bytes"]:
        status = "quota_exceeded"
    elif expires and expires < datetime.now(timezone.utc):
        status = "expired"
    elif not user["active"]:
        status = "blocked"
    async with CUSTOM_ADDRESSES_LOCK:
        addresses = list(CUSTOM_ADDRESSES)
    extra = {
        "custom_path": user.get("custom_path", ""), "custom_sni": user.get("custom_sni", ""),
        "custom_host": user.get("custom_host", ""), "custom_fp": user.get("custom_fp", "chrome"),
        "fragment": user.get("fragment", ""),
    }
    sub_content = _generate_sub_content(user, uid, addresses, extra, status)
    encoded = base64.b64encode(sub_content.encode()).decode()
    total_bytes = user["limit_bytes"] if user["limit_bytes"] > 0 else UNLIMITED_QUOTA_BYTES
    expire_ts = int(expires.timestamp()) if expires else 0
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": 'attachment; filename="sub.txt"',
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={user['used_bytes']}; download=0; total={total_bytes}; expire={expire_ts}",
        "X-Status": status,
    }
    return Response(content=encoded, headers=headers)

@app.get("/sub/{uid}")
@limiter.limit("10/minute")
async def subscription_endpoint(uid: str, request: Request):
    return await user_subscription(uid, request)

def _generate_sub_content(user: dict, uid: str, addresses: list, extra: dict = None, status: str = "active") -> str:
    used = user["used_bytes"]; limit = user["limit_bytes"]
    usage_str = f"{_fmt_bytes(used)} / ∞" if limit == 0 else f"{_fmt_bytes(used)} / {_fmt_bytes(limit)}"
    secs_left = seconds_until_expiry(user.get("expires_at"))
    expiry_str = "∞" if secs_left is None else ("Expired" if secs_left == 0 else f"{secs_left//86400} Days Left")
    status_remark = ""
    if status == "quota_exceeded": status_remark = "🚫 Quota Exceeded"
    elif status == "expired": status_remark = "⏰ Expired"
    elif status == "blocked": status_remark = "🔒 Blocked"
    full_remark = f"📊 {usage_str} | ⏳ {expiry_str}"
    if status_remark: full_remark += f" | {status_remark}"
    flag_emoji = code_to_flag(user.get("flag", ""))
    if flag_emoji: full_remark = flag_emoji + " " + full_remark
    status_node = generate_vless_link(uid, remark=full_remark, address="0.0.0.0", extra=extra)
    server_node = generate_vless_link(uid, remark="Best Panel", extra=extra)
    links = [status_node, server_node]
    for i, addr in enumerate(addresses):
        links.append(generate_vless_link(uid, remark=f"Best-IP{i+1}", address=addr, extra=extra))
    return "\n".join(links)

# ═══════════════════════════════════════════════════════════════
#  FRONTEND ROUTE — Serve the embedded HTML
# ═══════════════════════════════════════════════════════════════

@app.get("/panel")
@app.get("/login")
@app.get("/dashboard")
@app.get("/monitor")
@app.get("/analytics")
@app.get("/rankings")
@app.get("/logs")
@app.get("/addresses")
@app.get("/settings")
async def serve_spa():
    return HTMLResponse(content=FRONTEND_HTML)

# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=CONFIG["port"], reload=False, log_level="info")
