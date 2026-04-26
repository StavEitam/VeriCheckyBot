import sqlite3
import json
import time
import os

DB_PATH = os.getenv("DB_PATH", "veri_cache.db")
TTL = 3600  # 1 hour default

_db: sqlite3.Connection | None = None


def _conn() -> sqlite3.Connection:
    global _db
    if _db is None:
        _db = sqlite3.connect(DB_PATH, check_same_thread=False)
    return _db


def init_db():
    _conn().execute("""
        CREATE TABLE IF NOT EXISTS cache (
            key        TEXT PRIMARY KEY,
            value      TEXT,
            expires_at INTEGER
        )
    """)
    _conn().commit()


def get(key: str):
    row = _conn().execute(
        "SELECT value, expires_at FROM cache WHERE key=?", (key,)
    ).fetchone()
    if row and row[1] > int(time.time()):
        return json.loads(row[0])
    return None


def set(key: str, value, ttl: int = TTL):
    _conn().execute(
        "INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?,?,?)",
        (key, json.dumps(value), int(time.time()) + ttl),
    )
    _conn().commit()
