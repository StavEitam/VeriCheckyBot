import sqlite3
import json
import time

DB_PATH = "veri_cache.db"
TTL = 3600  # 1 hour

def _conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    with _conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                value TEXT,
                expires_at INTEGER
            )
        """)

def get(key: str):
    with _conn() as c:
        row = c.execute("SELECT value, expires_at FROM cache WHERE key=?", (key,)).fetchone()
    if row and row[1] > int(time.time()):
        return json.loads(row[0])
    return None

def set(key: str, value, ttl: int = TTL):
    with _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?,?,?)",
            (key, json.dumps(value), int(time.time()) + ttl)
        )
