"""
SQLite DB for known phishing URLs (OpenPhish feed).

Tables: phish_urls (url, source, created_at), feed_metadata (source, last_updated, urls_count).
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def get_connection(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS phish_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL UNIQUE,
            source TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_phish_urls_url ON phish_urls(url)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS feed_metadata (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            source TEXT NOT NULL,
            last_updated TEXT NOT NULL,
            urls_count INTEGER NOT NULL
        )
    """)
    conn.commit()


def replace_phish_urls(conn: sqlite3.Connection, source: str, urls: list[str]) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("DELETE FROM phish_urls WHERE source = ?", (source,))
    conn.executemany(
        "INSERT OR REPLACE INTO phish_urls (url, source, created_at) VALUES (?, ?, ?)",
        [(u, source, now) for u in urls],
    )
    conn.execute(
        """
        INSERT INTO feed_metadata (id, source, last_updated, urls_count) VALUES (1, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET source = ?, last_updated = ?, urls_count = ?
        """,
        (source, now, len(urls), source, now, len(urls)),
    )
    conn.commit()


def get_last_updated(conn: sqlite3.Connection) -> str | None:
    row = conn.execute(
        "SELECT last_updated FROM feed_metadata WHERE id = 1"
    ).fetchone()
    return row["last_updated"] if row else None


def lookup_urls(conn: sqlite3.Connection, urls: list[str]) -> list[tuple[str, str]]:
    """Return list of (url, source) for any url in urls that exists in phish_urls."""
    if not urls:
        return []
    placeholders = ",".join("?" * len(urls))
    rows = conn.execute(
        f"SELECT url, source FROM phish_urls WHERE url IN ({placeholders})",
        urls,
    ).fetchall()
    return [(r["url"], r["source"]) for r in rows]
