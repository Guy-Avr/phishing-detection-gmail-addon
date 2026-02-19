"""
OpenPhish Community Feed: fetch, normalize, store in phish DB, and lookup.

Uses same URL normalization as link_extractor so lookup matches ParsedEmail.links.
"""

import urllib.request
from typing import Optional

from app.core.constants import OPENPHISH_FEED_URL, PHISH_FEED_SOURCE
from app.database.phish_db import (
    get_connection,
    get_last_updated as db_get_last_updated,
    init_schema,
    lookup_urls as db_lookup_urls,
    replace_phish_urls,
)
from app.parsing.link_extractor import normalize_url


def fetch_feed(url: str = OPENPHISH_FEED_URL) -> list[str]:
    """Download feed and return list of raw URL strings (one per line)."""
    req = urllib.request.Request(url, headers={"User-Agent": "PhishingDetection/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    return [line.strip() for line in text.splitlines() if line.strip()]


def update_phish_db(db_path: str) -> tuple[int, str]:
    """
    Fetch OpenPhish feed, normalize URLs, replace phish_urls for source=openphish.
    Returns (urls_count, last_updated_iso).
    """
    raw_urls = fetch_feed()
    normalized: list[str] = []
    seen: set[str] = set()
    for u in raw_urls:
        n = normalize_url(u)
        if n and n not in seen:
            seen.add(n)
            normalized.append(n)

    conn = get_connection(db_path)
    init_schema(conn)
    replace_phish_urls(conn, PHISH_FEED_SOURCE, normalized)
    row = conn.execute(
        "SELECT last_updated, urls_count FROM feed_metadata WHERE id = 1"
    ).fetchone()
    conn.close()
    return (row["urls_count"], row["last_updated"]) if row else (0, "")


def get_last_updated(db_path: str) -> Optional[str]:
    """Return last_updated from feed_metadata or None if not yet updated."""
    conn = get_connection(db_path)
    init_schema(conn)
    out = db_get_last_updated(conn)
    conn.close()
    return out


def lookup_phish_urls(db_path: str, urls: list[str]) -> list[tuple[str, str]]:
    """
    Check which of the given (normalized) URLs are in the phish DB.
    Returns list of (url, source) for matches.
    """
    if not urls:
        return []
    conn = get_connection(db_path)
    init_schema(conn)
    matches = db_lookup_urls(conn, urls)
    conn.close()
    return matches
