"""
Extract and normalize URLs from text and/or HTML.

- From text: urlextract (all common URL forms). Caller provides one string.
- From HTML: extract_href_urls(html) returns raw href values from <a> tags
  so anchor-only links are never missed. Same normalization/dedup via extract_links.
See: https://github.com/lipoja/URLExtract

Rules must not perform link extraction; they consume ParsedEmail only.
"""

import re
from urllib.parse import urlparse, urlunparse

from bs4 import BeautifulSoup
from urlextract import URLExtract

# href schemes we skip (not navigable links for phishing checks)
_HREF_SKIP_PREFIXES = ("mailto:", "javascript:", "data:", "#")

# Single instance: URLExtract caches TLD list; reuse for performance.
_url_extractor = URLExtract()


def _normalize_url(url: str) -> str:
    """
    Normalize a single URL for consistent comparison and deduplication.

    - Lowercase and strip whitespace.
    - Add https:// when no scheme (or fix protocol-relative //).
    - Remove fragment (#...) so same page with different anchors dedup.
    """
    url = url.strip().lower()
    if not url:
        return ""
    if url.startswith("//"):
        url = "https:" + url
    elif not re.match(r"^[a-z][a-z0-9+.-]*://", url):
        url = "https://" + url
    parsed = urlparse(url)
    normalized = urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, "")
    )
    return normalized.rstrip("/") or normalized


def normalize_url(url: str) -> str:
    """
    Public normalization for URLs. Use when storing or comparing URLs
    (e.g. phish feed DB) so format matches ParsedEmail.links.
    """
    return _normalize_url(url)


def extract_links(text: str) -> list[str]:
    """
    Extract all URLs from a single text string.

    The caller is responsible for providing the right string (e.g. plain body,
    or body + HTML source, or preprocessed content). Detects http(s), ftp, bare
    domains, www, IPv4. Returns deduplicated, normalized URLs (order not guaranteed).
    """
    if not text or not text.strip():
        return []
    raw_urls = _url_extractor.find_urls(text, only_unique=False)
    seen: set[str] = set()
    result: list[str] = []
    for raw in raw_urls:
        norm = _normalize_url(raw)
        if norm and norm not in seen:
            seen.add(norm)
            result.append(norm)
    return result


def extract_href_urls(html: str) -> list[str]:
    """
    Return all href values from <a> tags that look like real URLs.

    Skips mailto:, javascript:, data:, and anchor-only (#...). Use so that
    links that appear only in the anchor (visible text, link in href) are
    still available for detection. Caller typically appends these to the
    string passed to extract_links() for normalization and dedup.
    """
    if not html or not html.strip():
        return []
    soup = BeautifulSoup(html, "html.parser")
    urls: list[str] = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href:
            continue
        h_lower = href.lower()
        if any(h_lower.startswith(p) for p in _HREF_SKIP_PREFIXES):
            continue
        urls.append(href)
    return urls
