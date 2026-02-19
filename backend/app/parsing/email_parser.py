"""
Parse and normalize email into ParsedEmail.

Combines body text and optional HTML into a single string for link extraction;
link_extractor receives only that string. Rules consume ParsedEmail only.
"""

from dataclasses import dataclass

from app.parsing.link_extractor import extract_href_urls, extract_links
from app.parsing.raw_parser import parse_raw_message


def _normalize_text(value: str | None) -> str:
    """Lowercase and strip. Safe for None or empty."""
    if value is None:
        return ""
    return value.strip().lower()


def _extract_sender_domain(sender: str) -> str:
    """Extract domain from email address. Lowercase, no leading/trailing dots."""
    if not sender or "@" not in sender:
        return ""
    domain = sender.strip().lower().split("@")[-1]
    return domain.strip(".")


@dataclass(frozen=True)
class ParsedEmail:
    """Normalized email content. All text lowercased and stripped. Rules use this only."""

    subject: str
    body_text: str
    body_html: str | None
    sender: str
    sender_domain: str
    links: list[str]


def parse_email(
    subject: str,
    sender: str,
    body_text: str,
    body_html: str | None = None,
) -> ParsedEmail:
    """
    Build a ParsedEmail from raw fields: normalize text, extract sender domain,
    delegate link extraction. No parsing in rules — they receive ParsedEmail.
    """
    subject_n = _normalize_text(subject)
    body_text_n = _normalize_text(body_text)
    body_html_clean = (body_html.strip() or None) if body_html else None
    sender_n = _normalize_text(sender)
    sender_domain = _extract_sender_domain(sender)

    # Single string for link extraction: body + HTML source (link_extractor is text-only).
    # Also append href URLs explicitly so anchor-only links (visible text, link in href) are never missed.
    text_for_links = body_text_n
    if body_html_clean:
        text_for_links = f"{body_text_n} {body_html_clean}"
        href_urls = extract_href_urls(body_html_clean)
        if href_urls:
            text_for_links = f"{text_for_links} {' '.join(href_urls)}"
    links = extract_links(text_for_links)

    return ParsedEmail(
        subject=subject_n,
        body_text=body_text_n,
        body_html=body_html_clean,
        sender=sender_n,
        sender_domain=sender_domain,
        links=links,
    )


def parse_raw_email(raw: str | bytes) -> ParsedEmail:
    """
    Parse a raw RFC-style email and return ParsedEmail.

    All splitting (headers, body, text vs HTML) is done in the backend.
    The client (e.g. addon) can send the full message; this does the rest.
    """
    fields = parse_raw_message(raw)
    return parse_email(
        subject=fields["subject"],
        sender=fields["sender"],
        body_text=fields["body_text"],
        body_html=fields["body_html"],
    )
