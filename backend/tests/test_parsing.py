"""Unit tests for parsing: ParsedEmail, link extraction, raw message, normalization."""

import pytest

from app.parsing import ParsedEmail, parse_email, parse_raw_email
from app.parsing.link_extractor import extract_links
from app.parsing.raw_parser import parse_raw_message


def test_parse_email_normalizes_and_extracts_domain():
    parsed = parse_email(
        subject="  Urgent: Verify NOW  ",
        sender="  Alerts@Example.COM  ",
        body_text="Click here https://evil.com/path  ",
        body_html=None,
    )
    assert parsed.subject == "urgent: verify now"
    assert parsed.sender == "alerts@example.com"
    assert parsed.sender_domain == "example.com"
    assert "https://evil.com/path" in parsed.links or "evil.com" in str(parsed.links)


def test_parse_email_extracts_links_from_html():
    parsed = parse_email(
        subject="x",
        sender="a@b.co",
        body_text="",
        body_html='<p><a href="https://phish.com">click</a></p>',
    )
    assert len(parsed.links) >= 1
    assert any("phish.com" in u for u in parsed.links)


def test_parse_email_extracts_anchor_only_link():
    """Link only in href (visible text is plain); no URL in body_text."""
    parsed = parse_email(
        subject="Verify your account",
        sender="noreply@example.com",
        body_text="Click here to continue.",
        body_html='<a href="https://evil-tracking.com/steal">Click here to continue.</a>',
    )
    assert any("evil-tracking.com" in u for u in parsed.links)


def test_extract_links_deduplicates_and_normalizes():
    links = extract_links(
        "see https://Site.com/Path#anchor and https://site.com/path",
    )
    assert len(links) == 1
    assert "site.com" in links[0].lower()


def test_parsed_email_empty_input_safe_defaults():
    parsed = parse_email(subject="", sender="", body_text="", body_html=None)
    assert parsed.subject == ""
    assert parsed.sender == ""
    assert parsed.sender_domain == ""
    assert parsed.links == []


def test_sender_domain_no_at_returns_empty():
    parsed = parse_email("s", "not-an-email", "b", None)
    assert parsed.sender_domain == ""


def test_parse_raw_message_splits_headers_and_body():
    raw = (
        "Subject: Verify your account\r\n"
        "From: Support <support@example.com>\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Click https://safe.com to continue."
    )
    out = parse_raw_message(raw)
    assert out["subject"] == "Verify your account"
    assert out["sender"] == "support@example.com"
    assert "safe.com" in out["body_text"]


def test_parse_raw_message_multipart_html():
    raw = (
        "Subject: Hi\r\n"
        "From: <alerts@evil.com>\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/alternative; boundary=x\r\n"
        "\r\n"
        "--x\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Plain text here.\r\n"
        "--x\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<a href=\"https://phish.com\">link</a>\r\n"
        "--x--"
    )
    out = parse_raw_message(raw)
    assert out["subject"] == "Hi"
    assert out["sender"] == "alerts@evil.com"
    assert "Plain text here" in out["body_text"]
    assert "phish.com" in (out["body_html"] or "")


def test_parse_raw_email_returns_parsed_email():
    raw = (
        "Subject: Test\r\n"
        "From: user@domain.co\r\n"
        "\r\n"
        "Body with https://link.org"
    )
    parsed = parse_raw_email(raw)
    assert isinstance(parsed, ParsedEmail)
    assert parsed.subject == "test"
    assert parsed.sender_domain == "domain.co"
    assert any("link.org" in u for u in parsed.links)
