"""
Parse raw RFC-style email so all splitting (headers, body, text vs HTML) happens in the backend.

The addon or any client can send the full email; this module produces subject, sender,
body_text, and body_html for parse_email().
"""

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

# Default policy decodes headers and handles encoding.
_EMAIL_POLICY = policy.default


def _decode_payload(part) -> str:
    """Decode part payload to str. Safe for None or binary."""
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except Exception:
        return payload.decode("utf-8", errors="replace")


def _get_address(header_value: str | None) -> str:
    """Extract email address from From/Reply-To header. Returns empty string if missing."""
    if not header_value or not header_value.strip():
        return ""
    _, addr = parseaddr(header_value)
    return addr.strip() or ""


def parse_raw_message(raw: str | bytes) -> dict:
    """
    Parse a raw RFC-style email message into structured fields for parse_email().

    Extracts: subject, sender (addr-spec), body_text (plain), body_html (if present).
    Multipart messages: uses text/plain and text/html parts; single part: uses body as text or HTML by content type.
    Returns dict with keys: subject, sender, body_text, body_html (body_html may be None).
    """
    if not raw:
        return {"subject": "", "sender": "", "body_text": "", "body_html": None}
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")

    msg = BytesParser(policy=_EMAIL_POLICY).parsebytes(raw)
    subject = (msg.get("Subject") or "").strip()
    sender = _get_address(msg.get("From"))

    body_text = ""
    body_html = None

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            ct = (part.get_content_type() or "").lower()
            decoded = _decode_payload(part)
            if ct == "text/plain":
                body_text = decoded
            elif ct == "text/html":
                body_html = decoded
    else:
        decoded = _decode_payload(msg)
        ct = (msg.get_content_type() or "").lower()
        if ct == "text/html":
            body_html = decoded
        else:
            body_text = decoded

    return {
        "subject": subject,
        "sender": sender,
        "body_text": body_text or "",
        "body_html": body_html,
    }
