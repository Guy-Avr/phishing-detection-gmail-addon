"""
Configurable constants for detection: rule weights, thresholds, and data lists.

Expand the lists here to tune detection without changing rule code.
"""

# --- Rule weights and thresholds ---

RULE_WEIGHTS: dict[str, float] = {
    "links": 1.0,
    "sender": 1.0,
    "language": 1.0,
    "html": 1.0,
    "openphish": 1.0,
    "llm": 1.0,
}

PHISHING_THRESHOLD: float = 0.7
SUSPICIOUS_THRESHOLD: float = 0.4

# --- Links rule (score = sum of weights per signal, capped at 1.0) ---

# Weight per occurrence: IP and anchor/href mismatch are strong signals ("link attached to link").
LINK_WEIGHT_IP: float = 0.5
LINK_WEIGHT_SHORTENER: float = 0.3
LINK_WEIGHT_ANCHOR_MISMATCH: float = 0.5

SHORTENER_DOMAINS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
})

# --- Sender rule ---

FREE_EMAIL_DOMAINS: frozenset[str] = frozenset({
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "protonmail.com", "yandex.com", "icloud.com", "zoho.com",
})

KNOWN_BRANDS: frozenset[str] = frozenset({
    "paypal", "apple", "amazon", "microsoft", "google", "netflix",
    "facebook", "instagram", "bank", "chase", "wellsfargo", "citibank",
    "dhl", "fedex", "ups", "usps",
})

BRAND_SIMILARITY_THRESHOLD: float = 0.75

# Sender rule: exact brand on free email = 0.5; distorted name (local or domain) = 1.0
SENDER_WEIGHT_EXACT_BRAND_ON_FREE: float = 0.5
SENDER_WEIGHT_SIMILAR_NOT_EXACT: float = 1.0  # local part distorted (e.g. paypa1)
SENDER_WEIGHT_DOMAIN_SPOOF: float = 1.0  # domain distorted (e.g. paypa1.com, natflix.com)

# --- Language rule ---

# --- HTML rule (score = sum of weights per signal, capped at 1.0) ---

# Hidden input is high risk (data exfiltration); form, script, inline JS also weighted.
HTML_WEIGHT_FORM: float = 0.3
HTML_WEIGHT_HIDDEN_INPUT: float = 0.55
HTML_WEIGHT_INLINE_JS: float = 0.3
HTML_WEIGHT_SCRIPT_TAG: float = 0.4

SUSPICIOUS_JS_ATTRS: list[str] = [
    "onclick", "onload", "onerror", "onmouseover", "onfocus",
]

# --- Language rule ---

# --- Reputation (OpenPhish feed) ---

OPENPHISH_FEED_URL: str = "https://openphish.com/feed.txt"
PHISH_FEED_SOURCE: str = "openphish"
FEED_UPDATE_INTERVAL_HOURS: int = 12

# --- Language rule ---

URGENCY_PHRASES: list[str] = [
    # urgency and attack
    "urgent", "verify", "suspended", "action required", "immediately",
    "account locked", "confirm your identity", "unauthorized", "expire",
    "click immediately", "act now", "limited time", "final warning",
    "security alert", "unusual activity", "verify your account",
    "your account has been", "failure to", "within 24 hours",

    # Creating pressure and urgency
    "time sensitive", "as soon as possible", "do not ignore",
    "respond now", "last chance", "final notice", "important notice",
    "attention required", "take action", "pending action",

    # Account / access
    "account restriction", "account limitation", "account disabled",
    "access blocked", "login attempt", "sign-in attempt",
    "credentials compromised", "authentication required",
    "re-authentication required",

    # Security / attack
    "suspicious activity", "potential risk", "security issue",
    "breach detected", "unauthorized access", "malicious activity",
    "security verification", "identity check",

    # Payment / money
    "payment declined", "payment failed", "billing issue",
    "outstanding balance", "invoice attached", "refund pending",
    "charge detected", "transaction pending",

    # Links / attached files
    "click the link below", "open attachment", "download attachment",
    "view document", "secure message", "encrypted message",

    # General phishing wording
    "this email was sent to you", "for your safety",
    "to avoid interruption", "to prevent suspension",
    "please confirm", "please verify",
]

