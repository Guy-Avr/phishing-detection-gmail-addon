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
}

PHISHING_THRESHOLD: float = 0.7
SUSPICIOUS_THRESHOLD: float = 0.4

# --- Links rule ---

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

# --- Language rule ---

# --- HTML rule ---

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
    "urgent", "verify", "suspended", "action required", "immediately",
    "account locked", "confirm your identity", "unauthorized", "expire",
    "click immediately", "act now", "limited time", "final warning",
    "security alert", "unusual activity", "verify your account",
    "your account has been", "failure to", "within 24 hours",
]
