"""Sender Spoofing rule: free email with brand name, domain similarity to known brands."""

from difflib import SequenceMatcher

from app.core.constants import (
    BRAND_SIMILARITY_THRESHOLD,
    FREE_EMAIL_DOMAINS,
    KNOWN_BRANDS,
)
from app.detection.rules.base import BaseRule, RuleResult
from app.parsing.email_parser import ParsedEmail


def _sender_uses_brand_on_free_email(sender: str, domain: str) -> str | None:
    """Check if sender address on a free email domain contains a brand name."""
    if domain not in FREE_EMAIL_DOMAINS:
        return None
    local = sender.split("@")[0] if "@" in sender else sender
    for brand in KNOWN_BRANDS:
        if brand in local:
            return f"Free email '{domain}' with brand name '{brand}' in address"
    return None


def _domain_resembles_brand(domain: str) -> str | None:
    """Check if sender domain is suspiciously similar to a known brand (e.g. paypa1.com)."""
    base = domain.split(".")[0] if "." in domain else domain
    if not base:
        return None
    for brand in KNOWN_BRANDS:
        if base == brand:
            return None
        ratio = SequenceMatcher(None, base, brand).ratio()
        if ratio >= BRAND_SIMILARITY_THRESHOLD:
            return f"Domain '{domain}' resembles brand '{brand}' (similarity {ratio:.0%})"
    return None


class SenderRule(BaseRule):
    rule_id = "sender"
    weight = 1.0

    def evaluate(self, email: ParsedEmail) -> RuleResult | None:
        if not email.sender or not email.sender_domain:
            return None

        reasons: list[str] = []

        brand_on_free = _sender_uses_brand_on_free_email(email.sender, email.sender_domain)
        if brand_on_free:
            reasons.append(brand_on_free)

        domain_spoof = _domain_resembles_brand(email.sender_domain)
        if domain_spoof:
            reasons.append(domain_spoof)

        if not reasons:
            return None

        score = min(1.0, 0.5 * len(reasons))
        return RuleResult(rule_id=self.rule_id, score=score, reasons=reasons)
