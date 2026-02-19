"""Sender Spoofing rule: free email with brand name, domain similarity to known brands."""

from difflib import SequenceMatcher

from app.core.constants import (
    BRAND_SIMILARITY_THRESHOLD,
    FREE_EMAIL_DOMAINS,
    KNOWN_BRANDS,
    SENDER_WEIGHT_DOMAIN_SPOOF,
    SENDER_WEIGHT_EXACT_BRAND_ON_FREE,
    SENDER_WEIGHT_SIMILAR_NOT_EXACT,
)
from app.detection.rules.base import BaseRule, RuleResult
from app.parsing.email_parser import ParsedEmail


def _local_exact_brand(local: str) -> str | None:
    """True if local part contains the exact brand name (e.g. paypal in paypal-support)."""
    local_lower = local.lower()
    for brand in KNOWN_BRANDS:
        if brand in local_lower:
            return f"Free email with exact brand name '{brand}' in address"
    return None


def _local_resembles_brand_not_exact(local: str) -> str | None:
    """Local part resembles a brand but is not exact (e.g. paypa1, natflix) => clearly fake."""
    local = local.lower()
    segments = [local]
    for sep in (".", "-", "_"):
        segments = [p for s in segments for p in s.split(sep)]
    seen: set[str] = set()
    for segment in segments:
        if len(segment) < 3 or segment in seen:
            continue
        seen.add(segment)
        for brand in KNOWN_BRANDS:
            if segment == brand:
                continue  # exact = handled by _local_exact_brand, lower weight
            ratio = SequenceMatcher(None, segment, brand).ratio()
            if ratio >= BRAND_SIMILARITY_THRESHOLD:
                return f"Free email with brand-like address '{segment}' (not exact match of '{brand}')"
    return None


def _sender_free_email_checks(sender: str, domain: str) -> list[tuple[str, float]]:
    """Returns list of (reason, weight) for free-email sender. Empty if not free email."""
    if domain not in FREE_EMAIL_DOMAINS:
        return []
    local = sender.split("@")[0] if "@" in sender else sender
    out: list[tuple[str, float]] = []
    # Similar but not exact => 1.0 (clearly fake)
    similar = _local_resembles_brand_not_exact(local)
    if similar:
        out.append((f"Free email '{domain}': {similar}", SENDER_WEIGHT_SIMILAR_NOT_EXACT))
        return out  # already max; no need to add exact
    # Exact brand in address => 0.5 (suspicious but could be support)
    exact = _local_exact_brand(local)
    if exact:
        out.append((f"Free email '{domain}': {exact}", SENDER_WEIGHT_EXACT_BRAND_ON_FREE))
    return out


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
            return RuleResult(rule_id=self.rule_id, score=0.0, reasons=[])

        weighted: list[tuple[str, float]] = []

        for reason, w in _sender_free_email_checks(email.sender, email.sender_domain):
            weighted.append((reason, w))

        domain_spoof = _domain_resembles_brand(email.sender_domain)
        if domain_spoof:
            weighted.append((domain_spoof, SENDER_WEIGHT_DOMAIN_SPOOF))

        if not weighted:
            return RuleResult(rule_id=self.rule_id, score=0.0, reasons=[])

        reasons = [r for r, _ in weighted]
        score = min(1.0, sum(w for _, w in weighted))
        return RuleResult(rule_id=self.rule_id, score=round(score, 4), reasons=reasons)
