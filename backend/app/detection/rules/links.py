"""Suspicious Links rule: IP addresses, URL shorteners, anchor/href mismatch."""

import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from app.core.constants import SHORTENER_DOMAINS
from app.detection.rules.base import BaseRule, RuleResult
from app.parsing.email_parser import ParsedEmail

_IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _has_ip_host(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return bool(_IP_PATTERN.match(host))


def _is_shortener(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in SHORTENER_DOMAINS


def _find_anchor_mismatches(body_html: str | None) -> list[str]:
    """Find <a> tags where display text looks like a URL but differs from href."""
    if not body_html:
        return []
    soup = BeautifulSoup(body_html, "html.parser")
    mismatches: list[str] = []
    for a in soup.find_all("a", href=True):
        display = a.get_text(strip=True).lower()
        href_host = (urlparse(a["href"]).hostname or "").lower()
        if not display or not href_host:
            continue
        # Display text looks like a URL (has a dot and no spaces)
        if "." in display and " " not in display:
            display_host = (urlparse("https://" + display).hostname or "").lower()
            if display_host and display_host != href_host:
                mismatches.append(
                    f"Display text '{display}' points to '{href_host}'"
                )
    return mismatches


class LinksRule(BaseRule):
    rule_id = "links"
    weight = 1.0

    def evaluate(self, email: ParsedEmail) -> RuleResult | None:
        if not email.links:
            return None

        reasons: list[str] = []
        flags = 0

        for url in email.links:
            if _has_ip_host(url):
                reasons.append(f"Link contains raw IP address: {url}")
                flags += 1
            if _is_shortener(url):
                reasons.append(f"Link uses URL shortener: {url}")
                flags += 1

        mismatches = _find_anchor_mismatches(email.body_html)
        reasons.extend(mismatches)
        flags += len(mismatches)

        if flags == 0:
            return None

        score = min(1.0, 0.3 * flags)
        return RuleResult(rule_id=self.rule_id, score=score, reasons=reasons)
