"""HTML Risk rule: forms, hidden inputs, and inline JS in email HTML."""

from bs4 import BeautifulSoup

from app.core.constants import SUSPICIOUS_JS_ATTRS
from app.detection.rules.base import BaseRule, RuleResult
from app.parsing.email_parser import ParsedEmail


class HtmlRule(BaseRule):
    rule_id = "html"
    weight = 1.0

    def evaluate(self, email: ParsedEmail) -> RuleResult | None:
        if not email.body_html:
            return None

        soup = BeautifulSoup(email.body_html, "html.parser")
        reasons: list[str] = []
        flags = 0

        # Forms inside email (credential harvesting)
        forms = soup.find_all("form")
        if forms:
            reasons.append(f"Email contains {len(forms)} <form> element(s)")
            flags += len(forms)

        # Hidden inputs (data exfiltration)
        hidden_inputs = soup.find_all("input", {"type": "hidden"})
        if hidden_inputs:
            reasons.append(f"Email contains {len(hidden_inputs)} hidden input(s)")
            flags += len(hidden_inputs)

        # Inline JavaScript (onclick, onload, onerror, etc.)
        js_count = 0
        for attr in SUSPICIOUS_JS_ATTRS:
            js_count += len(soup.find_all(attrs={attr: True}))
        if js_count:
            reasons.append(f"Email contains {js_count} inline JS handler(s)")
            flags += js_count

        # <script> tags
        scripts = soup.find_all("script")
        if scripts:
            reasons.append(f"Email contains {len(scripts)} <script> tag(s)")
            flags += len(scripts)

        if flags == 0:
            return None

        score = min(1.0, 0.3 * flags)
        return RuleResult(rule_id=self.rule_id, score=score, reasons=reasons)
