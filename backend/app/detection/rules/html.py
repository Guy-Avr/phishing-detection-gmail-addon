"""HTML Risk rule: forms, hidden inputs, and inline JS in email HTML."""

from bs4 import BeautifulSoup

from app.core.constants import (
    HTML_WEIGHT_FORM,
    HTML_WEIGHT_HIDDEN_INPUT,
    HTML_WEIGHT_INLINE_JS,
    HTML_WEIGHT_SCRIPT_TAG,
    SUSPICIOUS_JS_ATTRS,
)
from app.detection.rules.base import BaseRule, RuleResult
from app.parsing.email_parser import ParsedEmail


class HtmlRule(BaseRule):
    rule_id = "html"
    weight = 1.0

    def evaluate(self, email: ParsedEmail) -> RuleResult | None:
        if not email.body_html:
            return RuleResult(rule_id=self.rule_id, score=0.0, reasons=[])

        soup = BeautifulSoup(email.body_html, "html.parser")
        reasons: list[str] = []
        weight_sum = 0.0

        # Forms inside email (credential harvesting)
        forms = soup.find_all("form")
        if forms:
            reasons.append(f"Email contains {len(forms)} <form> element(s)")
            weight_sum += HTML_WEIGHT_FORM * len(forms)

        # Hidden inputs (data exfiltration) — high weight
        hidden_inputs = soup.find_all("input", {"type": "hidden"})
        if hidden_inputs:
            reasons.append(f"Email contains {len(hidden_inputs)} hidden input(s)")
            weight_sum += HTML_WEIGHT_HIDDEN_INPUT * len(hidden_inputs)

        # Inline JavaScript (onclick, onload, onerror, etc.)
        js_count = 0
        for attr in SUSPICIOUS_JS_ATTRS:
            js_count += len(soup.find_all(attrs={attr: True}))
        if js_count:
            reasons.append(f"Email contains {js_count} inline JS handler(s)")
            weight_sum += HTML_WEIGHT_INLINE_JS * js_count

        # <script> tags
        scripts = soup.find_all("script")
        if scripts:
            reasons.append(f"Email contains {len(scripts)} <script> tag(s)")
            weight_sum += HTML_WEIGHT_SCRIPT_TAG * len(scripts)

        if weight_sum == 0:
            return RuleResult(rule_id=self.rule_id, score=0.0, reasons=[])

        score = min(1.0, weight_sum)
        return RuleResult(rule_id=self.rule_id, score=round(score, 4), reasons=reasons)
