"""Urgent Language rule: detect urgency/threat keywords relative to text length."""

from app.core.constants import URGENCY_PHRASES
from app.detection.rules.base import BaseRule, RuleResult
from app.parsing.email_parser import ParsedEmail

_HIGH_RATIO_THRESHOLD = 0.05
_LOW_RATIO_THRESHOLD = 0.02


class LanguageRule(BaseRule):
    rule_id = "language"
    weight = 1.0

    def evaluate(self, email: ParsedEmail) -> RuleResult | None:
        text = f"{email.subject} {email.body_text}"
        if not text.strip():
            return None

        words = text.split()
        word_count = len(words)
        if word_count == 0:
            return None

        found: list[str] = []
        for phrase in URGENCY_PHRASES:
            if phrase in text:
                found.append(phrase)

        if not found:
            return None

        hit_count = len(found)
        ratio = hit_count / word_count

        reasons = [f"Urgency phrase detected: '{p}'" for p in found]

        if ratio >= _HIGH_RATIO_THRESHOLD:
            score = min(1.0, 0.5 + ratio * 5)
        elif ratio >= _LOW_RATIO_THRESHOLD:
            score = 0.3 + ratio * 3
        else:
            score = min(0.3, 0.1 * hit_count)

        score = min(1.0, score)
        return RuleResult(rule_id=self.rule_id, score=round(score, 4), reasons=reasons)
