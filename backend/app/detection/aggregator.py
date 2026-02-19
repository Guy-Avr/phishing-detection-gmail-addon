"""
Aggregate rule results into a final verdict and confidence score.

Uses configurable weights and thresholds from core/constants.
"""

from app.core.constants import (
    PHISHING_THRESHOLD,
    RULE_WEIGHTS,
    SUSPICIOUS_THRESHOLD,
)
from app.core.enums import Verdict
from app.detection.rules.base import RuleResult


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def aggregate(results: list[RuleResult]) -> tuple[Verdict, float, list[str], dict[str, float]]:
    """
    Combine rule results into (verdict, confidence, reasons, signals).

    - Weighted average of scores (only rules that fired, i.e. non-None results).
    - Verdict based on configurable thresholds.
    - Reasons collected from all fired rules, ordered by score descending.
    - Signals map: rule_id -> score.
    """
    if not results:
        return Verdict.SAFE, 0.0, [], {}

    signals: dict[str, float] = {}
    weighted_sum = 0.0
    total_weight = 0.0
    scored_reasons: list[tuple[float, str]] = []

    for r in results:
        weight = RULE_WEIGHTS.get(r.rule_id, 1.0)
        signals[r.rule_id] = round(r.score, 4)
        weighted_sum += r.score * weight
        total_weight += weight
        for reason in r.reasons:
            scored_reasons.append((r.score, reason))

    confidence = _clamp(weighted_sum / total_weight) if total_weight > 0 else 0.0
    confidence = round(confidence, 4)

    scored_reasons.sort(key=lambda x: x[0], reverse=True)
    reasons = [reason for _, reason in scored_reasons]

    if confidence >= PHISHING_THRESHOLD:
        verdict = Verdict.PHISHING
    elif confidence >= SUSPICIOUS_THRESHOLD:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.SAFE

    return verdict, confidence, reasons, signals
