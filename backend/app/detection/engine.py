"""
Detection engine: orchestrator that runs all registered rules and aggregates results.

Receives ParsedEmail, runs each rule, collects RuleResults (skips None),
optionally checks links against OpenPhish feed DB, then delegates to aggregator.
"""

from app.detection.aggregator import aggregate
from app.detection.rules.base import BaseRule, RuleResult
from app.parsing.email_parser import ParsedEmail


class DetectionEngine:
    """
    Runs registered rules against a ParsedEmail and returns detection output.

    If phish_db_path is set and email has links, checks them against the phish URL DB
    and adds an openphish signal when matches are found.
    """

    def __init__(
        self,
        rules: list[BaseRule],
        phish_db_path: str | None = None,
    ) -> None:
        self._rules = rules
        self._phish_db_path = phish_db_path

    def run(self, email: ParsedEmail) -> dict:
        """
        Execute all rules and aggregate into final result.

        Returns dict with: label (Verdict), confidence, reasons, signals, metadata.
        """
        results: list[RuleResult] = []

        for rule in self._rules:
            try:
                result = rule.evaluate(email)
                if result is not None:
                    results.append(result)
            except Exception:
                pass

        if email.links and self._phish_db_path:
            try:
                from app.reputation.openphish import lookup_phish_urls
                matches = lookup_phish_urls(self._phish_db_path, email.links)
                if matches:
                    reasons = [
                        f"URL in threat feed ({source}): {url}"
                        for url, source in matches
                    ]
                    results.append(
                        RuleResult(rule_id="openphish", score=1.0, reasons=reasons)
                    )
            except Exception:
                pass

        verdict, confidence, reasons, signals = aggregate(results)

        return {
            "label": verdict,
            "confidence": confidence,
            "reasons": reasons,
            "signals": signals,
        }
