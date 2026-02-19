"""
Detection engine: orchestrator that runs all registered rules and aggregates results.

Receives ParsedEmail, runs each rule, collects RuleResults (skips None),
optionally checks links against OpenPhish feed DB, then delegates to aggregator.
LLM is invoked only when label is Suspicious. LLM does not affect the final
confidence or label: we return rule-based label/confidence and, when LLM ran,
its opinion separately (llm_confidence, llm_reasons in metadata). If LLM fails,
rule-based result is returned unchanged.
"""

import logging

from app.core.constants import PHISHING_THRESHOLD, SUSPICIOUS_THRESHOLD
from app.core.enums import Verdict
from app.detection.aggregator import aggregate
from app.detection.rules.base import BaseRule, RuleResult
from app.parsing.email_parser import ParsedEmail

logger = logging.getLogger(__name__)


def _build_llm_analyzer():
    """Build LLMAnalyzer with the provider selected in settings (LLM_PROVIDER=ollama|gemini)."""
    from app.detection.llm import LLMAnalyzer
    from app.detection.llm.gemini import GeminiProvider
    from app.detection.llm.ollama import OllamaProvider
    from app.settings import settings

    if settings.llm_provider == "gemini":
        primary = GeminiProvider(
            api_key=settings.gemini_api_key,
            model=settings.gemini_model,
            timeout_sec=settings.llm_timeout_sec,
        )
    else:
        primary = OllamaProvider(
            base_url=settings.ollama_url,
            model=settings.ollama_model,
            timeout_sec=settings.llm_timeout_sec,
        )
    return LLMAnalyzer(
        primary=primary,
        fallback=None,
        timeout_sec=settings.llm_timeout_sec,
    )


class DetectionEngine:
    """
    Runs registered rules against a ParsedEmail and returns detection output.

    If phish_db_path is set and email has links, checks them against the phish URL DB
    and adds an openphish signal when matches are found.
    When verdict is Suspicious, invokes LLM and returns its opinion separately
    (llm_confidence, llm_reasons); rule-based confidence and label are unchanged.
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
        If label is Suspicious, call LLM and return its opinion separately;
        confidence and label stay rule-based only.

        Returns dict with: label, confidence, reasons, signals, llm_used,
        llm_confidence (when LLM ran), llm_reasons (when LLM ran).
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

        # OpenPhish match => link is known malicious => force Phishing, confidence 1
        if any(r.rule_id == "openphish" and r.score >= 1.0 for r in results):
            verdict = Verdict.PHISHING
            confidence = 1.0

        llm_used = False
        llm_confidence: float | None = None
        llm_reasons: list[str] = []
        llm_label: Verdict | None = None
        # LLM only when Suspicious; return its opinion separately, do not change confidence/label
        if verdict == Verdict.SUSPICIOUS:
            try:
                logger.info("LLM: invoking (verdict=Suspicious)")
                analyzer = _build_llm_analyzer()
                llm_result = analyzer.analyze(
                    subject=email.subject,
                    sender=email.sender,
                    body=email.body_text,
                )
                logger.info(
                    "LLM: result provider=%s risk_score=%s reasons_count=%s",
                    llm_result.provider,
                    llm_result.risk_score,
                    len(llm_result.reasons),
                )
                if llm_result.provider != "none":
                    llm_used = True
                    llm_confidence = llm_result.risk_score
                    llm_reasons = [f"LLM ({llm_result.provider}): {r}" for r in llm_result.reasons]
                    # Derive label from risk_score using same thresholds as aggregator
                    if llm_confidence >= PHISHING_THRESHOLD:
                        llm_label = Verdict.PHISHING
                    elif llm_confidence >= SUSPICIOUS_THRESHOLD:
                        llm_label = Verdict.SUSPICIOUS
                    else:
                        llm_label = Verdict.SAFE
                else:
                    logger.info("LLM: no provider succeeded, using rule-only result")
            except Exception as e:
                logger.warning("LLM: invocation failed, using rule-only result: %s", e)

        return {
            "label": verdict,
            "confidence": confidence,
            "reasons": reasons,
            "signals": signals,
            "llm_used": llm_used,
            "llm_confidence": llm_confidence,
            "llm_reasons": llm_reasons,
            "llm_label": llm_label,
        }
