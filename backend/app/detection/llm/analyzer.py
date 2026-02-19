"""
LLM analyzer: orchestration, fallback, normalization, error handling.

- Builds prompt via prompt.py.
- Tries primary (Ollama) then fallback (Gemini).
- Parses JSON response to LLMResult; normalizes score and reasons.
- Never raises: on any failure returns safe fallback (score=0.0, no reasons).
"""

import json
import re

from app.detection.llm.base import LLMProvider, LLMResult
from app.detection.llm.prompt import build_phishing_prompt


def _parse_response(raw: str, provider: str) -> LLMResult | None:
    """
    Parse raw LLM text into LLMResult. Returns None on parse failure or invalid schema.
    """
    if not raw or not raw.strip():
        return None
    # Allow markdown code block
    text = raw.strip()
    m = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", text)
    if m:
        text = m.group(1)
    else:
        # Try whole string as JSON
        text = text.strip()
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    risk = obj.get("risk_score")
    reasons = obj.get("reasons")
    if risk is None or not isinstance(reasons, list):
        return None
    try:
        score = float(risk)
    except (TypeError, ValueError):
        return None
    score = max(0.0, min(1.0, score))
    reason_list = [str(r).strip() for r in reasons[:3] if r]
    return LLMResult(risk_score=round(score, 4), reasons=tuple(reason_list), provider=provider)


class LLMAnalyzer:
    """
    Orchestrates LLM calls: primary provider first, then fallback.
    Normalizes output to LLMResult. Does not raise; returns fallback on total failure.
    """

    def __init__(
        self,
        primary: LLMProvider,
        fallback: LLMProvider | None,
        timeout_sec: float,
    ) -> None:
        self._primary = primary
        self._fallback = fallback
        self._timeout_sec = timeout_sec

    def analyze(self, subject: str, sender: str, body: str) -> LLMResult:
        """
        Run LLM analysis. Tries primary then fallback. Never raises.
        On both failure or invalid response, returns LLMResult(0.0, (), "none").
        """
        prompt = build_phishing_prompt(subject, sender, body)

        for provider in (self._primary, self._fallback):
            if provider is None:
                continue
            try:
                raw = provider.complete(prompt, self._timeout_sec)
                result = _parse_response(raw, provider.name)
                if result is not None:
                    return result
            except Exception:
                continue

        return LLMResult(risk_score=0.0, reasons=(), provider="none")
