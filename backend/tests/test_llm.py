"""Unit tests for LLM layer: invocation only when Suspicious, Ollama first, Gemini fallback, no leak on failure."""

from unittest.mock import MagicMock, patch

from app.core.enums import Verdict
from app.detection.engine import DetectionEngine
from app.detection.llm.analyzer import LLMAnalyzer, _parse_response
from app.detection.llm.base import LLMResult
from app.detection.rules.base import BaseRule, RuleResult
from app.parsing.email_parser import ParsedEmail


def _make_email(**overrides) -> ParsedEmail:
    defaults = {
        "subject": "test",
        "body_text": "test body",
        "body_html": None,
        "sender": "user@example.com",
        "sender_domain": "example.com",
        "links": [],
    }
    defaults.update(overrides)
    return ParsedEmail(**defaults)


class SuspiciousOnlyRule(BaseRule):
    """Returns score 0.5 so aggregate verdict is Suspicious."""

    rule_id = "susp"
    weight = 1.0

    def evaluate(self, email: ParsedEmail) -> RuleResult | None:
        return RuleResult(rule_id=self.rule_id, score=0.5, reasons=["borderline"])


def test_llm_not_called_for_safe():
    """LLM must not be invoked when rule-based label is Safe."""
    engine = DetectionEngine(rules=[], phish_db_path=None)
    email = _make_email()
    llm_called = []

    def track_analyzer(*args, **kwargs):
        a = MagicMock()
        def analyze(*a, **k):
            llm_called.append(1)
            return LLMResult(risk_score=0.0, reasons=(), provider="none")
        a.analyze = analyze
        return a

    with patch("app.detection.engine._build_llm_analyzer", side_effect=track_analyzer):
        result = engine.run(email)
    assert result["label"] == Verdict.SAFE
    assert len(llm_called) == 0


def test_llm_not_called_for_phishing():
    """LLM must not be invoked when rule-based label is Phishing (e.g. OpenPhish match)."""
    email = _make_email(links=["http://evil.com"])
    engine = DetectionEngine(rules=[SuspiciousOnlyRule()], phish_db_path="/any.db")
    llm_called = []

    def track_analyzer(*args, **kwargs):
        a = MagicMock()
        def analyze(*a, **k):
            llm_called.append(1)
            return LLMResult(risk_score=0.0, reasons=(), provider="none")
        a.analyze = analyze
        return a

    with patch("app.detection.engine._build_llm_analyzer", side_effect=track_analyzer), \
         patch("app.reputation.openphish.lookup_phish_urls", return_value=[("http://evil.com", "openphish")]):
        result = engine.run(email)
    assert result["label"] == Verdict.PHISHING
    assert len(llm_called) == 0


def test_ollama_attempted_first_when_suspicious():
    """When label is Suspicious, Ollama (primary) must be attempted first."""
    email = _make_email()
    engine = DetectionEngine(rules=[SuspiciousOnlyRule()], phish_db_path=None)
    primary_called = []

    class TrackPrimary:
        name = "ollama"
        def complete(self, prompt: str, timeout_sec: float) -> str:
            primary_called.append(1)
            return '{"risk_score": 0.3, "reasons": ["looks ok"]}'

    class TrackFallback:
        name = "gemini"
        def complete(self, prompt: str, timeout_sec: float) -> str:
            return ""

    with patch("app.detection.engine._build_llm_analyzer") as m:
        m.return_value = LLMAnalyzer(
            primary=TrackPrimary(),
            fallback=TrackFallback(),
            timeout_sec=10.0,
        )
        result = engine.run(email)
    assert result["label"] == Verdict.SUSPICIOUS
    assert len(primary_called) == 1
    assert result.get("llm_used") is True
    assert result.get("llm_confidence") is not None
    assert "llm" not in result["signals"]  # LLM does not affect rule-based signals


def test_gemini_used_only_if_ollama_fails():
    """Gemini (fallback) is used only when Ollama fails."""
    email = _make_email()
    engine = DetectionEngine(rules=[SuspiciousOnlyRule()], phish_db_path=None)
    fallback_called = []

    class FailingPrimary:
        name = "ollama"
        def complete(self, prompt: str, timeout_sec: float) -> str:
            raise ConnectionError("ollama down")

    class TrackFallback:
        name = "gemini"
        def complete(self, prompt: str, timeout_sec: float) -> str:
            fallback_called.append(1)
            return '{"risk_score": 0.6, "reasons": ["suspicious link"]}'

    with patch("app.detection.engine._build_llm_analyzer") as m:
        m.return_value = LLMAnalyzer(
            primary=FailingPrimary(),
            fallback=TrackFallback(),
            timeout_sec=10.0,
        )
        result = engine.run(email)
    assert result["label"] == Verdict.SUSPICIOUS
    assert len(fallback_called) == 1
    assert result.get("llm_used") is True
    assert result.get("llm_confidence") == 0.6


def test_both_providers_fail_keeps_rule_result():
    """If both Ollama and Gemini fail, rule-based result is unchanged; no exception."""
    email = _make_email()
    engine = DetectionEngine(rules=[SuspiciousOnlyRule()], phish_db_path=None)

    class FailingPrimary:
        name = "ollama"
        def complete(self, prompt: str, timeout_sec: float) -> str:
            raise TimeoutError("timeout")

    class FailingFallback:
        name = "gemini"
        def complete(self, prompt: str, timeout_sec: float) -> str:
            raise RuntimeError("api error")

    with patch("app.detection.engine._build_llm_analyzer") as m:
        m.return_value = LLMAnalyzer(
            primary=FailingPrimary(),
            fallback=FailingFallback(),
            timeout_sec=10.0,
        )
        result = engine.run(email)
    assert result["label"] == Verdict.SUSPICIOUS
    assert result.get("llm_used") is False
    assert result.get("llm_confidence") is None
    assert result["confidence"] == 0.5
    assert "borderline" in result["reasons"]


def test_parse_response_valid_json():
    """_parse_response returns LLMResult for valid JSON."""
    raw = '{"risk_score": 0.8, "reasons": ["urgent language", "suspicious link"]}'
    r = _parse_response(raw, "ollama")
    assert r is not None
    assert r.risk_score == 0.8
    assert len(r.reasons) == 2
    assert r.provider == "ollama"


def test_parse_response_json_in_code_block():
    """_parse_response extracts JSON from markdown code block."""
    raw = '```json\n{"risk_score": 0.5, "reasons": []}\n```'
    r = _parse_response(raw, "gemini")
    assert r is not None
    assert r.risk_score == 0.5
    assert r.reasons == ()


def test_parse_response_invalid_returns_none():
    """_parse_response returns None for invalid or empty input."""
    assert _parse_response("", "ollama") is None
    assert _parse_response("not json", "ollama") is None
    assert _parse_response('{"reasons": []}', "ollama") is None  # missing risk_score
