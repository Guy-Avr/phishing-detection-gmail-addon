"""Tests for detection framework: rules base, aggregator, engine."""

from app.core.enums import Verdict
from app.detection.aggregator import aggregate
from app.detection.engine import DetectionEngine
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


class FakeHighRule(BaseRule):
    rule_id = "fake_high"
    weight = 1.0

    def evaluate(self, email: ParsedEmail) -> RuleResult | None:
        return RuleResult(rule_id=self.rule_id, score=0.9, reasons=["Looks bad"])


class FakeLowRule(BaseRule):
    rule_id = "fake_low"
    weight = 1.0

    def evaluate(self, email: ParsedEmail) -> RuleResult | None:
        return RuleResult(rule_id=self.rule_id, score=0.1, reasons=["Minor issue"])


class FakeNoneRule(BaseRule):
    """Rule that does not fire."""
    rule_id = "fake_none"
    weight = 1.0

    def evaluate(self, email: ParsedEmail) -> RuleResult | None:
        return None


# --- Aggregator ---

def test_aggregate_no_results_returns_safe():
    verdict, confidence, reasons, signals = aggregate([])
    assert verdict == Verdict.SAFE
    assert confidence == 0.0
    assert reasons == []
    assert signals == {}


def test_aggregate_high_score_returns_phishing():
    results = [RuleResult(rule_id="test", score=0.9, reasons=["Bad"])]
    verdict, confidence, _, signals = aggregate(results)
    assert verdict == Verdict.PHISHING
    assert confidence >= 0.7
    assert "test" in signals


def test_aggregate_medium_score_returns_suspicious():
    results = [RuleResult(rule_id="a", score=0.5, reasons=["Meh"])]
    verdict, confidence, _, _ = aggregate(results)
    assert verdict == Verdict.SUSPICIOUS
    assert 0.4 <= confidence < 0.7


def test_aggregate_low_score_returns_safe():
    results = [RuleResult(rule_id="a", score=0.1, reasons=["Minor"])]
    verdict, confidence, _, _ = aggregate(results)
    assert verdict == Verdict.SAFE
    assert confidence < 0.4


def test_aggregate_reasons_ordered_by_score():
    results = [
        RuleResult(rule_id="low", score=0.1, reasons=["Low reason"]),
        RuleResult(rule_id="high", score=0.9, reasons=["High reason"]),
    ]
    _, _, reasons, _ = aggregate(results)
    assert reasons[0] == "High reason"
    assert reasons[1] == "Low reason"


# --- Engine ---

def test_engine_no_rules_returns_safe():
    engine = DetectionEngine(rules=[])
    result = engine.run(_make_email())
    assert result["label"] == Verdict.SAFE
    assert result["confidence"] == 0.0


def test_engine_runs_rules_and_aggregates():
    engine = DetectionEngine(rules=[FakeHighRule(), FakeLowRule()])
    result = engine.run(_make_email())
    assert result["label"] in (Verdict.SAFE, Verdict.SUSPICIOUS, Verdict.PHISHING)
    assert 0 <= result["confidence"] <= 1
    assert "fake_high" in result["signals"]
    assert "fake_low" in result["signals"]


def test_engine_skips_none_results():
    engine = DetectionEngine(rules=[FakeNoneRule(), FakeLowRule()])
    result = engine.run(_make_email())
    assert "fake_none" not in result["signals"]
    assert "fake_low" in result["signals"]
