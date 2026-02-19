"""Tests for detection: aggregator, engine, and real rules with complex scenarios."""

from unittest.mock import patch

from app.core.enums import Verdict
from app.detection.aggregator import aggregate
from app.detection.engine import DetectionEngine
from app.detection.rules.base import BaseRule, RuleResult
from app.detection.rules.html import HtmlRule
from app.detection.rules.language import LanguageRule
from app.detection.rules.links import LinksRule
from app.detection.rules.sender import SenderRule
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


def _real_engine(phish_db_path: str | None = None) -> DetectionEngine:
    return DetectionEngine(
        rules=[LinksRule(), SenderRule(), LanguageRule(), HtmlRule()],
        phish_db_path=phish_db_path,
    )


# --- Fake rules for unit-style engine tests ---


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
    """Rule that does not fire (returns None)."""

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


# --- Engine with fake rules ---


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


# --- Real rules: clean email ---


def test_clean_email_all_rules_participate_safe():
    """Fully clean email: all rules return 0, confidence stays 0, verdict Safe."""
    email = _make_email(
        subject="monthly report",
        body_text="please find the report attached.",
        sender="colleague@company.com",
        sender_domain="company.com",
        links=[],
    )
    engine = _real_engine()
    result = engine.run(email)
    assert result["label"] == Verdict.SAFE
    assert result["confidence"] == 0.0
    assert "links" in result["signals"]
    assert "sender" in result["signals"]
    assert "language" in result["signals"]
    assert "html" in result["signals"]
    assert result["signals"]["links"] == 0.0
    assert result["signals"]["sender"] == 0.0
    assert result["signals"]["language"] == 0.0
    assert result["signals"]["html"] == 0.0


# --- Real rules: sender ---


def test_sender_distorted_local_paypa1_scores_one():
    """paypa1@gmail.com: local resembles paypal but not exact -> sender 1.0."""
    email = _make_email(
        sender="paypa1-notify@gmail.com",
        sender_domain="gmail.com",
    )
    engine = _real_engine()
    result = engine.run(email)
    assert result["signals"]["sender"] == 1.0
    assert any("resembles" in r.lower() or "brand" in r.lower() for r in result["reasons"])


def test_sender_exact_brand_on_free_scores_half():
    """paypal@gmail.com: exact brand on free email -> sender 0.5."""
    email = _make_email(
        sender="paypal@gmail.com",
        sender_domain="gmail.com",
    )
    engine = _real_engine()
    result = engine.run(email)
    assert result["signals"]["sender"] == 0.5
    assert any("paypal" in r.lower() for r in result["reasons"])


def test_sender_domain_spoof_scores_one():
    """user@paypa1.com: domain resembles brand but not exact -> 1.0."""
    email = _make_email(
        sender="support@paypa1.com",
        sender_domain="paypa1.com",
    )
    engine = _real_engine()
    result = engine.run(email)
    assert result["signals"]["sender"] == 1.0
    assert any("domain" in r.lower() and "resembles" in r.lower() for r in result["reasons"])


def test_sender_legitimate_not_flagged():
    """support@paypal.com: real domain, not free email -> sender 0."""
    email = _make_email(
        sender="support@paypal.com",
        sender_domain="paypal.com",
    )
    engine = _real_engine()
    result = engine.run(email)
    assert result["signals"]["sender"] == 0.0


# --- Real rules: links ---


def test_links_ip_and_anchor_mismatch_cap_one():
    """IP host + display/href mismatch -> links score 1.0 (0.5+0.5)."""
    email = _make_email(
        body_html=(
            '<a href="http://192.168.1.1/login">https://paypal.com/secure</a>'
        ),
        links=["http://192.168.1.1/login", "https://paypal.com/secure"],
    )
    engine = _real_engine()
    result = engine.run(email)
    assert result["signals"]["links"] == 1.0
    assert any("IP" in r or "192" in r for r in result["reasons"])
    assert any("points to" in r or "display" in r.lower() for r in result["reasons"])


def test_anchor_plain_click_me_not_counted_as_mismatch():
    """Display 'click me' with href to evil.com -> no anchor mismatch (plain text)."""
    email = _make_email(
        body_html='<a href="http://evil.com/phish">click me</a>',
        links=["http://evil.com/phish"],
    )
    engine = _real_engine()
    result = engine.run(email)
    # No mismatch reason (display is not URL-like); may have other link signals or none
    mismatch_reasons = [r for r in result["reasons"] if "points to" in r or "display text" in r.lower()]
    assert len(mismatch_reasons) == 0


# --- Real rules: language ---


def test_language_heavy_urgency_scores_high():
    """Many urgency phrases relative to text length -> language ~1.0."""
    email = _make_email(
        subject="urgent verify your account immediately",
        body_text="your account has been suspended. action required within 24 hours. verify immediately.",
    )
    engine = _real_engine()
    result = engine.run(email)
    assert result["signals"]["language"] >= 0.5
    assert any("urgency" in r.lower() or "phrase" in r.lower() for r in result["reasons"])


# --- Real rules: HTML ---


def test_html_form_and_hidden_input_scores_high():
    """Form + hidden input -> html weight sum, score >= 0.85."""
    email = _make_email(
        body_html=(
            '<form action="http://evil.com/collect">'
            '<input type="hidden" name="t" value="x"/>'
            '<input type="submit" value="Confirm"/>'
            '</form>'
        ),
    )
    engine = _real_engine()
    result = engine.run(email)
    assert result["signals"]["html"] >= 0.8
    assert any("form" in r.lower() for r in result["reasons"])
    assert any("hidden" in r.lower() for r in result["reasons"])


# --- Full phishing scenario ---


def test_full_phishing_email_verdict_phishing():
    """Combined: distorted sender + IP link + mismatch + urgency + form + hidden -> Phishing."""
    email = _make_email(
        subject="urgent verify your account immediately",
        body_text="your account has been suspended. action required within 24 hours.",
        body_html=(
            '<p>verify now.</p>'
            '<a href="http://10.0.0.1/fake">https://paypal.com/secure</a>'
            '<form action="http://evil.com"><input type="hidden" name="x" value="1"/><input type="submit" value="OK"/></form>'
        ),
        sender="paypa1-notify@gmail.com",
        sender_domain="gmail.com",
        links=["http://10.0.0.1/fake", "https://paypal.com/secure"],
    )
    engine = _real_engine()
    result = engine.run(email)
    assert result["label"] == Verdict.PHISHING
    assert result["confidence"] >= 0.7
    assert result["signals"]["sender"] == 1.0
    assert result["signals"]["links"] >= 0.5
    assert result["signals"]["language"] >= 0.3
    assert result["signals"]["html"] >= 0.5


# --- OpenPhish override ---


def test_openphish_match_forces_confidence_one_and_phishing():
    """When a link is in the threat feed, verdict must be Phishing and confidence 1.0."""
    email = _make_email(links=["http://known-phish.example.com/login"])
    engine = _real_engine(phish_db_path="/nonexistent/path.db")
    with patch("app.reputation.openphish.lookup_phish_urls") as mock_lookup:
        mock_lookup.return_value = [
            ("http://known-phish.example.com/login", "openphish"),
        ]
        result = engine.run(email)
    assert result["label"] == Verdict.PHISHING
    assert result["confidence"] == 1.0
    assert "openphish" in result["signals"]
    assert result["signals"]["openphish"] == 1.0


def test_openphish_no_match_no_override():
    """When no link is in the feed, normal aggregation (no forced 1.0)."""
    email = _make_email(links=["http://legitimate-site.com"])
    engine = _real_engine(phish_db_path="/nonexistent/path.db")
    with patch("app.reputation.openphish.lookup_phish_urls") as mock_lookup:
        mock_lookup.return_value = []
        result = engine.run(email)
    assert "openphish" not in result["signals"]
    assert result["confidence"] < 1.0
