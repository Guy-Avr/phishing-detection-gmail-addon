"""Unit tests for the 4 detection rules."""

from app.detection.rules.html import HtmlRule
from app.detection.rules.language import LanguageRule
from app.detection.rules.links import LinksRule
from app.detection.rules.sender import SenderRule
from app.parsing.email_parser import ParsedEmail


def _email(**overrides) -> ParsedEmail:
    defaults = {
        "subject": "hello",
        "body_text": "normal body",
        "body_html": None,
        "sender": "user@example.com",
        "sender_domain": "example.com",
        "links": [],
    }
    defaults.update(overrides)
    return ParsedEmail(**defaults)


# --- LinksRule ---

class TestLinksRule:
    rule = LinksRule()

    def test_no_links_returns_none(self):
        assert self.rule.evaluate(_email()) is None

    def test_ip_link_fires(self):
        result = self.rule.evaluate(_email(links=["https://192.168.1.1/login"]))
        assert result is not None
        assert result.score > 0
        assert any("IP" in r for r in result.reasons)

    def test_shortener_fires(self):
        result = self.rule.evaluate(_email(links=["https://bit.ly/abc123"]))
        assert result is not None
        assert any("shortener" in r for r in result.reasons)

    def test_anchor_mismatch_fires(self):
        html = '<a href="https://evil.com">paypal.com</a>'
        result = self.rule.evaluate(_email(body_html=html, links=["https://evil.com"]))
        assert result is not None
        assert any("paypal.com" in r for r in result.reasons)

    def test_clean_link_returns_none(self):
        result = self.rule.evaluate(_email(links=["https://google.com"]))
        assert result is None


# --- SenderRule ---

class TestSenderRule:
    rule = SenderRule()

    def test_normal_sender_returns_none(self):
        assert self.rule.evaluate(_email()) is None

    def test_brand_on_free_email_fires(self):
        result = self.rule.evaluate(_email(
            sender="paypal-support@gmail.com",
            sender_domain="gmail.com",
        ))
        assert result is not None
        assert any("paypal" in r for r in result.reasons)

    def test_similar_domain_fires(self):
        result = self.rule.evaluate(_email(
            sender="support@paypa1.com",
            sender_domain="paypa1.com",
        ))
        assert result is not None
        assert any("resembles" in r for r in result.reasons)

    def test_exact_brand_domain_returns_none(self):
        result = self.rule.evaluate(_email(
            sender="support@paypal.com",
            sender_domain="paypal.com",
        ))
        assert result is None


# --- LanguageRule ---

class TestLanguageRule:
    rule = LanguageRule()

    def test_normal_text_returns_none(self):
        assert self.rule.evaluate(_email(body_text="Hey, how are you?")) is None

    def test_urgency_fires(self):
        result = self.rule.evaluate(_email(
            subject="urgent action required",
            body_text="verify your account immediately or it will be suspended",
        ))
        assert result is not None
        assert result.score > 0
        assert any("urgent" in r.lower() for r in result.reasons)

    def test_subject_urgency_fires(self):
        result = self.rule.evaluate(_email(subject="account locked final warning"))
        assert result is not None


# --- HtmlRule ---

class TestHtmlRule:
    rule = HtmlRule()

    def test_no_html_returns_none(self):
        assert self.rule.evaluate(_email()) is None

    def test_form_fires(self):
        html = '<form action="https://evil.com"><input type="text"></form>'
        result = self.rule.evaluate(_email(body_html=html))
        assert result is not None
        assert any("form" in r.lower() for r in result.reasons)

    def test_hidden_input_fires(self):
        html = '<input type="hidden" name="token" value="abc">'
        result = self.rule.evaluate(_email(body_html=html))
        assert result is not None
        assert any("hidden" in r.lower() for r in result.reasons)

    def test_onclick_fires(self):
        html = '<div onclick="steal()">Click me</div>'
        result = self.rule.evaluate(_email(body_html=html))
        assert result is not None
        assert any("JS" in r for r in result.reasons)

    def test_script_tag_fires(self):
        html = '<script>alert("xss")</script>'
        result = self.rule.evaluate(_email(body_html=html))
        assert result is not None
        assert any("script" in r.lower() for r in result.reasons)

    def test_clean_html_returns_none(self):
        html = '<p>Hello, this is a normal email.</p>'
        result = self.rule.evaluate(_email(body_html=html))
        assert result is None
