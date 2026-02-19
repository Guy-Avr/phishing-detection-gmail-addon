"""Tests for API endpoints: health and scan."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_scan_with_raw_email():
    raw = (
        "Subject: Verify your account\r\n"
        "From: Support <phishing@evil.com>\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        '<html><body><a href="https://evil.com/steal">Click here</a></body></html>'
    )
    response = client.post("/scan", json={"raw": raw})
    assert response.status_code == 200
    data = response.json()
    assert data["label"] in ("Safe", "Suspicious", "Phishing")
    assert 0 <= data["confidence"] <= 1
    assert isinstance(data["reasons"], list)
    assert isinstance(data["signals"], dict)
    assert "processing_ms" in data["metadata"]
    assert "sender_domain" in data["metadata"]


def test_scan_empty_raw_rejected():
    response = client.post("/scan", json={"raw": ""})
    assert response.status_code == 422


def test_scan_missing_raw_rejected():
    response = client.post("/scan", json={})
    assert response.status_code == 422
