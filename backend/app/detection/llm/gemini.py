"""
Gemini LLM provider (fallback).

Uses Google Generative Language REST API. No prompt logic here; receives full prompt string.
"""

import httpx

from app.detection.llm.base import LLMProvider

_GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"


class GeminiProvider(LLMProvider):
    """
    Gemini provider: POST to generateContent with API key.
    """

    def __init__(self, api_key: str, model: str, timeout_sec: float) -> None:
        self._api_key = api_key
        self._model = model
        self._timeout_sec = timeout_sec

    @property
    def name(self) -> str:
        return "gemini"

    def complete(self, prompt: str, timeout_sec: float) -> str:
        url = f"{_GEMINI_BASE}/models/{self._model}:generateContent"
        params = {"key": self._api_key}
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
        }
        timeout = min(timeout_sec, self._timeout_sec)
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, params=params, json=payload)
            resp.raise_for_status()
        data = resp.json()
        try:
            parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
            text = (parts[0].get("text") or "").strip() if parts else ""
        except (IndexError, KeyError, TypeError):
            text = ""
        return text
