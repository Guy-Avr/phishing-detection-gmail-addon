"""
Ollama LLM provider (primary).

Uses the local Ollama REST API. No prompt logic here; receives full prompt string.
"""

import httpx

from app.detection.llm.base import LLMProvider


class OllamaProvider(LLMProvider):
    """
    Ollama provider: POST to /api/generate, stream=false, read response.response.
    """

    def __init__(self, base_url: str, model: str, timeout_sec: float) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout_sec = timeout_sec

    @property
    def name(self) -> str:
        return "ollama"

    def complete(self, prompt: str, timeout_sec: float) -> str:
        url = f"{self._base_url}/api/generate"
        payload = {"model": self._model, "prompt": prompt, "stream": False}
        timeout = min(timeout_sec, self._timeout_sec)
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
        data = resp.json()
        return (data.get("response") or "").strip()
