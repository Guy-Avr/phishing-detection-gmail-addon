"""
Provider-agnostic LLM abstraction.

Defines the interface that all providers (Ollama, Gemini) must implement,
and the normalized result type (LLMResult) used by the analyzer.
No business logic here; providers only perform I/O and return raw text.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class LLMResult:
    """
    Normalized output from any LLM provider.

    risk_score: 0–1 from the model (or 0.0 on failure/fallback).
    reasons: up to 3 short strings from the model (empty on failure).
    provider: which provider produced this (for logging/debugging).
    """

    risk_score: float
    reasons: tuple[str, ...]
    provider: str


class LLMProvider(ABC):
    """
    Abstract interface for LLM providers.

    Caller passes a single prompt string (built by prompt.py).
    Provider returns raw response text; analyzer parses and normalizes to LLMResult.
    Providers do not contain prompt logic or business rules.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider identifier (e.g. 'ollama', 'gemini')."""
        ...

    @abstractmethod
    def complete(self, prompt: str, timeout_sec: float) -> str:
        """
        Send prompt to the LLM and return the raw response body as string.

        Raises on network/API errors or timeout; analyzer catches and fallbacks.
        """
        ...
