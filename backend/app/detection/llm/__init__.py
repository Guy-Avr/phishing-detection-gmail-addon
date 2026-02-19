"""
LLM analysis layer for phishing detection.

Invoked only when rule-based verdict is Suspicious. Provider-agnostic abstraction
with Ollama (primary) and Gemini (fallback). Never raises to caller; on total
failure returns safe fallback and leaves rule-based result unchanged.
"""

from app.detection.llm.analyzer import LLMAnalyzer
from app.detection.llm.base import LLMResult

__all__ = ["LLMAnalyzer", "LLMResult"]
