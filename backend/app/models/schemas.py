"""Pydantic request/response schemas for the scan API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.core.enums import Verdict


class ScanRequest(BaseModel):
    """
    Request body for POST /scan.

    The addon sends the full raw email (RFC-style, as returned by
    GmailMessage.getRawContent()). The backend does all the parsing.
    """

    raw: str = Field(..., min_length=1, description="Full raw RFC email content")


class ScanResponse(BaseModel):
    """
    Response body for POST /scan.

    label:      Verdict enum (Safe / Suspicious / Phishing).
    confidence: Aggregate score in [0, 1].
    reasons:    Human-readable explanations, ordered by relevance.
    signals:    Map of rule_id -> score (0-1) for transparency.
    metadata:   Optional extra info (e.g. processing_ms, version).
    """

    label: Verdict
    confidence: float = Field(..., ge=0, le=1)
    reasons: list[str] = Field(default_factory=list)
    signals: dict[str, float] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
