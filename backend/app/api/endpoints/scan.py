"""POST /scan — receive raw email from addon and return detection result."""

import time

from fastapi import APIRouter, HTTPException

from app.detection.engine import DetectionEngine
from app.detection.rules.html import HtmlRule
from app.detection.rules.language import LanguageRule
from app.detection.rules.links import LinksRule
from app.detection.rules.sender import SenderRule
from app.models.schemas import ScanRequest, ScanResponse
from app.parsing import parse_raw_email
from app.settings import settings

router = APIRouter()

_engine = DetectionEngine(
    rules=[
        LinksRule(),
        SenderRule(),
        LanguageRule(),
        HtmlRule(),
    ],
    phish_db_path=settings.phish_db_path,
)


@router.post("", response_model=ScanResponse)
def scan_email(request: ScanRequest) -> ScanResponse:
    """
    Main endpoint. The addon sends { "raw": "<full RFC email>" }.
    Backend parses, runs detection, and returns label + confidence + reasons.
    """
    start = time.time()

    try:
        parsed = parse_raw_email(request.raw)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Failed to parse email: {exc}")

    result = _engine.run(parsed)
    processing_ms = round((time.time() - start) * 1000, 1)

    metadata: dict = {
        "processing_ms": processing_ms,
        "links_found": len(parsed.links),
        "sender_domain": parsed.sender_domain,
    }
    if settings.phish_db_path:
        try:
            from app.reputation.openphish import get_last_updated
            last = get_last_updated(settings.phish_db_path)
            if last is not None:
                metadata["feed_last_updated"] = last
        except Exception:
            pass

    return ScanResponse(
        label=result["label"],
        confidence=result["confidence"],
        reasons=result["reasons"],
        signals=result["signals"],
        metadata=metadata,
    )
