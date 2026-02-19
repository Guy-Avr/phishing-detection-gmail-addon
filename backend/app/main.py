"""FastAPI application entry point."""

import logging
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI

from app.api.endpoints import health, scan
from app.core.constants import FEED_UPDATE_INTERVAL_HOURS
from app.settings import settings

logger = logging.getLogger(__name__)
# Ensure phish feed update logs are visible (uvicorn often sets root to WARNING)
if not logger.handlers:
    _h = logging.StreamHandler(sys.stderr)
    _h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)


def _run_phish_feed_update() -> None:
    try:
        from app.reputation.openphish import update_phish_db
        count, last_updated = update_phish_db(settings.phish_db_path)
        logger.info("Phish feed updated: %d URLs, last_updated=%s", count, last_updated)
    except Exception as e:
        logger.warning("Phish feed update failed: %s", e, exc_info=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler = BackgroundScheduler()
    # First run 10s after startup, then every FEED_UPDATE_INTERVAL_HOURS
    first_run = datetime.now(timezone.utc) + timedelta(seconds=10)
    scheduler.add_job(
        _run_phish_feed_update,
        "interval",
        hours=FEED_UPDATE_INTERVAL_HOURS,
        start_date=first_run,
    )
    scheduler.start()
    logger.info(
        "Phish feed auto-update scheduled: first run in 10s, then every %sh",
        FEED_UPDATE_INTERVAL_HOURS,
    )
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(
    title=settings.app_name,
    debug=settings.debug,
    lifespan=lifespan,
)

app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(scan.router, prefix="/scan", tags=["scan"])
