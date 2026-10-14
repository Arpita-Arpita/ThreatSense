"""ThreatSense FastAPI entrypoint (task 1.3). Boots the app and exposes /health."""
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from .config import settings
from .database import SessionLocal, get_db
from .routers import (accounts, alerts, auth, dashboard, detections, reports,
                      settings as settings_router, sources)
from .services import heartbeat
from .services.alerting import config_cache

logger = logging.getLogger("threatsense.startup")


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Prime the alert_config cache at start-up (task 2.1, Section 2.5)."""
    try:
        with SessionLocal() as session:
            loaded = config_cache.prime(session)
        logger.info("alert_config cache primed with %d row(s)", loaded)
    except Exception:  # a cold DB must not stop the API from booting
        logger.warning("could not prime alert_config cache at start-up", exc_info=True)
    yield

app = FastAPI(title="ThreatSense API", version="0.1.0", lifespan=lifespan)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    # Content-Disposition carries the PDF filename; Retry-After carries the
    # report rate-limit wait. Neither is CORS-safelisted, so without this the
    # dashboard cannot read them (task 3.4).
    expose_headers=["Content-Disposition", "Retry-After"],
)


app.include_router(auth.router)
app.include_router(accounts.router)
app.include_router(sources.router)
app.include_router(detections.router)
# Section 2.4 / Algorithm 4 panel routes. Registered after detections because
# /api/dashboard/alerts delegates to that router's list handler.
app.include_router(dashboard.router)
app.include_router(alerts.router)
app.include_router(reports.router)
app.include_router(settings_router.router)


def _ingestion_health() -> dict:
    """Read the counters the listener publishes (see IngestionService.write_stats).

    The listener runs as a separate process, so this is a file read rather
    than an attribute lookup. Three distinct states are reported, and the
    caller needs to be able to tell them apart:

      unknown  — no stats file. The listener has never run since this file
                 was last cleared. NOT the same as "no drops".
      stale    — file older than ingestion_stats_stale_seconds. The listener
                 wrote at some point but is not writing now; treat the
                 counters as a last-known value, not a current one.
      up       — file fresh; counters are current.
    """
    path = Path(settings.ingestion_stats_path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"listener": "unknown"}

    try:
        updated = datetime.fromisoformat(data["updated_at"])
    except (KeyError, TypeError, ValueError):
        return {"listener": "unknown"}
    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=timezone.utc)

    age = (datetime.now(timezone.utc) - updated).total_seconds()
    fresh = age <= settings.ingestion_stats_stale_seconds
    return {
        "listener": "up" if fresh else "stale",
        "last_update_age_seconds": round(age, 1),
        "ingested_total": data.get("ingested_total"),
        "dropped_total": data.get("dropped_total"),
        "dropped_unknown_source_total": data.get("dropped_unknown_source_total"),
        "dropped_unparseable_total": data.get("dropped_unparseable_total"),
        "buffered_now": data.get("buffered_now"),
    }


@app.get("/health")
def health(db: Session = Depends(get_db)) -> dict:
    """Liveness + DB connectivity probe.

    NFR-06 measures availability from server access logs; this endpoint is
    what those logs record against, and the ingestion block below lets a
    reader distinguish "the API is up" from "the API is up and logs are
    actually arriving" — which are different availability claims.
    """
    try:
        db.execute(text("SELECT 1"))
        db_up = True
    except Exception:
        db_up = False
    return {
        "status": "ok" if db_up else "degraded",
        "database": "up" if db_up else "down",
        "env": settings.env,
        "ingestion": _ingestion_health(),
        # Phase 6.3: ThreatSense is four processes. Starting only some of them
        # fails silently — logs arrive with no detections, or detections
        # appear with no email — and nothing in the UI says why. This block
        # makes a missing background process visible.
        "processes": heartbeat.read_all(),
    }
