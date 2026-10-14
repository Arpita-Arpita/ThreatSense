"""Cross-process liveness heartbeats (Phase 6.3).

    from app.services import heartbeat
    heartbeat.write("detection_engine", last_cycle_logs=1001)
    heartbeat.read("detection_engine")

WHY THIS EXISTS
---------------
ThreatSense runs as four processes against one database: the API, the syslog
listener, the detection engine, and the alert worker. Section 2.3 makes the
engine a scheduled background job and Section 2.5 makes alerting asynchronous
"so it does not delay the detection pipeline", so the split is by design.

The problem found during the Phase 6.3 dry run is that starting only some of
them fails SILENTLY. With the engine down, logs arrive and no detection is
ever created. With the worker down, detections appear and no email is ever
sent. Neither produces an error anywhere — the dashboard looks healthy, the
API returns 200, and the operator concludes the feature is broken.

Both of those happened during the dry run, and each cost a diagnosis cycle.

Each background process writes a small heartbeat file; /health reads them and
reports up / stale / unknown per process, exactly as it already does for the
listener's ingestion counters. A missing heartbeat is reported as "unknown"
rather than "down": the file only proves a process HAS run, and claiming a
process is down when we merely have no evidence would be the same overreach
as reporting a zero drop count for a listener that never started.

Writes are atomic (temp file plus rename) and failures are swallowed and
logged: telemetry must never be able to stop the pipeline it observes.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from ..config import settings

logger = logging.getLogger("threatsense.heartbeat")

# Components that /health reports on. The listener is deliberately NOT here:
# it already publishes richer telemetry through ingestion_stats_path, and a
# second file for the same process would be one more thing to keep in step.
COMPONENTS = ("detection_engine", "alert_worker")


def path_for(component: str) -> Path:
    return Path(settings.heartbeat_dir) / f"heartbeat_{component}.json"


def write(component: str, **fields) -> None:
    """Publish a heartbeat for this component. Never raises."""
    payload = {"component": component,
               "updated_at": datetime.now(timezone.utc).isoformat(),
               **fields}
    path = path_for(component)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(path)                     # atomic on POSIX
    except OSError as exc:
        logger.warning("could not write heartbeat for %s: %s", component, exc)


def read(component: str) -> dict:
    """Report one component's state: up, stale, or unknown.

    'unknown' means no usable heartbeat file — the process may never have
    started, or the file may have been cleared. It is NOT a claim that the
    process is down.
    """
    try:
        data = json.loads(path_for(component).read_text(encoding="utf-8"))
        updated = datetime.fromisoformat(data["updated_at"])
    except (OSError, ValueError, KeyError, TypeError):
        return {"state": "unknown"}

    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - updated).total_seconds()

    out = {k: v for k, v in data.items()
           if k not in ("component", "updated_at")}
    out["state"] = "up" if age <= settings.heartbeat_stale_seconds else "stale"
    out["last_seen_age_seconds"] = round(age, 1)
    return out


def read_all() -> dict:
    return {c: read(c) for c in COMPONENTS}
