"""Processing watermark for the alert worker (task 2.3).

Why this exists
---------------
The detection engine (task 1.12) writes Detection rows and nothing else — there
is no notification queue in the codebase. The worker therefore polls the
detections table. "Rows with no matching alerts row" is not a usable poll
condition on its own, because a detection that was below the severity
threshold, suppressed as a duplicate, or skipped during quiet hours never
produces an alerts row, and would be re-examined on every cycle forever.

So the worker keeps a watermark: the (created_at, detection_id) of the last
detection it evaluated. The pair is ordered lexicographically, which gives a
total order even when several detections share a timestamp.

The watermark lives in a small JSON file rather than a database column because
the nine-table schema is fixed by the proposal and adding a column would be a
schema change. It is advisory, not authoritative: if the file is lost the
worker resumes from the current time, and the duplicate guard in the worker
(an alerts row already exists for that detection) stops anything that was
already emailed from being emailed twice.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

from ...config import settings

logger = logging.getLogger("threatsense.alerting.watermark")


@dataclass(frozen=True)
class Watermark:
    created_at: datetime
    detection_id: UUID | None = None

    def as_dict(self) -> dict:
        return {
            "created_at": self.created_at.isoformat(),
            "detection_id": str(self.detection_id) if self.detection_id else None,
        }


def _path() -> Path:
    p = Path(settings.alert_worker_state_path)
    if not p.is_absolute():
        # Anchor to backend/ so the worker behaves the same from any cwd.
        p = Path(__file__).resolve().parents[3] / p
    return p


def load() -> Watermark:
    """Read the stored watermark, or start from the configured lookback."""
    path = _path()
    if path.exists():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            created = datetime.fromisoformat(raw["created_at"])
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            det_id = raw.get("detection_id")
            return Watermark(created, UUID(det_id) if det_id else None)
        except (ValueError, KeyError, OSError, json.JSONDecodeError):
            logger.warning("unreadable watermark at %s — restarting from now", path,
                           exc_info=True)

    start = datetime.now(timezone.utc) - timedelta(
        minutes=max(0, settings.alert_initial_lookback_minutes)
    )
    mark = Watermark(start, None)
    # Persist immediately. If a synthesised start were left unsaved, every idle
    # cycle would re-anchor it to "now", and a detection created between two
    # idle cycles would fall behind the moving mark and never be alerted.
    try:
        save(mark)
    except OSError:
        logger.warning("could not persist initial watermark to %s", _path(), exc_info=True)
    logger.info("no watermark found — starting from %s", start.isoformat())
    return mark


def save(mark: Watermark) -> None:
    """Persist atomically, so a crash mid-write cannot corrupt the file."""
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(mark.as_dict(), indent=2), encoding="utf-8")
    tmp.replace(path)


def reset() -> None:
    _path().unlink(missing_ok=True)
