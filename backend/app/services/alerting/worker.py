"""Alert notification worker (task 2.3, Section 2.5, Algorithm 3, NFR-09).

Runs as a SEPARATE process from the detection engine, which is what makes alert
processing asynchronous with respect to detection: the engine writes its
Detection rows, commits, and moves on. It never waits on a policy check or on
SendGrid, so a slow or failing mail provider cannot stall the detection
pipeline. This is the same process-separation model the engine itself uses.

Each cycle:

  1. Read detections newer than the stored watermark (see watermark.py).
  2. Skip any detection that already has an alerts row — the guard that makes a
     lost or reset watermark harmless.
  3. Suppress duplicates: the same source_ip + threat_type alerted within the
     last five minutes (Algorithm 3 applies this before the per-admin checks).
  4. For each recipient configuration: apply the severity threshold, then quiet
     hours — which CRITICAL always bypasses.
  5. Deliver, with an initial attempt plus three retries at 2s, 4s and 8s,
     writing the outcome to the alerts table as SENT, PENDING or FAILED.
  6. Advance and persist the watermark.

Run it (from backend/, venv active, DB up):
    python -m app.services.alerting.worker
"""
from __future__ import annotations

import logging
import signal
import time
from datetime import datetime, time as dtime, timedelta, timezone
from uuid import UUID
from zoneinfo import ZoneInfo

from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from ...config import settings
from ...database import SessionLocal
from .. import heartbeat
from ...models import (
    Alert, AlertChannel, AlertConfig, AlertStatus, DataSource, Detection,
    SeverityLevel,
)
from . import config_cache, watermark
from .renderer import render, subject_for
from .sender import AlertSender, get_sender

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s alert-worker %(levelname)s %(message)s")
logger = logging.getLogger("threatsense.alerting.worker")

# Ordering used by the severity threshold. alert_config stores CRITICAL / HIGH /
# MEDIUM / ALL, where ALL means "anything the engine chose to record".
_RANK = {
    SeverityLevel.LOW: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.HIGH: 3,
    SeverityLevel.CRITICAL: 4,
}
_THRESHOLD_RANK = {"ALL": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _val(enum_or_str) -> str:
    return getattr(enum_or_str, "value", str(enum_or_str))


def _backoff() -> list[int]:
    """Parse the retry schedule. Defaults to the specified 2s / 4s / 8s."""
    try:
        delays = [int(x) for x in settings.alert_retry_backoff.split(",") if x.strip()]
        return delays or [2, 4, 8]
    except ValueError:
        logger.warning("invalid ALERT_RETRY_BACKOFF %r — using 2,4,8",
                       settings.alert_retry_backoff)
        return [2, 4, 8]


# --- policy checks -----------------------------------------------------------

def meets_threshold(severity, threshold) -> bool:
    sev_rank = _RANK.get(
        severity if isinstance(severity, SeverityLevel) else SeverityLevel(_val(severity)), 0
    )
    return sev_rank >= _THRESHOLD_RANK.get(_val(threshold), 3)


def in_quiet_hours(now: dtime, start: dtime | None, end: dtime | None) -> bool:
    """True when `now` falls inside the window, handling overnight wrap-around."""
    if start is None or end is None or start == end:
        return False
    if start < end:                      # e.g. 01:00 -> 05:00, same day
        return start <= now < end
    return now >= start or now < end     # e.g. 22:00 -> 06:00, crosses midnight


def _local_now() -> dtime:
    """Wall-clock time used for quiet hours.

    alert_config stores bare TIME values with no zone, so they are interpreted
    against ALERT_QUIET_HOURS_TZ when set, otherwise the host's local time.
    Containers commonly run UTC, so set this explicitly (Australia/Sydney) if
    quiet hours must line up with an operator's working day.
    """
    tz_name = (settings.alert_quiet_hours_tz or "").strip()
    if tz_name:
        try:
            return datetime.now(ZoneInfo(tz_name)).time()
        except Exception:
            logger.warning("unknown ALERT_QUIET_HOURS_TZ %r — using system time", tz_name)
    return datetime.now().time()


def is_duplicate(db: Session, detection: Detection) -> bool:
    """Same source_ip + threat_type alerted inside the suppression window."""
    since = datetime.now(timezone.utc) - timedelta(minutes=settings.alert_dedup_minutes)
    hit = db.scalar(
        select(Alert.alert_id)
        .join(Detection, Alert.detection_id == Detection.detection_id)
        .where(
            Detection.source_ip == detection.source_ip,
            Detection.threat_type == detection.threat_type,
            Alert.created_at >= since,
            Alert.detection_id != detection.detection_id,
        )
        .limit(1)
    )
    return hit is not None


def recipients_for(db: Session, detection: Detection) -> list[AlertConfig]:
    """Which configurations should receive this detection.

    Phase 1 made data sources admin-owned, so by default only the admin who owns
    the source is notified. ALERT_FANOUT_ALL_ADMINS=true restores the literal
    Algorithm 3 behaviour of notifying every admin with email enabled.
    """
    if settings.alert_fanout_all_admins:
        configs = config_cache.all_configs(db)
    else:
        admin_id = db.scalar(
            select(DataSource.admin_id).where(DataSource.source_id == detection.source_id)
        )
        cfg = config_cache.get(db, admin_id) if admin_id else None
        configs = [cfg] if cfg else []
    return [c for c in configs if c and c.email_enabled and c.email_recipient]


# --- delivery ----------------------------------------------------------------

def deliver(db: Session, detection: Detection, config: AlertConfig,
            sender: AlertSender, sleep=time.sleep) -> Alert:
    """Send one alert, persisting the outcome and every retry to alerts.

    Initial attempt, then up to three retries at 2s / 4s / 8s (NFR-09). The row
    is written as PENDING the moment the first attempt fails, so an operator
    inspecting the table mid-retry sees work in progress rather than nothing.
    """
    subject = subject_for(detection)
    html = render(detection)
    to = config.email_recipient

    result = sender.send(to, subject, html)
    alert = Alert(
        detection_id=detection.detection_id,
        channel=AlertChannel.EMAIL,
        recipient=to,
        status=AlertStatus.SENT if result.success else AlertStatus.PENDING,
        retry_count=0,
        sent_at=datetime.now(timezone.utc) if result.success else None,
        error_message=result.error_message,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    if result.success:
        logger.info("alert SENT to %s for detection %s", to, detection.detection_id)
        return alert

    for attempt, delay in enumerate(_backoff(), start=1):
        sleep(delay)
        result = sender.send(to, subject, html)
        alert.retry_count = attempt
        alert.error_message = result.error_message
        if result.success:
            alert.status = AlertStatus.SENT
            alert.sent_at = datetime.now(timezone.utc)
            db.commit()
            logger.info("alert SENT to %s on retry %d", to, attempt)
            return alert
        db.commit()

    alert.status = AlertStatus.FAILED
    db.commit()
    logger.error("alert FAILED to %s after %d retries: %s",
                 to, alert.retry_count, alert.error_message)
    return alert


# --- cycle -------------------------------------------------------------------

def pending_detections(db: Session, mark: watermark.Watermark) -> list[Detection]:
    """Detections after the watermark, in (created_at, detection_id) order."""
    stmt = select(Detection).order_by(
        Detection.created_at, Detection.detection_id
    ).limit(settings.alert_batch_size)
    if mark.detection_id is None:
        stmt = stmt.where(Detection.created_at > mark.created_at)
    else:
        stmt = stmt.where(
            tuple_(Detection.created_at, Detection.detection_id)
            > (mark.created_at, mark.detection_id)
        )
    return list(db.scalars(stmt).all())


def already_alerted(db: Session, detection_id: UUID) -> bool:
    return db.scalar(
        select(Alert.alert_id).where(Alert.detection_id == detection_id).limit(1)
    ) is not None


def run_cycle(db: Session, sender: AlertSender, sleep=time.sleep) -> dict:
    """Evaluate one batch. Returns counters, which the tests assert against."""
    mark = watermark.load()
    detections = pending_detections(db, mark)
    stats = {"examined": 0, "sent": 0, "failed": 0, "suppressed": 0,
             "below_threshold": 0, "quiet_hours": 0, "no_recipient": 0,
             "already_alerted": 0}
    if not detections:
        return stats

    now_local = _local_now()
    for det in detections:
        stats["examined"] += 1
        mark = watermark.Watermark(det.created_at, det.detection_id)

        if already_alerted(db, det.detection_id):
            # Only reachable when the watermark was rewound or lost. Counted and
            # logged so a quiet cycle is never unexplained.
            stats["already_alerted"] += 1
            logger.info("detection %s already has an alert row — skipping",
                        det.detection_id)
            continue
        if is_duplicate(db, det):
            stats["suppressed"] += 1
            logger.info("suppressed duplicate %s / %s within %d min",
                        det.source_ip, _val(det.threat_type),
                        settings.alert_dedup_minutes)
            continue

        configs = recipients_for(db, det)
        if not configs:
            stats["no_recipient"] += 1
            continue

        for cfg in configs:
            if not meets_threshold(det.severity, cfg.severity_threshold):
                stats["below_threshold"] += 1
                continue
            critical = _val(det.severity) == SeverityLevel.CRITICAL.value
            if not critical and in_quiet_hours(now_local, cfg.quiet_start, cfg.quiet_end):
                stats["quiet_hours"] += 1
                logger.info("quiet hours: holding %s alert for %s",
                            _val(det.severity), cfg.email_recipient)
                continue
            alert = deliver(db, det, cfg, sender, sleep=sleep)
            stats["sent" if alert.status == AlertStatus.SENT else "failed"] += 1

    watermark.save(mark)
    return stats


def main() -> None:  # pragma: no cover - process entrypoint
    sender = get_sender()
    logger.info("alert worker starting (sender=%s, poll=%ds, dedup=%dmin)",
                sender.name, settings.alert_poll_seconds, settings.alert_dedup_minutes)
    running = True

    def _stop(*_):
        nonlocal running
        running = False
        logger.info("shutdown requested")

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    heartbeat.write("alert_worker", status="starting", sender=sender.name)
    stats = {}
    while running:
        try:
            with SessionLocal() as db:
                stats = run_cycle(db, sender)
            if stats["examined"]:
                logger.info("cycle: %s", stats)
        except Exception:
            # One bad cycle must never kill the worker.
            logger.exception("alert cycle failed; retrying next poll")
        heartbeat.write("alert_worker", last_cycle=stats,
                        poll_seconds=settings.alert_poll_seconds)
        for _ in range(settings.alert_poll_seconds):
            if not running:
                break
            time.sleep(1)
    logger.info("alert worker stopped")


if __name__ == "__main__":  # pragma: no cover
    main()
