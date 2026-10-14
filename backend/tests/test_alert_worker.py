"""Integration tests for the alert worker (task 2.3, Algorithm 3, NFR-09).

Runs against real PostgreSQL with a mock sender, so the whole pipeline — poll,
watermark, duplicate suppression, severity threshold, quiet hours, retry
schedule and alerts rows — is exercised without a SendGrid account.

    cd backend && source .venv/bin/activate
    pytest tests/test_alert_worker.py -v
"""
from __future__ import annotations

import uuid
from datetime import datetime, time as dtime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.core.security import hash_password
from app.database import SessionLocal
from app.models import (
    AdminRole, Administrator, Alert, AlertConfig, AlertSeverityThreshold,
    AlertStatus, DataSource, Detection, SeverityLevel, SourceStatus, SourceType,
    ThreatType,
)
from app.services.alerting import config_cache, watermark
from app.services.alerting.sender import MockSender
from app.services.alerting.worker import (
    deliver, in_quiet_hours, is_duplicate, meets_threshold, run_cycle,
)

NO_SLEEP = lambda _s: None   # noqa: E731 - collapse retry backoff in tests


@pytest.fixture()
def env():
    """A private admin + source, with the watermark parked just before its data."""
    email = f"worker-{uuid.uuid4().hex[:8]}@threatsense.local"
    with SessionLocal() as db:
        admin = Administrator(full_name="Worker Test", email=email,
                              # NFR-11: hash_password now rejects non-compliant
                              # passwords, so this fixture value changed from
                              # "x". The admin here never logs in; the hash is
                              # only needed to satisfy the NOT NULL column.
                              password_hash=hash_password("TestPassw0rd!"),
                              role=AdminRole.ADMIN)
        db.add(admin)
        db.flush()
        cfg = AlertConfig(admin_id=admin.admin_id, email_enabled=True,
                          email_recipient=email,
                          severity_threshold=AlertSeverityThreshold.HIGH)
        source = DataSource(admin_id=admin.admin_id, name=f"src-{uuid.uuid4().hex[:6]}",
                            type=SourceType.SYSLOG, status=SourceStatus.ACTIVE)
        db.add_all([cfg, source])
        db.commit()
        ids = {"admin_id": admin.admin_id, "source_id": source.source_id,
               "email": email}

    config_cache.invalidate()
    watermark.save(watermark.Watermark(datetime.now(timezone.utc) - timedelta(seconds=1)))
    yield ids

    with SessionLocal() as db:
        det_ids = db.scalars(select(Detection.detection_id)
                             .where(Detection.source_id == ids["source_id"])).all()
        if det_ids:
            db.query(Alert).filter(Alert.detection_id.in_(det_ids)).delete(
                synchronize_session=False)
        db.query(Detection).filter(Detection.source_id == ids["source_id"]).delete(
            synchronize_session=False)
        db.query(DataSource).filter(DataSource.source_id == ids["source_id"]).delete()
        db.query(AlertConfig).filter(AlertConfig.admin_id == ids["admin_id"]).delete()
        db.query(Administrator).filter(Administrator.admin_id == ids["admin_id"]).delete()
        db.commit()
    watermark.reset()
    config_cache.invalidate()


def make_detection(source_id, severity=SeverityLevel.CRITICAL,
                   threat=ThreatType.PORT_SCAN, source_ip="203.0.113.10",
                   score=0.96) -> uuid.UUID:
    with SessionLocal() as db:
        det = Detection(
            source_id=source_id, source_ip=source_ip, destination_ip="192.168.1.1",
            timestamp=datetime.now(timezone.utc), anomaly_score=score,
            severity=severity, threat_type=threat, model_version="IF_v1.0",
            model_type="ISOLATION_FOREST", feature_vector={"pps": 4520, "unique_ports": 847},
        )
        db.add(det)
        db.commit()
        return det.detection_id


def alerts_for(detection_id) -> list[Alert]:
    with SessionLocal() as db:
        return list(db.scalars(
            select(Alert).where(Alert.detection_id == detection_id)).all())


# --- policy units ------------------------------------------------------------

@pytest.mark.parametrize("severity,threshold,expected", [
    (SeverityLevel.CRITICAL, "HIGH", True),
    (SeverityLevel.HIGH, "HIGH", True),
    (SeverityLevel.MEDIUM, "HIGH", False),
    (SeverityLevel.LOW, "ALL", True),
    (SeverityLevel.MEDIUM, "CRITICAL", False),
    (SeverityLevel.MEDIUM, "MEDIUM", True),
])
def test_severity_threshold(severity, threshold, expected):
    assert meets_threshold(severity, threshold) is expected


@pytest.mark.parametrize("now,expected", [
    (dtime(23, 0), True),    # inside an overnight window
    (dtime(2, 0), True),     # after midnight, still inside
    (dtime(6, 0), False),    # end is exclusive
    (dtime(12, 0), False),
    (dtime(22, 0), True),    # start is inclusive
])
def test_overnight_quiet_window(now, expected):
    assert in_quiet_hours(now, dtime(22, 0), dtime(6, 0)) is expected


@pytest.mark.parametrize("now,expected", [
    (dtime(2, 0), True), (dtime(6, 0), False), (dtime(0, 30), False),
])
def test_same_day_quiet_window(now, expected):
    assert in_quiet_hours(now, dtime(1, 0), dtime(5, 0)) is expected


def test_quiet_hours_disabled_when_unset():
    assert in_quiet_hours(dtime(23, 0), None, None) is False


# --- happy path --------------------------------------------------------------

def test_detection_produces_email_and_sent_alert_row(env):
    det_id = make_detection(env["source_id"])
    sender = MockSender()
    with SessionLocal() as db:
        stats = run_cycle(db, sender, sleep=NO_SLEEP)

    assert stats["sent"] == 1
    assert len(sender.sent) == 1
    assert sender.sent[0]["to"] == env["email"]
    assert "CRITICAL" in sender.sent[0]["subject"]

    rows = alerts_for(det_id)
    assert len(rows) == 1
    assert rows[0].status == AlertStatus.SENT
    assert rows[0].retry_count == 0
    assert rows[0].sent_at is not None
    assert rows[0].error_message is None


def test_email_body_contains_detection_detail(env):
    make_detection(env["source_id"], score=0.96)
    sender = MockSender()
    with SessionLocal() as db:
        run_cycle(db, sender, sleep=NO_SLEEP)
    html = sender.sent[0]["html"]
    for fragment in ("Port scan", "CRITICAL", "203.0.113.10", "0.96", "IF_v1.0"):
        assert fragment in html


# --- watermark ---------------------------------------------------------------

def test_watermark_stops_reprocessing(env):
    make_detection(env["source_id"])
    sender = MockSender()
    with SessionLocal() as db:
        assert run_cycle(db, sender, sleep=NO_SLEEP)["sent"] == 1
        second = run_cycle(db, sender, sleep=NO_SLEEP)
    assert second["examined"] == 0
    assert len(sender.sent) == 1


def test_skipped_detection_is_not_re_examined(env):
    """A below-threshold detection has no alerts row, yet must not be re-read."""
    make_detection(env["source_id"], severity=SeverityLevel.MEDIUM)
    sender = MockSender()
    with SessionLocal() as db:
        first = run_cycle(db, sender, sleep=NO_SLEEP)
        second = run_cycle(db, sender, sleep=NO_SLEEP)
    assert first["below_threshold"] == 1 and first["sent"] == 0
    assert second["examined"] == 0


def test_lost_watermark_does_not_resend(env):
    """The alerts-row guard protects against a deleted or reset state file."""
    det_id = make_detection(env["source_id"])
    sender = MockSender()
    with SessionLocal() as db:
        run_cycle(db, sender, sleep=NO_SLEEP)
    # Rewind to just before THIS detection only. A blanket rewind would sweep in
    # unrelated rows already in the database and make the test order-dependent.
    with SessionLocal() as db:
        created = db.get(Detection, det_id).created_at
    watermark.save(watermark.Watermark(created - timedelta(milliseconds=1)))
    with SessionLocal() as db:
        stats = run_cycle(db, sender, sleep=NO_SLEEP)
    assert stats["sent"] == 0
    assert len(sender.sent) == 1
    assert len(alerts_for(det_id)) == 1


# --- suppression and policy --------------------------------------------------

def test_duplicate_within_window_is_suppressed(env):
    make_detection(env["source_id"], source_ip="203.0.113.55")
    sender = MockSender()
    with SessionLocal() as db:
        run_cycle(db, sender, sleep=NO_SLEEP)
    make_detection(env["source_id"], source_ip="203.0.113.55")
    with SessionLocal() as db:
        stats = run_cycle(db, sender, sleep=NO_SLEEP)
    assert stats["suppressed"] == 1
    assert len(sender.sent) == 1


def test_different_threat_type_is_not_suppressed(env):
    make_detection(env["source_id"], source_ip="203.0.113.60",
                   threat=ThreatType.PORT_SCAN)
    sender = MockSender()
    with SessionLocal() as db:
        run_cycle(db, sender, sleep=NO_SLEEP)
    make_detection(env["source_id"], source_ip="203.0.113.60", threat=ThreatType.DDOS)
    with SessionLocal() as db:
        stats = run_cycle(db, sender, sleep=NO_SLEEP)
    assert stats["suppressed"] == 0 and stats["sent"] == 1


def test_old_alert_outside_window_does_not_suppress(env):
    det_id = make_detection(env["source_id"], source_ip="203.0.113.70")
    sender = MockSender()
    with SessionLocal() as db:
        run_cycle(db, sender, sleep=NO_SLEEP)
        old = db.scalar(select(Alert).where(Alert.detection_id == det_id))
        old.created_at = datetime.now(timezone.utc) - timedelta(minutes=30)
        db.commit()
    make_detection(env["source_id"], source_ip="203.0.113.70")
    with SessionLocal() as db:
        stats = run_cycle(db, sender, sleep=NO_SLEEP)
    assert stats["suppressed"] == 0 and stats["sent"] == 1


def test_below_threshold_is_not_emailed(env):
    make_detection(env["source_id"], severity=SeverityLevel.MEDIUM)
    sender = MockSender()
    with SessionLocal() as db:
        stats = run_cycle(db, sender, sleep=NO_SLEEP)
    assert stats["below_threshold"] == 1 and not sender.sent


def test_email_disabled_means_no_delivery(env):
    with SessionLocal() as db:
        cfg = db.scalar(select(AlertConfig)
                        .where(AlertConfig.admin_id == env["admin_id"]))
        cfg.email_enabled = False
        db.commit()
    config_cache.invalidate()
    make_detection(env["source_id"])
    sender = MockSender()
    with SessionLocal() as db:
        stats = run_cycle(db, sender, sleep=NO_SLEEP)
    assert stats["no_recipient"] == 1 and not sender.sent


def _set_quiet_hours_around_now(admin_id):
    """A window guaranteed to contain the current time."""
    now = datetime.now()
    with SessionLocal() as db:
        cfg = db.scalar(select(AlertConfig).where(AlertConfig.admin_id == admin_id))
        cfg.quiet_start = (now - timedelta(hours=1)).time()
        cfg.quiet_end = (now + timedelta(hours=1)).time()
        cfg.severity_threshold = AlertSeverityThreshold.MEDIUM
        db.commit()
    config_cache.invalidate()


def test_quiet_hours_hold_non_critical(env):
    _set_quiet_hours_around_now(env["admin_id"])
    make_detection(env["source_id"], severity=SeverityLevel.HIGH)
    sender = MockSender()
    with SessionLocal() as db:
        stats = run_cycle(db, sender, sleep=NO_SLEEP)
    assert stats["quiet_hours"] == 1 and not sender.sent


def test_critical_bypasses_quiet_hours(env):
    _set_quiet_hours_around_now(env["admin_id"])
    make_detection(env["source_id"], severity=SeverityLevel.CRITICAL)
    sender = MockSender()
    with SessionLocal() as db:
        stats = run_cycle(db, sender, sleep=NO_SLEEP)
    assert stats["sent"] == 1 and len(sender.sent) == 1


# --- retry behaviour ---------------------------------------------------------

def test_retry_succeeds_on_second_attempt(env):
    det_id = make_detection(env["source_id"])
    sender = MockSender(fail_times=1)
    delays: list[int] = []
    with SessionLocal() as db:
        stats = run_cycle(db, sender, sleep=delays.append)
    assert stats["sent"] == 1
    assert delays == [2]                      # one retry, first backoff step
    row = alerts_for(det_id)[0]
    assert row.status == AlertStatus.SENT
    assert row.retry_count == 1
    assert row.sent_at is not None


def test_all_retries_exhausted_marks_failed(env):
    det_id = make_detection(env["source_id"])
    sender = MockSender(fail_forever=True)
    delays: list[int] = []
    with SessionLocal() as db:
        stats = run_cycle(db, sender, sleep=delays.append)
    assert stats["failed"] == 1
    assert delays == [2, 4, 8]                # the specified schedule, in order
    row = alerts_for(det_id)[0]
    assert row.status == AlertStatus.FAILED
    assert row.retry_count == 3               # initial attempt + 3 retries
    assert row.sent_at is None
    assert row.error_message


def test_row_is_pending_between_attempts(env):
    """A row must exist as PENDING while retries are still running."""
    det_id = make_detection(env["source_id"])
    seen: list[AlertStatus] = []

    def observe(_delay):
        seen.append(alerts_for(det_id)[0].status)

    with SessionLocal() as db:
        deliver(db, db.get(Detection, det_id),
                db.scalar(select(AlertConfig)
                          .where(AlertConfig.admin_id == env["admin_id"])),
                MockSender(fail_times=2), sleep=observe)
    assert seen[0] == AlertStatus.PENDING


def test_failed_send_records_error_message(env):
    det_id = make_detection(env["source_id"])
    with SessionLocal() as db:
        run_cycle(db, MockSender(fail_forever=True), sleep=NO_SLEEP)
    assert "simulated delivery failure" in alerts_for(det_id)[0].error_message


# --- ordering / batching -----------------------------------------------------

def test_multiple_detections_all_processed_in_order(env):
    ids = [make_detection(env["source_id"], source_ip=f"203.0.113.{i}")
           for i in (101, 102, 103)]
    sender = MockSender()
    with SessionLocal() as db:
        stats = run_cycle(db, sender, sleep=NO_SLEEP)
    assert stats["sent"] == 3
    assert all(len(alerts_for(i)) == 1 for i in ids)


def test_is_duplicate_helper_ignores_the_detection_itself(env):
    det_id = make_detection(env["source_id"], source_ip="203.0.113.200")
    with SessionLocal() as db:
        run_cycle(db, MockSender(), sleep=NO_SLEEP)
        det = db.get(Detection, det_id)
        assert is_duplicate(db, det) is False


def test_detection_created_while_worker_idle_is_still_alerted(env):
    """Regression: an unsaved initial watermark used to re-anchor to "now" each
    idle cycle, so detections arriving between cycles were silently skipped."""
    watermark.reset()
    sender = MockSender()
    with SessionLocal() as db:
        assert run_cycle(db, sender, sleep=NO_SLEEP)["examined"] == 0   # idle cycle
    make_detection(env["source_id"], source_ip="203.0.113.250")
    with SessionLocal() as db:
        stats = run_cycle(db, sender, sleep=NO_SLEEP)
    assert stats["sent"] == 1, "detection created between idle cycles was skipped"


def test_already_alerted_is_counted_not_silent(env):
    """The skip path must be visible in the cycle stats, not invisible."""
    det_id = make_detection(env["source_id"])
    sender = MockSender()
    with SessionLocal() as db:
        run_cycle(db, sender, sleep=NO_SLEEP)
        created = db.get(Detection, det_id).created_at
    watermark.save(watermark.Watermark(created - timedelta(milliseconds=1)))
    with SessionLocal() as db:
        stats = run_cycle(db, sender, sleep=NO_SLEEP)
    assert stats["already_alerted"] == 1
    assert stats["sent"] == 0
