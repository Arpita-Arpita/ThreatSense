"""Background process liveness on /health (Phase 6.3).

    cd backend && source .venv/bin/activate
    pytest tests/test_process_heartbeat.py -v

WHY THIS EXISTS
---------------
ThreatSense runs four processes against one database: the API, the syslog
listener, the detection engine (Section 2.3, a scheduled background job), and
the alert worker (Section 2.5, asynchronous "so it does not delay the
detection pipeline").

During the Phase 6.3 end-to-end dry run, two of the three apparent failures
were a background process that had not been started:

    engine not running  -> logs ingest, no detection is ever created
    worker not running  -> detections appear, no email is ever sent

Neither produced an error. The API returned 200, the dashboard rendered, and
the only symptom was a feature appearing broken. Each cost a diagnosis cycle
before the cause was found.

These tests pin the reporting contract. The distinction that matters most is
"unknown" versus "down": a missing heartbeat file proves only that we have no
evidence, not that a process has stopped. Reporting "down" on no evidence
would be the same overreach as reporting a zero drop count for a listener
that never ran.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.services import heartbeat


@pytest.fixture()
def hb_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "heartbeat_dir", str(tmp_path))
    return tmp_path


def _write(component, *, age_seconds=0.0, **fields):
    heartbeat.write(component, **fields)
    if age_seconds:
        path = heartbeat.path_for(component)
        data = json.loads(path.read_text(encoding="utf-8"))
        data["updated_at"] = (datetime.now(timezone.utc)
                              - timedelta(seconds=age_seconds)).isoformat()
        path.write_text(json.dumps(data), encoding="utf-8")


def _processes(client):
    r = client.get("/health")
    assert r.status_code == 200, r.text
    return r.json()["processes"]


# --- the three states ---------------------------------------------------------

def test_missing_heartbeat_reports_unknown_not_down(hb_dir):
    """No file means no evidence. Claiming "down" would be a guess.

    This is the same reasoning as the absent ingestion stats file reporting
    "unknown" rather than a zero drop count.
    """
    with TestClient(app) as c:
        procs = _processes(c)
    assert procs["detection_engine"]["state"] == "unknown"
    assert procs["alert_worker"]["state"] == "unknown"


def test_fresh_heartbeat_reports_up(hb_dir):
    _write("detection_engine", last_cycle_logs=1001, last_cycle_detections=1)
    with TestClient(app) as c:
        engine = _processes(c)["detection_engine"]
    assert engine["state"] == "up"
    assert engine["last_cycle_logs"] == 1001
    assert engine["last_cycle_detections"] == 1


def test_old_heartbeat_reports_stale(hb_dir):
    _write("alert_worker", age_seconds=settings.heartbeat_stale_seconds + 60)
    with TestClient(app) as c:
        worker = _processes(c)["alert_worker"]
    assert worker["state"] == "stale"
    assert worker["last_seen_age_seconds"] > settings.heartbeat_stale_seconds


def test_processes_are_reported_independently(hb_dir):
    """The dry run's exact failure: one process up, the other never started."""
    _write("detection_engine", last_cycle_logs=1001)
    with TestClient(app) as c:
        procs = _processes(c)
    assert procs["detection_engine"]["state"] == "up"
    assert procs["alert_worker"]["state"] == "unknown"


# --- the threshold has to fit the slowest cycle -------------------------------

def test_stale_threshold_exceeds_the_slowest_cycle(hb_dir):
    """A healthy process must never read as stale.

    The engine writes once per detection cycle (60s by default, operator
    configurable via detection_settings) and the worker once per
    alert_poll_seconds. Too tight a threshold turns a working system into a
    false alarm, which is worse than no signal at all.
    """
    assert settings.heartbeat_stale_seconds > 60
    assert settings.heartbeat_stale_seconds > settings.alert_poll_seconds


# --- robustness: telemetry must never break the thing it observes -------------

def test_corrupt_heartbeat_reports_unknown_not_500(hb_dir):
    heartbeat.path_for("alert_worker").parent.mkdir(parents=True, exist_ok=True)
    heartbeat.path_for("alert_worker").write_text("{ not json", encoding="utf-8")
    with TestClient(app) as c:
        r = c.get("/health")
    assert r.status_code == 200
    assert r.json()["processes"]["alert_worker"]["state"] == "unknown"


def test_write_failure_is_swallowed(hb_dir, monkeypatch):
    """A read-only or missing directory must not crash the engine mid-cycle."""
    monkeypatch.setattr(settings, "heartbeat_dir", "/proc/nonexistent/nope")
    heartbeat.write("detection_engine", last_cycle_logs=5)   # must not raise


def test_write_leaves_no_temp_file(hb_dir):
    heartbeat.write("detection_engine", last_cycle_logs=1)
    assert list(hb_dir.glob("*.tmp")) == []


def test_health_still_reports_status_and_ingestion(hb_dir):
    """The processes block is additive; nothing existing may change shape."""
    with TestClient(app) as c:
        body = c.get("/health").json()
    assert body["status"] == "ok"
    assert "database" in body
    assert "ingestion" in body
    assert "processes" in body
