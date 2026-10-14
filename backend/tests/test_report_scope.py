"""Incident-report traffic window and the Incident Reports history endpoint.

    cd backend && source .venv/bin/activate
    pytest tests/test_report_scope.py -v

Two changes are covered here.

WINDOW (Algorithm 5). summarise_related_logs() aggregated the fifteen minutes
of traffic before a detection, while Algorithm 2 scores ONE-minute windows. A
report could therefore describe traffic the detection was never scored on, and
invite the model to present unrelated activity as part of the incident. The
window now matches the detection.

HISTORY (Section 2.1). Report history existed only per detection, so the
Incident Reports navigation destination had nothing to show. GET /api/reports
lists every report the signed-in administrator owns, scoped through the same
detection -> data_source -> admin_id join used elsewhere in the router.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.security import hash_password
from app.database import SessionLocal
from app.main import app
from app.models import (
    AdminRole, Administrator, AuditLog, DataSource, Detection, IncidentReport,
    NetworkLog, SeverityLevel, SourceStatus, SourceType, ThreatType,
)
from app.services.reporting.prompt import (
    RELATED_LOG_WINDOW_MINUTES, detection_window_start, summarise_related_logs,
)

PASSWORD = "TestPassw0rd!"
# :40 within the minute, so the fixtures below can place traffic a few
# seconds earlier and still be inside the detection's own 12:30 bucket.
DETECTED_AT = datetime(2026, 9, 1, 12, 30, 40, tzinfo=timezone.utc)

REPORT_TEXT = "\n\n".join(
    f"## {title}\n{'Body text for the section, long enough to validate.'}"
    for title in ("Executive Summary", "Threat Details", "Risk Assessment",
                  "Recommended Actions")
)


def _admin(prefix):
    email = f"{prefix}-{uuid.uuid4().hex[:8]}@threatsense.local"
    with SessionLocal() as db:
        row = Administrator(full_name="Report Scope Test", email=email,
                            password_hash=hash_password(PASSWORD),
                            role=AdminRole.ADMIN)
        db.add(row)
        db.commit()
        return {"admin_id": row.admin_id, "email": email}


def _cleanup(ids):
    with SessionLocal() as db:
        source_ids = [s for (s,) in db.query(DataSource.source_id).filter(
            DataSource.admin_id == ids["admin_id"]).all()]
        if source_ids:
            det_ids = [d for (d,) in db.query(Detection.detection_id).filter(
                Detection.source_id.in_(source_ids)).all()]
            if det_ids:
                db.query(IncidentReport).filter(
                    IncidentReport.detection_id.in_(det_ids)
                ).delete(synchronize_session=False)
            db.query(NetworkLog).filter(
                NetworkLog.source_id.in_(source_ids)).delete(synchronize_session=False)
            db.query(Detection).filter(
                Detection.source_id.in_(source_ids)).delete(synchronize_session=False)
        db.query(DataSource).filter(
            DataSource.admin_id == ids["admin_id"]).delete(synchronize_session=False)
        db.query(AuditLog).filter(AuditLog.admin_id == ids["admin_id"]).delete()
        db.query(Administrator).filter(
            Administrator.admin_id == ids["admin_id"]).delete()
        db.commit()


def _source(admin_id):
    with SessionLocal() as db:
        src = DataSource(admin_id=admin_id, name=f"rs-{uuid.uuid4().hex[:6]}",
                         type=SourceType.SYSLOG, status=SourceStatus.ACTIVE)
        db.add(src)
        db.commit()
        return src.source_id


def _detection(source_id, ts=DETECTED_AT):
    with SessionLocal() as db:
        det = Detection(
            source_id=source_id, timestamp=ts, source_ip="192.168.64.2",
            destination_ip="10.0.0.1", threat_type=ThreatType.PORT_SCAN,
            anomaly_score=1.0, severity=SeverityLevel.CRITICAL,
            model_version="IF_v1.0", model_type="ISOLATION_FOREST",
            feature_vector={"unique_dst_ports": 1000.0},
        )
        db.add(det)
        db.commit()
        db.refresh(det)
        return det.detection_id


def _log(source_id, ts, dst_port):
    with SessionLocal() as db:
        db.add(NetworkLog(
            source_id=source_id, batch_id=uuid.uuid4(), timestamp=ts,
            src_ip="192.168.64.2", dst_ip="10.0.0.1", src_port=4444,
            dst_port=dst_port, protocol="TCP", packet_size=60, flags="S",
            raw_message="x", is_analysed=True))
        db.commit()


@pytest.fixture()
def owner():
    ids = _admin("owner")
    yield ids
    _cleanup(ids)


@pytest.fixture()
def stranger():
    ids = _admin("stranger")
    yield ids
    _cleanup(ids)


def _client(ids):
    c = TestClient(app)
    c.__enter__()
    r = c.post("/api/auth/login", json={"email": ids["email"], "password": PASSWORD})
    assert r.status_code == 200, r.text
    return c


# --- window ------------------------------------------------------------------

def test_window_matches_the_detection_window():
    """Algorithm 2 groups one-minute windows, so the report covers one minute."""
    assert RELATED_LOG_WINDOW_MINUTES == 1


def test_window_start_is_the_detections_own_minute_bucket():
    """ml/features.py::group_windows buckets on replace(second=0,
    microsecond=0), so a detection at 12:30:20 belongs to the 12:30 bucket.

    A rolling "timestamp minus one minute" scope would start at 12:29:20 and
    pull in forty seconds of the PREVIOUS bucket — traffic scored as a
    different detection.
    """
    class _D:
        timestamp = datetime(2026, 9, 1, 12, 30, 20, 500_000, tzinfo=timezone.utc)

    assert detection_window_start(_D) == datetime(
        2026, 9, 1, 12, 30, 0, tzinfo=timezone.utc)


def test_preceding_bucket_traffic_is_excluded(owner):
    """The boundary the previous fix missed.

    Detection at 12:30:20. 12:29:50 sits inside a rolling one-minute window
    but belongs to the 12:29 bucket, so it must NOT be summarised.
    """
    source_id = _source(owner["admin_id"])
    detected_at = datetime(2026, 9, 1, 12, 30, 20, tzinfo=timezone.utc)
    detection_id = _detection(source_id, detected_at)

    _log(source_id, datetime(2026, 9, 1, 12, 29, 50, tzinfo=timezone.utc), 21)
    _log(source_id, datetime(2026, 9, 1, 12, 30, 0, tzinfo=timezone.utc), 22)
    _log(source_id, datetime(2026, 9, 1, 12, 30, 5, tzinfo=timezone.utc), 23)
    _log(source_id, datetime(2026, 9, 1, 12, 30, 20, tzinfo=timezone.utc), 24)

    with SessionLocal() as db:
        det = db.get(Detection, detection_id)
        summary = summarise_related_logs(db, det)

    assert summary["events"] == 3, (
        "12:29:50 belongs to the previous bucket and must be excluded; "
        "12:30:00, 12:30:05 and 12:30:20 must be included")
    assert sorted(summary["top_dst_ports"]) == [22, 23, 24]


def test_traffic_after_the_detection_is_excluded(owner):
    """The model never scored it, so the report must not describe it."""
    source_id = _source(owner["admin_id"])
    detected_at = datetime(2026, 9, 1, 12, 30, 20, tzinfo=timezone.utc)
    detection_id = _detection(source_id, detected_at)

    _log(source_id, datetime(2026, 9, 1, 12, 30, 10, tzinfo=timezone.utc), 80)
    _log(source_id, datetime(2026, 9, 1, 12, 30, 45, tzinfo=timezone.utc), 443)

    with SessionLocal() as db:
        det = db.get(Detection, detection_id)
        summary = summarise_related_logs(db, det)

    assert summary["events"] == 1
    assert summary["top_dst_ports"] == [80]


def test_traffic_outside_the_window_is_excluded(owner):
    """The regression: records from minutes earlier were summarised into the
    report as though they were part of the incident."""
    source_id = _source(owner["admin_id"])
    detection_id = _detection(source_id)

    for port in (80, 443, 8080):                      # inside the minute
        _log(source_id, DETECTED_AT - timedelta(seconds=20), port)
    for port in (21, 22, 23, 25, 3389):               # 10 minutes earlier
        _log(source_id, DETECTED_AT - timedelta(minutes=10), port)

    with SessionLocal() as db:
        det = db.get(Detection, detection_id)
        summary = summarise_related_logs(db, det)

    assert summary["events"] == 3, (
        "only traffic inside the detection's own minute may be summarised")
    assert summary["distinct_dst_ports"] == 3
    assert summary["window_minutes"] == 1


def test_window_still_summarises_the_traffic_it_should(owner):
    source_id = _source(owner["admin_id"])
    detection_id = _detection(source_id)
    for port in range(1, 21):
        _log(source_id, DETECTED_AT - timedelta(seconds=5), port)

    with SessionLocal() as db:
        det = db.get(Detection, detection_id)
        summary = summarise_related_logs(db, det)

    assert summary["events"] == 20
    assert summary["distinct_dst_ports"] == 20


def test_no_related_traffic_returns_empty_summary(owner):
    """Injected detections with no matching logs must not break generation."""
    source_id = _source(owner["admin_id"])
    detection_id = _detection(source_id)
    with SessionLocal() as db:
        det = db.get(Detection, detection_id)
        assert summarise_related_logs(db, det) == {}


# --- history endpoint --------------------------------------------------------

def _report(detection_id, admin_id):
    with SessionLocal() as db:
        row = IncidentReport(detection_id=detection_id, generated_by=admin_id,
                             report_text=REPORT_TEXT, model_used="mock-llm",
                             token_count=123)
        db.add(row)
        db.commit()
        return row.report_id


def test_history_lists_reports_with_detection_context(owner):
    source_id = _source(owner["admin_id"])
    detection_id = _detection(source_id)
    report_id = _report(detection_id, owner["admin_id"])

    with _client(owner) as c:
        body = c.get("/api/reports").json()

    assert body["total"] == 1
    item = body["items"][0]
    assert item["report_id"] == str(report_id)
    assert item["detection_id"] == str(detection_id)
    assert item["threat_type"] == "PORT_SCAN"
    assert item["severity"] == "CRITICAL"
    assert item["source_ip"] == "192.168.64.2"
    assert item["model_used"] == "mock-llm"
    assert "report_text" not in item, "the list is metadata only"


def test_history_is_newest_first(owner):
    source_id = _source(owner["admin_id"])
    first = _report(_detection(source_id), owner["admin_id"])
    second = _report(_detection(source_id, DETECTED_AT + timedelta(minutes=5)),
                     owner["admin_id"])
    with _client(owner) as c:
        items = c.get("/api/reports").json()["items"]
    ids = [i["report_id"] for i in items]
    assert ids.index(str(second)) < ids.index(str(first))


def test_history_never_leaks_another_administrators_reports(owner, stranger):
    """Ownership runs through detection -> data_source -> admin_id, the same
    join the rest of the reports router uses."""
    source_id = _source(owner["admin_id"])
    _report(_detection(source_id), owner["admin_id"])

    with _client(stranger) as c:
        body = c.get("/api/reports").json()
    assert body["total"] == 0
    assert body["items"] == []


def test_history_requires_a_session():
    c = TestClient(app)
    with c:
        assert c.get("/api/reports").status_code == 401


def test_history_paging_is_bounded(owner):
    source_id = _source(owner["admin_id"])
    for i in range(3):
        _report(_detection(source_id, DETECTED_AT + timedelta(minutes=i)),
                owner["admin_id"])
    with _client(owner) as c:
        page = c.get("/api/reports?limit=2&offset=0").json()
        rest = c.get("/api/reports?limit=2&offset=2").json()
    assert page["total"] == 3 and len(page["items"]) == 2
    assert len(rest["items"]) == 1
