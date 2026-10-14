"""Tests for the detection traffic summary endpoint (task 3.4, Figure 7).

The Detection Detail screen shows a protocol distribution. It comes from the
same aggregate the report prompt uses, so the screen and the AI report can
never describe the traffic differently.

    cd backend && source .venv/bin/activate
    pytest tests/test_traffic_summary.py -v
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.security import hash_password
from app.database import SessionLocal
from app.main import app
from app.models import (
    AdminRole, Administrator, AuditLog, DataSource, Detection, IncidentReport,
    NetworkLog, SeverityLevel, SourceStatus, SourceType, ThreatType,
)

PASSWORD = "TestPassw0rd!"


def _make_env(with_logs=True):
    email = f"traffic-{uuid.uuid4().hex[:8]}@threatsense.local"
    # Pinned to :50 within the minute, not the wall clock. The related-log
    # scope is the detection's own CALENDAR-MINUTE bucket, so a fixture that
    # placed the detection at an arbitrary second could put its own log
    # records in the preceding bucket whenever the suite happened to run near
    # the top of a minute — a test that passes or fails depending on the time
    # of day. Fixing the seconds makes the boundary explicit.
    now = datetime.now(timezone.utc).replace(second=50, microsecond=0)
    with SessionLocal() as db:
        admin = Administrator(full_name="Traffic Test", email=email,
                              password_hash=hash_password(PASSWORD),
                              role=AdminRole.ADMIN)
        db.add(admin)
        db.flush()
        source = DataSource(admin_id=admin.admin_id,
                            name=f"src-{uuid.uuid4().hex[:6]}",
                            type=SourceType.SYSLOG, status=SourceStatus.ACTIVE)
        db.add(source)
        db.flush()
        det = Detection(
            source_id=source.source_id, source_ip="203.0.113.77",
            destination_ip="192.168.1.30", timestamp=now, anomaly_score=0.88,
            severity=SeverityLevel.HIGH, threat_type=ThreatType.PORT_SCAN,
            model_version="IF_v1.0", model_type="ISOLATION_FOREST",
            feature_vector={"unique_dst_ports": 0.9},
        )
        db.add(det)
        db.flush()
        if with_logs:
            for i in range(8):
                db.add(NetworkLog(
                    source_id=source.source_id, batch_id=uuid.uuid4(),
                    src_ip="203.0.113.77", dst_ip="192.168.1.30",
                    src_port=41000 + i, dst_port=80 + i,
                    protocol="TCP" if i < 6 else "UDP",
                    packet_size=100 + i * 10,
                    raw_message=f"SECRET-RAW-{i} user=jsmith",
                    # Inside the detection's one-minute window. The traffic
                    # panel and the AI report share one aggregate query on
                    # purpose (see routers/detections.py::detection_traffic),
                    # and that window now matches the minute Algorithm 2
                    # actually scored rather than the previous fifteen.
                    timestamp=now - timedelta(seconds=5 + i * 5),
                ))
        db.commit()
        return {"admin_id": admin.admin_id, "email": email,
                "source_id": source.source_id, "detection_id": det.detection_id}


def _teardown(ids):
    with SessionLocal() as db:
        det_ids = db.scalars(select(Detection.detection_id)
                             .where(Detection.source_id == ids["source_id"])).all()
        if det_ids:
            db.query(IncidentReport).filter(
                IncidentReport.detection_id.in_(det_ids)).delete(
                synchronize_session=False)
        db.query(NetworkLog).filter(
            NetworkLog.source_id == ids["source_id"]).delete(synchronize_session=False)
        db.query(Detection).filter(
            Detection.source_id == ids["source_id"]).delete(synchronize_session=False)
        db.query(DataSource).filter(DataSource.source_id == ids["source_id"]).delete()
        db.query(AuditLog).filter(AuditLog.admin_id == ids["admin_id"]).delete()
        db.query(Administrator).filter(
            Administrator.admin_id == ids["admin_id"]).delete()
        db.commit()


@pytest.fixture()
def env():
    ids = _make_env()
    yield ids
    _teardown(ids)


@pytest.fixture()
def client(env):
    with TestClient(app) as c:
        r = c.post("/api/auth/login",
                   json={"email": env["email"], "password": PASSWORD})
        assert r.status_code == 200, r.text
        yield c


def test_returns_protocol_distribution(client, env):
    r = client.get(f"/api/detections/{env['detection_id']}/traffic")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["events"] == 8
    assert body["protocols"] == {"TCP": 6, "UDP": 2}
    assert body["distinct_dst_ports"] == 8
    assert body["distinct_dst_ips"] == 1
    assert len(body["top_dst_ports"]) == 5
    assert body["packet_size_bytes"]["min"] == 100
    assert body["packet_size_bytes"]["max"] == 170
    assert body["window_minutes"] == 1


def test_never_returns_raw_log_content(client, env):
    """Aggregates only — a raw syslog payload must not reach the browser."""
    body = client.get(f"/api/detections/{env['detection_id']}/traffic").text
    assert "SECRET-RAW" not in body
    assert "jsmith" not in body


def test_detection_without_logs_returns_zeroed_summary(client):
    ids = _make_env(with_logs=False)
    try:
        with TestClient(app) as c:
            c.post("/api/auth/login",
                   json={"email": ids["email"], "password": PASSWORD})
            r = c.get(f"/api/detections/{ids['detection_id']}/traffic")
        assert r.status_code == 200
        body = r.json()
        assert body["events"] == 0
        assert body["protocols"] == {}
        assert body["top_dst_ports"] == []
    finally:
        _teardown(ids)


def test_requires_authentication(env):
    with TestClient(app) as anon:
        r = anon.get(f"/api/detections/{env['detection_id']}/traffic")
    assert r.status_code == 401


def test_404s_for_another_admins_detection(client):
    other = _make_env()
    try:
        r = client.get(f"/api/detections/{other['detection_id']}/traffic")
        assert r.status_code == 404
    finally:
        _teardown(other)
