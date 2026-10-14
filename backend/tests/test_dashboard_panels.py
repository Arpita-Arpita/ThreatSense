"""Dashboard panel endpoints (Section 2.4, Algorithm 4, Figure 2c).

    cd backend && source .venv/bin/activate
    pytest tests/test_dashboard_panels.py -v

WHY THIS EXISTS
---------------
Section 2.4, verbatim:

    "RESTful API endpoints provide data for each panel through routes such as
     /api/dashboard/health, /api/dashboard/alerts, and /api/dashboard/analytics"

Figure 2c draws the browser calling all three on dashboard load, and
Algorithm 4 (getDashboardData) specifies health, timeline and analytics as one
retrieval. The functionality existed but only under /api/detections, and
app/routers/dashboard.py was an empty stub, so the implemented route shape did
not match the design.

/alerts delegates to detections.list_detections. The delegation test below is
the point of that decision: two independent queries would be free to drift,
and a detection visible on one route but not the other is the kind of
inconsistency that only shows up in a demo.

/health and /analytics are new aggregates over network_logs and data_sources.
Note /api/dashboard/health is NOT the root /health liveness probe that NFR-06
measures against — different scope, different auth. The last test pins that.
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
from app.models import (AdminRole, Administrator, DataSource, NetworkLog,
                        SourceStatus)

PASSWORD = "DashPanel1!"


@pytest.fixture()
def admin_with_logs():
    """An administrator owning one source with a known set of log rows."""
    email = f"dash-{uuid.uuid4().hex[:8]}@threatsense.local"
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        admin = Administrator(full_name="Dash Test", email=email,
                              password_hash=hash_password(PASSWORD),
                              role=AdminRole.ADMIN)
        db.add(admin)
        db.flush()
        source = DataSource(admin_id=admin.admin_id, name=f"dash-src-{uuid.uuid4().hex[:6]}",
                            type="SYSLOG", ip_address="192.168.64.2", port=6514,
                            transport="TLS", status=SourceStatus.ACTIVE)
        db.add(source)
        db.flush()

        batch = uuid.uuid4()
        rows = []
        # 30 rows inside the last hour: 20 TCP from .10, 10 UDP from .11
        for i in range(30):
            rows.append(NetworkLog(
                source_id=source.source_id,
                timestamp=now - timedelta(minutes=i % 50),
                ingested_at=now - timedelta(minutes=i % 50),
                src_ip="10.9.9.10" if i < 20 else "10.9.9.11",
                dst_ip="192.168.64.1", src_port=40000 + i, dst_port=443,
                protocol="TCP" if i < 20 else "UDP",
                packet_size=500, flags="SYN", batch_id=batch, is_analysed=True))
        # 5 rows well outside the hour, to prove the window is applied
        for i in range(5):
            rows.append(NetworkLog(
                source_id=source.source_id,
                timestamp=now - timedelta(hours=8),
                ingested_at=now - timedelta(hours=8),
                src_ip="10.9.9.99", dst_ip="192.168.64.1",
                src_port=41000 + i, dst_port=22, protocol="TCP",
                packet_size=100, flags="SYN", batch_id=batch, is_analysed=True))
        db.add_all(rows)
        db.commit()
        ids = {"admin_id": admin.admin_id, "source_id": source.source_id,
               "email": email}

    yield ids

    with SessionLocal() as db:
        db.query(NetworkLog).filter(
            NetworkLog.source_id == ids["source_id"]).delete()
        db.query(DataSource).filter(
            DataSource.source_id == ids["source_id"]).delete()
        from app.models import AuditLog
        db.query(AuditLog).filter(AuditLog.admin_id == ids["admin_id"]).delete()
        db.query(Administrator).filter(
            Administrator.admin_id == ids["admin_id"]).delete()
        db.commit()


@pytest.fixture()
def client(admin_with_logs):
    with TestClient(app) as c:
        r = c.post("/api/auth/login",
                   json={"email": admin_with_logs["email"], "password": PASSWORD})
        assert r.status_code == 200, r.text
        yield c


# --- the routes exist at the specified paths ---------------------------------

@pytest.mark.parametrize("path", ["/api/dashboard/health",
                                  "/api/dashboard/alerts",
                                  "/api/dashboard/analytics"])
def test_specified_routes_exist(client, path):
    """The three routes Section 2.4 names, at the paths it names."""
    assert client.get(path).status_code == 200


@pytest.mark.parametrize("path", ["/api/dashboard/health",
                                  "/api/dashboard/alerts",
                                  "/api/dashboard/analytics"])
def test_routes_require_a_session(path):
    """Algorithm 4 opens with "VERIFY active administrator session"."""
    with TestClient(app) as anon:
        assert anon.get(path).status_code == 401


# --- health panel -------------------------------------------------------------

def test_health_counts_only_the_last_hour(client):
    """Section 2.4: "total logs processed during the last hour"."""
    body = client.get("/api/dashboard/health").json()
    assert body["logs_last_hour"] == 30, "the 8-hour-old rows must be excluded"


def test_health_reports_active_sources_and_rate(client):
    body = client.get("/api/dashboard/health").json()
    assert body["active_sources"] == 1
    # 30 rows over a 3600s window, rounded to 3dp by the endpoint. The
    # rounding is sized for NFR-01 volumes (1,000/s), where 3dp is ample;
    # at test volumes it is the dominant term, hence the exact comparison.
    assert body["ingestion_rate_per_sec"] == round(30 / 3600, 3)


def test_health_is_scoped_to_the_owning_admin(admin_with_logs):
    """Another admin must not see these logs. Ownership runs through
    data_sources; network_logs has no admin_id of its own."""
    other_email = f"dash-other-{uuid.uuid4().hex[:8]}@threatsense.local"
    with SessionLocal() as db:
        other = Administrator(full_name="Other", email=other_email,
                              password_hash=hash_password(PASSWORD),
                              role=AdminRole.ADMIN)
        db.add(other)
        db.commit()
        other_id = other.admin_id
    try:
        with TestClient(app) as c:
            c.post("/api/auth/login",
                   json={"email": other_email, "password": PASSWORD})
            body = c.get("/api/dashboard/health").json()
        assert body["logs_last_hour"] == 0
        assert body["active_sources"] == 0
    finally:
        with SessionLocal() as db:
            from app.models import AuditLog
            db.query(AuditLog).filter(AuditLog.admin_id == other_id).delete()
            db.query(Administrator).filter(
                Administrator.admin_id == other_id).delete()
            db.commit()


def test_dashboard_health_is_not_the_liveness_probe():
    """GET /health (root) is the unauthenticated probe NFR-06 measures
    against. /api/dashboard/health is a different, authenticated endpoint.
    Conflating them would either break the probe or expose the panel."""
    with TestClient(app) as anon:
        root = anon.get("/health")
        panel = anon.get("/api/dashboard/health")
    assert root.status_code == 200
    assert "database" in root.json()
    assert panel.status_code == 401


# --- alerts panel: delegation -------------------------------------------------

def test_alerts_matches_the_detections_route_exactly(client):
    """The whole reason /alerts delegates rather than re-queries."""
    a = client.get("/api/dashboard/alerts").json()
    b = client.get("/api/detections").json()
    assert a["total"] == b["total"]
    assert [i["detection_id"] for i in a["items"]] == \
           [i["detection_id"] for i in b["items"]]


def test_alerts_honours_pagination(client):
    body = client.get("/api/dashboard/alerts?limit=1&offset=0").json()
    assert body["limit"] == 1
    assert len(body["items"]) <= 1


# --- analytics panel ----------------------------------------------------------

def test_analytics_returns_the_three_aggregates(client):
    """Algorithm 4: "AGGREGATE traffic volume, protocol distribution,
    top source IPs"."""
    body = client.get("/api/dashboard/analytics").json()
    assert set(body) >= {"volume", "protocols", "top_talkers"}


def test_analytics_protocol_distribution_is_correct(client):
    body = client.get("/api/dashboard/analytics").json()
    assert body["protocols"].get("TCP") == 20
    assert body["protocols"].get("UDP") == 10


def test_analytics_top_talkers_are_ordered_by_volume(client):
    body = client.get("/api/dashboard/analytics").json()
    talkers = body["top_talkers"]
    assert talkers[0]["src_ip"] == "10.9.9.10"
    assert talkers[0]["events"] == 20
    counts = [t["events"] for t in talkers]
    assert counts == sorted(counts, reverse=True)


def test_analytics_volume_buckets_the_range(client):
    """date_bin needs PostgreSQL 14+; the project targets 16. This is the
    test that fails loudly if it is ever run against something older."""
    body = client.get("/api/dashboard/analytics?hours=1&bucket_minutes=5").json()
    assert body["bucket_minutes"] == 5
    assert body["volume"], "expected at least one populated bucket"
    assert sum(p["events"] for p in body["volume"]) == 30


def test_analytics_range_is_capped(client):
    """Uncapped, one dashboard load could walk the whole of network_logs."""
    assert client.get("/api/dashboard/analytics?hours=24").status_code == 200
    assert client.get("/api/dashboard/analytics?hours=25").status_code == 422


def test_analytics_wider_range_includes_older_rows(client):
    """The 8-hour-old rows appear at hours=12 but not at hours=1."""
    narrow = client.get("/api/dashboard/analytics?hours=1").json()
    wide = client.get("/api/dashboard/analytics?hours=12").json()
    assert sum(p["events"] for p in narrow["volume"]) == 30
    assert sum(p["events"] for p in wide["volume"]) == 35
