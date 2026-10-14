"""Detection search (Section 2.4).

    cd backend && source .venv/bin/activate
    pytest tests/test_detection_search.py -v

WHY THIS EXISTS
---------------
The header search box routes to /detections?q=..., and the first
implementation filtered the rows the client had already loaded. With 25 rows
per page and a match on page 4, the page said "No detections match these
filters" while the match existed — and the total, and therefore the page
count, still described the unfiltered set.

The search is now applied by the API before counting and paging. The test that
matters most here is test_a_match_beyond_the_first_page_is_found: it seeds more
detections than fit on one page and puts the needle at the end, which is
exactly the case client-side filtering got wrong.

Search covers source IP, destination IP, threat type and severity, which are
the four columns shown in the table.

ISOLATION
---------
Own scratch database per test, autouse — these tests create administrators,
sources and detections, and must never run against a configured system.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.security import hash_password
from app.main import app
from app.models import (AdminRole, Administrator, DataSource, Detection,
                        SeverityLevel, SourceStatus, ThreatType, TransportType)

SCRATCH_DB_PREFIX = "threatsense_search_test_"
PASSWORD = "SearchPass1!"


def _admin_db_url() -> str:
    from app.config import settings as app_settings
    base, _, _name = app_settings.database_url.rpartition("/")
    return f"{base}/postgres"


def _scratch_url(name: str) -> str:
    from app.config import settings as app_settings
    base, _, _name = app_settings.database_url.rpartition("/")
    return f"{base}/{name}"


@pytest.fixture(autouse=True)
def scratch_db():
    import sqlalchemy
    import sqlalchemy.orm
    from pathlib import Path
    import app.database as database_mod
    import app.main as main_mod

    name = f"{SCRATCH_DB_PREFIX}{uuid.uuid4().hex[:12]}"
    admin_engine = sqlalchemy.create_engine(_admin_db_url(),
                                            isolation_level="AUTOCOMMIT")
    try:
        with admin_engine.connect() as conn:
            conn.execute(sqlalchemy.text(f'CREATE DATABASE "{name}"'))
    except Exception as exc:                        # pragma: no cover
        pytest.skip(f"cannot create the scratch database ({exc})")

    engine = sqlalchemy.create_engine(_scratch_url(name), pool_pre_ping=True)
    sessions = sqlalchemy.orm.sessionmaker(bind=engine, autoflush=False,
                                           expire_on_commit=False)
    original_db, original_main = database_mod.SessionLocal, main_mod.SessionLocal
    try:
        db_dir = Path(__file__).resolve().parent.parent / "db"
        with engine.connect() as conn:
            for path in [db_dir / "schema.sql"] + sorted(
                    (db_dir / "migrations").glob("*.sql")):
                conn.exec_driver_sql(path.read_text())
                conn.commit()
        database_mod.SessionLocal = sessions
        main_mod.SessionLocal = sessions
        yield
    finally:
        database_mod.SessionLocal = original_db
        main_mod.SessionLocal = original_main
        engine.dispose()
        with admin_engine.connect() as conn:
            conn.execute(sqlalchemy.text(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                f"WHERE datname = '{name}' AND pid <> pg_backend_pid()"))
            conn.execute(sqlalchemy.text(f'DROP DATABASE IF EXISTS "{name}"'))
        admin_engine.dispose()


def _sessions():
    import app.database as database_mod
    return database_mod.SessionLocal


def _owner(label: str) -> dict:
    email = f"{label}-{uuid.uuid4().hex[:6]}@threatsense.local"
    with _sessions()() as db:
        admin = Administrator(full_name=f"Owner {label}", email=email,
                              password_hash=hash_password(PASSWORD),
                              role=AdminRole.ADMIN)
        db.add(admin)
        db.flush()
        src = DataSource(admin_id=admin.admin_id, name=f"src-{uuid.uuid4().hex[:6]}",
                         type="SYSLOG", ip_address=f"10.60.{abs(hash(label)) % 250}.1",
                         port=1514, transport=TransportType.UDP,
                         status=SourceStatus.ACTIVE)
        db.add(src)
        db.commit()
        return {"email": email, "source_id": src.source_id}


def _detection(source_id, *, source_ip="203.0.113.10", dest_ip="192.168.1.1",
               threat=ThreatType.PORT_SCAN, severity=SeverityLevel.CRITICAL):
    with _sessions()() as db:
        det = Detection(
            source_id=source_id, source_ip=source_ip, destination_ip=dest_ip,
            timestamp=datetime.now(timezone.utc), anomaly_score=0.96,
            severity=severity, threat_type=threat, model_version="IF_v1.0",
            model_type="ISOLATION_FOREST", feature_vector={"pps": 100},
        )
        db.add(det)
        db.commit()
        return det.detection_id


def _client(owner) -> TestClient:
    c = TestClient(app)
    c.__enter__()
    r = c.post("/api/auth/login", json={"email": owner["email"], "password": PASSWORD})
    assert r.status_code == 200, r.text
    return c


def _search(c, q, **extra):
    params = "&".join(f"{k}={v}" for k, v in {"q": q, **extra}.items())
    r = c.get(f"/api/detections?{params}")
    assert r.status_code == 200, r.text
    return r.json()


# --- the case client-side filtering got wrong ---------------------------------

def test_a_match_beyond_the_first_page_is_found():
    """The reason the search moved to the server.

    Thirty detections with the needle last. Filtering the already-loaded page
    would look at the first 25, not find it, and report no matches — while the
    detection plainly existed.
    """
    owner = _owner("a")
    for i in range(29):
        _detection(owner["source_id"], source_ip=f"198.51.100.{i + 1}")
    _detection(owner["source_id"], source_ip="203.0.113.77")   # the needle, last

    c = _client(owner)
    try:
        data = _search(c, "203.0.113.77", limit=25, offset=0)
    finally:
        c.__exit__(None, None, None)

    assert data["total"] == 1, "the match was not found from the first page"
    assert len(data["items"]) == 1
    assert data["items"][0]["source_ip"].startswith("203.0.113.77")


def test_total_is_the_filtered_total_not_the_global_one():
    """Pagination must describe the result set, or the page count lies."""
    owner = _owner("a")
    for i in range(12):
        _detection(owner["source_id"], source_ip=f"198.51.100.{i + 1}")
    _detection(owner["source_id"], source_ip="203.0.113.99")

    c = _client(owner)
    try:
        everything = _search(c, "")
        filtered = _search(c, "203.0.113.99")
    finally:
        c.__exit__(None, None, None)

    assert everything["total"] == 13
    assert filtered["total"] == 1, "total still describes the unfiltered set"


# --- each searchable column ---------------------------------------------------

def test_search_matches_the_source_address():
    owner = _owner("a")
    _detection(owner["source_id"], source_ip="203.0.113.55")
    _detection(owner["source_id"], source_ip="198.51.100.4")
    c = _client(owner)
    try:
        data = _search(c, "203.0.113.55")
    finally:
        c.__exit__(None, None, None)
    assert data["total"] == 1


def test_search_matches_a_partial_address():
    """An operator types the first octets, not the whole address."""
    owner = _owner("a")
    for i in range(3):
        _detection(owner["source_id"], source_ip=f"203.0.113.{i + 1}")
    _detection(owner["source_id"], source_ip="198.51.100.9")
    c = _client(owner)
    try:
        data = _search(c, "203.0.113")
    finally:
        c.__exit__(None, None, None)
    assert data["total"] == 3


def test_search_matches_the_destination_address():
    """host() is used rather than str(), so no /32 suffix has to be typed."""
    owner = _owner("a")
    _detection(owner["source_id"], dest_ip="10.40.40.40")
    _detection(owner["source_id"], dest_ip="10.50.50.50")
    c = _client(owner)
    try:
        data = _search(c, "10.40.40.40")
    finally:
        c.__exit__(None, None, None)
    assert data["total"] == 1


def test_search_matches_the_threat_type():
    owner = _owner("a")
    _detection(owner["source_id"], threat=ThreatType.PORT_SCAN)
    _detection(owner["source_id"], threat=ThreatType.DDOS)
    _detection(owner["source_id"], threat=ThreatType.DDOS)
    c = _client(owner)
    try:
        data = _search(c, "ddos")
    finally:
        c.__exit__(None, None, None)
    assert data["total"] == 2


def test_search_matches_the_severity():
    owner = _owner("a")
    _detection(owner["source_id"], severity=SeverityLevel.CRITICAL)
    _detection(owner["source_id"], severity=SeverityLevel.LOW)
    c = _client(owner)
    try:
        data = _search(c, "critical")
    finally:
        c.__exit__(None, None, None)
    assert data["total"] == 1


def test_search_is_case_insensitive():
    owner = _owner("a")
    _detection(owner["source_id"], threat=ThreatType.PORT_SCAN)
    c = _client(owner)
    try:
        assert _search(c, "PORT_SCAN")["total"] == 1
        assert _search(c, "port_scan")["total"] == 1
        assert _search(c, "Port_Scan")["total"] == 1
    finally:
        c.__exit__(None, None, None)


def test_a_term_matching_nothing_returns_nothing():
    owner = _owner("a")
    _detection(owner["source_id"])
    c = _client(owner)
    try:
        data = _search(c, "zzzznomatch")
    finally:
        c.__exit__(None, None, None)
    assert data["total"] == 0
    assert data["items"] == []


def test_an_empty_term_returns_everything():
    owner = _owner("a")
    for _ in range(3):
        _detection(owner["source_id"])
    c = _client(owner)
    try:
        data = _search(c, "")
    finally:
        c.__exit__(None, None, None)
    assert data["total"] == 3


# --- ownership still applies --------------------------------------------------

def test_search_never_returns_another_administrators_detection():
    """Search must not become a way around the ownership scoping that every
    other detection route enforces."""
    mine = _owner("mine")
    theirs = _owner("theirs")
    _detection(mine["source_id"], source_ip="203.0.113.11")
    _detection(theirs["source_id"], source_ip="203.0.113.11")   # same address

    c = _client(mine)
    try:
        data = _search(c, "203.0.113.11")
    finally:
        c.__exit__(None, None, None)

    assert data["total"] == 1, "another administrator's detection was returned"
    with _sessions()() as db:
        owned = {d.detection_id for d in db.scalars(
            select(Detection).where(Detection.source_id == mine["source_id"]))}
    assert uuid.UUID(data["items"][0]["detection_id"]) in owned


def test_search_combines_with_the_other_filters():
    owner = _owner("a")
    _detection(owner["source_id"], source_ip="203.0.113.20",
               severity=SeverityLevel.CRITICAL, threat=ThreatType.PORT_SCAN)
    _detection(owner["source_id"], source_ip="203.0.113.20",
               severity=SeverityLevel.LOW, threat=ThreatType.PORT_SCAN)
    c = _client(owner)
    try:
        both = _search(c, "203.0.113.20", severity="CRITICAL")
    finally:
        c.__exit__(None, None, None)
    assert both["total"] == 1, "q and severity are not combined"
