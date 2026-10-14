"""Source ACTIVE -> INACTIVE transition (Use Case 4.2, step 5a).

    cd backend && source .venv/bin/activate
    pytest tests/test_source_status.py -v

Use Case 4.2 requires a registered source to read ACTIVE while traffic is
arriving and INACTIVE once 60 seconds pass with no valid message, returning to
ACTIVE when traffic resumes. The stored data_sources.status column only ever
recorded the last write, so a source that had gone silent kept reading ACTIVE
indefinitely and both the Log Sources table and the Dashboard's "active
sources" card overstated what was really reporting.

The transition is applied at READ time (app/core/source_status.py) rather than
by a background sweeper, so the tests below are deterministic: they move the
clock rather than waiting for one.

The first group needs no database — effective_status is a pure function.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.config import settings
from app.core.source_status import effective_status, is_effectively_active
from app.models import SourceStatus

NOW = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)


def _ago(seconds: int) -> datetime:
    return NOW - timedelta(seconds=seconds)


# --- pure unit tests (no database) ------------------------------------------

def test_recent_traffic_reads_active():
    """A message one second ago: comfortably inside the 60-second window."""
    assert effective_status(SourceStatus.ACTIVE, _ago(1), NOW) == SourceStatus.ACTIVE


def test_just_inside_the_window_reads_active():
    """59 seconds is still ACTIVE — the boundary is 60, not 'about a minute'."""
    assert effective_status(SourceStatus.ACTIVE, _ago(59), NOW) == SourceStatus.ACTIVE


def test_exactly_sixty_seconds_reads_inactive():
    """Use Case 4.2 step 5a: "if no messages arrive within 60 seconds".

    Sixty seconds of silence IS the transition, not the last moment before it.
    The boundary is inclusive, so 60.000s reads INACTIVE.
    """
    assert effective_status(SourceStatus.ACTIVE, _ago(60), NOW) == SourceStatus.INACTIVE


def test_just_under_the_boundary_still_reads_active():
    """59.999s is the last moment a source is still reporting."""
    almost = NOW - timedelta(seconds=59, milliseconds=999)
    assert effective_status(SourceStatus.ACTIVE, almost, NOW) == SourceStatus.ACTIVE


def test_past_the_window_reads_inactive():
    """61 seconds of silence is unambiguously past the transition."""
    assert effective_status(SourceStatus.ACTIVE, _ago(61), NOW) == SourceStatus.INACTIVE


def test_long_silence_reads_inactive():
    assert effective_status(SourceStatus.ACTIVE, _ago(86_400), NOW) == SourceStatus.INACTIVE


def test_traffic_resuming_returns_to_active():
    """The stored status is still whatever the last write left; a fresh
    last_received is enough to read ACTIVE again with no extra bookkeeping."""
    assert effective_status(SourceStatus.INACTIVE, _ago(2), NOW) == SourceStatus.ACTIVE


def test_new_source_reads_active_before_the_window_elapses():
    """Use Case 4.2 step 4 registers a source ACTIVE with a green indicator.

    Nothing has been received yet, so the countdown runs from created_at —
    otherwise the confirmation screen would show INACTIVE the instant the
    source was saved, contradicting the use case's main flow.
    """
    got = effective_status(SourceStatus.ACTIVE, None, NOW, created_at=_ago(5))
    assert got == SourceStatus.ACTIVE


def test_new_source_that_never_receives_goes_inactive():
    got = effective_status(SourceStatus.ACTIVE, None, NOW, created_at=_ago(120))
    assert got == SourceStatus.INACTIVE


def test_error_status_is_never_overridden():
    """An errored source needs an operator. Relabelling it INACTIVE because it
    is also quiet would hide the fault behind an ordinary-looking state."""
    assert effective_status(SourceStatus.ERROR, _ago(10_000), NOW) == SourceStatus.ERROR
    assert effective_status(SourceStatus.ERROR, _ago(1), NOW) == SourceStatus.ERROR


def test_naive_timestamp_is_treated_as_utc():
    """Defensive: a row written without tzinfo must not raise on comparison."""
    naive = NOW.replace(tzinfo=None) - timedelta(seconds=5)
    assert effective_status(SourceStatus.ACTIVE, naive, NOW) == SourceStatus.ACTIVE


def test_timeout_follows_the_configured_setting(monkeypatch):
    """The 60 seconds is Use Case 4.2's number, not a magic constant."""
    monkeypatch.setattr(settings, "source_inactive_after_seconds", 5)
    assert effective_status(SourceStatus.ACTIVE, _ago(4), NOW) == SourceStatus.ACTIVE
    assert effective_status(SourceStatus.ACTIVE, _ago(5), NOW) == SourceStatus.INACTIVE


class _FakeSource:
    def __init__(self, status, last_received, created_at):
        self.status = status
        self.last_received = last_received
        self.created_at = created_at
        self.source_id = uuid.uuid4()


def test_is_effectively_active_predicate():
    live = _FakeSource(SourceStatus.ACTIVE, _ago(3), _ago(1000))
    quiet = _FakeSource(SourceStatus.ACTIVE, _ago(600), _ago(1000))
    assert is_effectively_active(live, NOW) is True
    assert is_effectively_active(quiet, NOW) is False


# --- API-level tests (need PostgreSQL) --------------------------------------

pytest.importorskip("fastapi.testclient")

from fastapi.testclient import TestClient          # noqa: E402

from app.core.security import hash_password        # noqa: E402
from app.database import SessionLocal              # noqa: E402
from app.main import app                           # noqa: E402
from app.models import (                           # noqa: E402
    AdminRole, Administrator, AuditLog, DataSource, SourceType,
)

PASSWORD = "TestPassw0rd!"


@pytest.fixture()
def admin():
    email = f"srcstatus-{uuid.uuid4().hex[:8]}@threatsense.local"
    with SessionLocal() as db:
        row = Administrator(full_name="Source Status Test", email=email,
                            password_hash=hash_password(PASSWORD),
                            role=AdminRole.ADMIN)
        db.add(row)
        db.commit()
        ids = {"admin_id": row.admin_id, "email": email}
    yield ids
    with SessionLocal() as db:
        db.query(DataSource).filter(
            DataSource.admin_id == ids["admin_id"]).delete(synchronize_session=False)
        db.query(AuditLog).filter(AuditLog.admin_id == ids["admin_id"]).delete()
        db.query(Administrator).filter(
            Administrator.admin_id == ids["admin_id"]).delete()
        db.commit()


def _client(ids):
    c = TestClient(app)
    c.__enter__()
    r = c.post("/api/auth/login", json={"email": ids["email"], "password": PASSWORD})
    assert r.status_code == 200, r.text
    return c


def _source(admin_id, last_received):
    with SessionLocal() as db:
        src = DataSource(admin_id=admin_id, name=f"s-{uuid.uuid4().hex[:6]}",
                         type=SourceType.SYSLOG, status=SourceStatus.ACTIVE,
                         last_received=last_received)
        db.add(src)
        db.commit()
        return src.source_id


def test_list_sources_reports_the_effective_status(admin):
    """A source last heard from ten minutes ago must not list as ACTIVE."""
    stale = _source(admin["admin_id"],
                    datetime.now(timezone.utc) - timedelta(minutes=10))
    fresh = _source(admin["admin_id"],
                    datetime.now(timezone.utc) - timedelta(seconds=2))
    with _client(admin) as c:
        rows = {r["source_id"]: r["status"] for r in c.get("/api/sources").json()}
    assert rows[str(stale)] == "INACTIVE"
    assert rows[str(fresh)] == "ACTIVE"


def test_get_source_agrees_with_the_list(admin):
    stale = _source(admin["admin_id"],
                    datetime.now(timezone.utc) - timedelta(minutes=10))
    with _client(admin) as c:
        assert c.get(f"/api/sources/{stale}").json()["status"] == "INACTIVE"


def test_dashboard_active_count_matches_log_sources(admin):
    """The regression that motivated read-time derivation: the Dashboard card
    counted the stored column while the table showed something else, so the
    same system reported two different numbers on two screens."""
    _source(admin["admin_id"], datetime.now(timezone.utc) - timedelta(minutes=10))
    _source(admin["admin_id"], datetime.now(timezone.utc) - timedelta(seconds=2))
    with _client(admin) as c:
        card = c.get("/api/dashboard/health").json()["active_sources"]
        listed = sum(1 for r in c.get("/api/sources").json()
                     if r["status"] == "ACTIVE")
    assert card == listed == 1
