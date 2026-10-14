"""Account lockout expiry (Phase 6 optional item).

    cd backend && source .venv/bin/activate
    pytest tests/test_account_lockout.py -v

WHY THIS EXISTS
---------------
Two different throttles guard login, and conflating them is the trap:

  NFR-05, Table 11: "five login attempts per IP within a 15-minute window;
  ... Exceeding limits returns HTTP 429."  Enforced per IP by middleware.

  Account lockout: administrators.failed_attempts reaching
  max_failed_attempts returns 423. This is per ACCOUNT, and Table 11 does
  not require it — Section 2.1 describes failed_attempts as supporting
  "account-level monitoring".

Before this change the 423 lockout never expired. An administrator who
mistyped five times was locked permanently and could only recover through a
successful password reset or a manual UPDATE. The expiry window is derived
from the most recent failed-login entry in audit_logs, so no column is added
to administrators — the proposal's Table 2 defines that table's fields
exactly.

These tests manipulate audit timestamps directly rather than sleeping; a
real 15-minute wait is not a test.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.config import settings
from app.core.security import hash_password
from app.database import SessionLocal
from app.main import app
from app.middleware.rate_limit import login_rate_limiter
from app.models import AdminRole, Administrator, AuditAction, AuditLog

PASSWORD = "LockoutTest1!"
WRONG = "WrongPassword9!"


@pytest.fixture()
def admin():
    email = f"lockout-{uuid.uuid4().hex[:8]}@threatsense.local"
    with SessionLocal() as db:
        row = Administrator(full_name="Lockout Test", email=email,
                            password_hash=hash_password(PASSWORD),
                            role=AdminRole.ADMIN)
        db.add(row)
        db.commit()
        admin_id = row.admin_id
    yield {"admin_id": admin_id, "email": email}
    with SessionLocal() as db:
        db.query(AuditLog).filter(AuditLog.admin_id == admin_id).delete()
        db.query(Administrator).filter(
            Administrator.admin_id == admin_id).delete()
        db.commit()


def _login(client, email, password):
    return client.post("/api/auth/login",
                       json={"email": email, "password": password})


def _lock(client, admin):
    """Drive the account into lockout, then clear the per-IP window.

    Filling failed_attempts also fills NFR-05's per-IP window, because both
    thresholds are five and the IP check runs first (see
    test_per_ip_throttle_shadows_the_account_lockout below). Without the
    reset, every assertion after this point would see 429 and the account
    lockout would be untestable through the API. TestClient reports one
    client host for the whole process, so this mirrors what conftest.py
    already does for the same reason.
    """
    for _ in range(settings.max_failed_attempts):
        _login(client, admin["email"], WRONG)
    with SessionLocal() as db:
        row = db.get(Administrator, admin["admin_id"])
        assert row.failed_attempts >= settings.max_failed_attempts
    login_rate_limiter.reset()


def _age_failures(admin, minutes):
    """Backdate this admin's failed-login audit entries."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    with SessionLocal() as db:
        rows = db.scalars(
            select(AuditLog).where(AuditLog.admin_id == admin["admin_id"],
                                   AuditLog.action == AuditAction.LOGIN)).all()
        for r in rows:
            r.created_at = cutoff
        db.commit()


# --- the lock still locks -----------------------------------------------------

def test_account_locks_after_max_failed_attempts(admin):
    with TestClient(app) as c:
        _lock(c, admin)
        r = _login(c, admin["email"], WRONG)
    assert r.status_code == 423


def test_correct_password_is_still_refused_while_locked(admin):
    """The lockout must not be bypassable by finally getting it right."""
    with TestClient(app) as c:
        _lock(c, admin)
        r = _login(c, admin["email"], PASSWORD)
    assert r.status_code == 423


# --- ... and now expires ------------------------------------------------------

def test_lockout_expires_after_the_window(admin):
    """The defect being fixed: this used to stay 423 forever."""
    with TestClient(app) as c:
        _lock(c, admin)
        _age_failures(admin, settings.account_lockout_minutes + 1)
        r = _login(c, admin["email"], PASSWORD)
    assert r.status_code == 200, r.text


def test_expiry_clears_the_counter(admin):
    with TestClient(app) as c:
        _lock(c, admin)
        _age_failures(admin, settings.account_lockout_minutes + 1)
        _login(c, admin["email"], PASSWORD)
    with SessionLocal() as db:
        assert db.get(Administrator, admin["admin_id"]).failed_attempts == 0


def test_lockout_holds_just_inside_the_window(admin):
    """Boundary: one minute short of the window must still be locked."""
    with TestClient(app) as c:
        _lock(c, admin)
        _age_failures(admin, settings.account_lockout_minutes - 1)
        r = _login(c, admin["email"], PASSWORD)
    assert r.status_code == 423


def test_wrong_password_after_expiry_relocks_rather_than_passing(admin):
    """Expiry grants a fresh attempt, not an exemption."""
    with TestClient(app) as c:
        _lock(c, admin)
        _age_failures(admin, settings.account_lockout_minutes + 1)
        r = _login(c, admin["email"], WRONG)
        assert r.status_code == 401
        with SessionLocal() as db:
            assert db.get(Administrator, admin["admin_id"]).failed_attempts == 1


# --- what the locked-out response tells the administrator ---------------------

def test_locked_response_carries_retry_after_header(admin):
    with TestClient(app) as c:
        _lock(c, admin)
        r = _login(c, admin["email"], WRONG)
    assert "Retry-After" in r.headers
    seconds = int(r.headers["Retry-After"])
    assert 0 < seconds <= settings.account_lockout_minutes * 60


def test_locked_message_states_when_to_return(admin):
    with TestClient(app) as c:
        _lock(c, admin)
        r = _login(c, admin["email"], WRONG)
    detail = r.json()["detail"]
    assert "minute" in detail.lower()
    # Must remain a readable string, not a serialised object.
    assert isinstance(detail, str)


def test_retry_after_shrinks_as_the_window_elapses(admin):
    with TestClient(app) as c:
        _lock(c, admin)
        first = int(_login(c, admin["email"], WRONG).headers["Retry-After"])
        _age_failures(admin, settings.account_lockout_minutes // 2)
        later = int(_login(c, admin["email"], WRONG).headers["Retry-After"])
    assert later < first


# --- degraded cases -----------------------------------------------------------

def test_missing_audit_history_fails_open(admin):
    """Pruned audit rows must not strand an account permanently.

    Fail-open is the deliberate choice here: an account locked forever with
    no surviving record of why is the defect this work removes. NFR-05's
    per-IP throttle still applies underneath.
    """
    with TestClient(app) as c:
        _lock(c, admin)
        with SessionLocal() as db:
            db.query(AuditLog).filter(
                AuditLog.admin_id == admin["admin_id"]).delete()
            db.commit()
        r = _login(c, admin["email"], PASSWORD)
    assert r.status_code == 200, r.text


def test_lockout_window_is_independent_of_other_accounts(admin):
    """One locked account must not lock or unlock another."""
    other_email = f"lockout-other-{uuid.uuid4().hex[:8]}@threatsense.local"
    with SessionLocal() as db:
        other = Administrator(full_name="Other", email=other_email,
                              password_hash=hash_password(PASSWORD),
                              role=AdminRole.ADMIN)
        db.add(other)
        db.commit()
        other_id = other.admin_id
    try:
        with TestClient(app) as c:
            _lock(c, admin)
            r = _login(c, other_email, PASSWORD)
        assert r.status_code == 200, r.text
    finally:
        with SessionLocal() as db:
            db.query(AuditLog).filter(AuditLog.admin_id == other_id).delete()
            db.query(Administrator).filter(
                Administrator.admin_id == other_id).delete()
            db.commit()


# --- interaction between the two throttles -----------------------------------

def test_per_ip_throttle_shadows_the_account_lockout(admin):
    """Documents real behaviour, not a defect — but a surprising one.

    Table 11, NFR-05: "five login attempts per IP within a 15-minute window
    ... Exceeding limits returns HTTP 429."

    max_failed_attempts and login_rate_limit are both five, and the per-IP
    check runs before authenticate(). A single attacker from one address
    therefore always meets 429 and never sees the 423: the account lockout
    only becomes reachable when attempts arrive from several addresses
    against one account — which is when a per-account control is the one
    that matters. Worth stating in the report, because a reader who tries to
    reproduce a 423 by hand from one machine will not be able to.
    """
    with TestClient(app) as c:
        codes = [_login(c, admin["email"], WRONG).status_code
                 for _ in range(settings.max_failed_attempts + 1)]

    assert codes[:settings.max_failed_attempts] == [401] * settings.max_failed_attempts
    assert codes[-1] == 429, "expected the per-IP throttle to fire before the lockout"
