"""
NFR-05, login clause — per-IP sliding-window rate limiting (task 1.4).

    cd backend && source .venv/bin/activate
    pytest tests/test_login_rate_limit.py -v

Proposal Section 3, Table 11, NFR-05 — Requirement (verbatim):
    "Rate limiting: five login attempts per IP within a 15-minute window; ten
    report generations per administrator per hour. Exceeding limits returns
    HTTP 429."

Proposal Section 3, Table 11, NFR-05 — Measurement / Metric (verbatim):
    "Test scripts (automated) to send requests in rapid succession and check
    for HTTP 429 response at specified thresholds."

This file IS that automated test script for the login clause; the report
clause is covered by tests/test_reports.py. Each of the three literal
parameters in the requirement — the count (5), the scope (per IP), and the
window (15 minutes) — gets its own test, so a future edit that changes one of
them fails loudly rather than quietly diverging from Table 11.

The 15-minute window is exercised by advancing a fake clock, not by sleeping.
"""
from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.core.security import hash_password
from app.database import SessionLocal
from app.main import app
from app.middleware import rate_limit as rate_limit_module
from app.middleware.rate_limit import login_rate_limiter
from app.models import AdminRole, Administrator, AuditLog

PASSWORD = "TestPassw0rd!"


class FakeClock:
    """Monotonic clock the tests can advance instantly."""

    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture()
def clock(monkeypatch):
    fake = FakeClock()
    monkeypatch.setattr(rate_limit_module, "_monotonic", fake)
    login_rate_limiter.reset()
    yield fake
    login_rate_limiter.reset()


@pytest.fixture()
def admin():
    """A real administrator, so a correct password can actually succeed."""
    email = f"ratelimit-{uuid.uuid4().hex[:8]}@threatsense.local"
    with SessionLocal() as db:
        row = Administrator(full_name="Rate Limit Test", email=email,
                            password_hash=hash_password(PASSWORD),
                            role=AdminRole.ADMIN)
        db.add(row)
        db.commit()
        admin_id = row.admin_id
    yield {"admin_id": admin_id, "email": email}
    with SessionLocal() as db:
        db.query(AuditLog).filter(AuditLog.admin_id == admin_id).delete()
        db.query(Administrator).filter(Administrator.admin_id == admin_id).delete()
        db.commit()


def _client(ip: str) -> TestClient:
    """A TestClient that presents a specific source address."""
    return TestClient(app, client=(ip, 40000))


def _attempt(client: TestClient, email: str, password: str):
    return client.post("/api/auth/login", json={"email": email, "password": password})


def _probe(client: TestClient):
    """One attempt against an email that matches no account.

    Used by the tests that isolate the per-IP window. A real account would
    trip the separate failed_attempts lockout (423) on its fifth failure and
    mask the 401/429 distinction these tests are measuring.
    """
    return _attempt(client, f"nobody-{uuid.uuid4().hex[:8]}@threatsense.local",
                    "WrongPassw0rd!")


# --- the count: "five login attempts" -------------------------------------

def test_fifth_attempt_is_allowed_and_sixth_returns_429(clock):
    """Table 11, NFR-05: five attempts per IP; "Exceeding limits returns HTTP 429"."""
    client = _client("203.0.113.10")
    for i in range(5):
        assert _probe(client).status_code == 401, \
            f"attempt {i + 1} should reach the credential check"

    assert _probe(client).status_code == 429


def test_limit_matches_the_configured_threshold():
    """The 5 in the test is the 5 in Table 11, not an independent constant."""
    assert settings.login_rate_limit == 5
    assert settings.login_rate_window_minutes == 15


def test_successful_logins_also_count_against_the_window(clock, admin):
    """NFR-05 throttles "login attempts", not "failed login attempts".

    Reading a success exemption into the requirement would be a silent
    divergence from Table 11, so a valid password consumes a slot too.
    """
    client = _client("203.0.113.11")
    for _ in range(5):
        res = _attempt(client, admin["email"], PASSWORD)
        assert res.status_code == 200

    assert _attempt(client, admin["email"], PASSWORD).status_code == 429


# --- the response: "returns HTTP 429" -------------------------------------

def test_429_carries_a_retry_after_header(clock):
    client = _client("203.0.113.12")
    for _ in range(5):
        _probe(client)

    res = _probe(client)
    assert res.status_code == 429
    retry_after = res.headers.get("retry-after")
    assert retry_after is not None
    assert 0 < int(retry_after) <= settings.login_rate_window_minutes * 60


def test_rejected_attempts_do_not_extend_the_window(clock):
    """Hammering the endpoint while blocked must not push the reset further out."""
    client = _client("203.0.113.13")
    for _ in range(5):
        _probe(client)

    first = int(_probe(client).headers["retry-after"])
    clock.advance(60)
    for _ in range(10):
        _probe(client)
    second = int(_probe(client).headers["retry-after"])

    assert second <= first - 59, "blocked attempts must not reset the window"


# --- the scope: "per IP" ---------------------------------------------------

def test_window_is_scoped_per_ip(clock):
    """One exhausted IP must not throttle a different one."""
    exhausted = _client("203.0.113.20")
    for _ in range(5):
        _probe(exhausted)
    assert _probe(exhausted).status_code == 429

    other = _client("203.0.113.21")
    assert _probe(other).status_code == 401


def test_attempts_against_unknown_emails_still_count(clock):
    """The enumeration-spray case the audit_logs table cannot see.

    audit_logs.admin_id is NOT NULL, so no row is written when the email
    matches no account. The counter must catch these anyway.
    """
    client = _client("203.0.113.30")
    for _ in range(5):
        res = _attempt(client, f"nobody-{uuid.uuid4().hex[:6]}@threatsense.local", "WrongPassw0rd!")
        assert res.status_code == 401

    res = _attempt(client, "nobody-final@threatsense.local", "WrongPassw0rd!")
    assert res.status_code == 429


# --- the window: "within a 15-minute window" -------------------------------

def test_window_reopens_after_fifteen_minutes(clock):
    client = _client("203.0.113.40")
    for _ in range(5):
        _probe(client)
    assert _probe(client).status_code == 429

    clock.advance(settings.login_rate_window_minutes * 60 + 1)
    assert _probe(client).status_code == 401


def test_window_still_closed_just_before_fifteen_minutes(clock):
    """Boundary: the window must not reopen early."""
    client = _client("203.0.113.41")
    for _ in range(5):
        _probe(client)

    clock.advance(settings.login_rate_window_minutes * 60 - 10)
    assert _probe(client).status_code == 429


def test_window_slides_rather_than_resetting_wholesale(clock):
    """A sliding window frees slots one at a time, not all five at once."""
    client = _client("203.0.113.42")
    for _ in range(4):
        _probe(client)
    clock.advance(600)                      # 10 min: first four are 10 min old
    _probe(client)                          # fifth, fresh
    assert _probe(client).status_code == 429

    clock.advance(301)                      # first four age out; fifth has not
    for _ in range(4):
        assert _probe(client).status_code == 401
    assert _probe(client).status_code == 429


# --- defence in depth: the account lockout is NOT NFR-05 -------------------

def test_account_lockout_survives_alongside_the_ip_window(clock, admin):
    """The 423 lockout defends a different surface and must remain reachable.

    Five failures against one account are spread across five DIFFERENT IPs, so
    no single IP window fills. The per-account counter still trips.
    """
    for i in range(settings.max_failed_attempts):
        res = _attempt(_client(f"198.51.100.{i + 1}"), admin["email"], "WrongPassw0rd!")
        assert res.status_code == 401

    res = _attempt(_client("198.51.100.99"), admin["email"], PASSWORD)
    assert res.status_code == 423, "per-IP limiting must not have replaced the lockout"
