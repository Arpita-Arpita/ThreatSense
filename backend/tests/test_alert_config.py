"""Integration tests for the alert configuration API (task 2.1).

Runs against a real PostgreSQL instance — the same database the app uses — so
the UNIQUE constraint, ENUM types and TIME columns are all genuinely exercised.

    cd backend && source .venv/bin/activate
    pytest tests/test_alert_config.py -v
"""
from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.security import hash_password
from app.database import SessionLocal
from app.main import app
from app.models import AdminRole, Administrator, AlertConfig, AuditAction, AuditLog
from app.services.alerting import config_cache

PASSWORD = "TestPassw0rd!"


@pytest.fixture()
def admin():
    """A throwaway admin, removed afterwards along with everything it owns."""
    email = f"pytest-{uuid.uuid4().hex[:8]}@threatsense.local"
    with SessionLocal() as db:
        row = Administrator(full_name="Pytest Admin", email=email,
                            password_hash=hash_password(PASSWORD),
                            role=AdminRole.ADMIN)
        db.add(row)
        db.commit()
        db.refresh(row)
        admin_id = row.admin_id
    yield {"admin_id": admin_id, "email": email}
    with SessionLocal() as db:
        db.query(AuditLog).filter(AuditLog.admin_id == admin_id).delete()
        db.query(AlertConfig).filter(AlertConfig.admin_id == admin_id).delete()
        db.query(Administrator).filter(Administrator.admin_id == admin_id).delete()
        db.commit()
    config_cache.invalidate(admin_id)


@pytest.fixture()
def client(admin):
    with TestClient(app) as c:
        r = c.post("/api/auth/login", json={"email": admin["email"], "password": PASSWORD})
        assert r.status_code == 200, r.text
        yield c


# --- access control ---------------------------------------------------------

def test_requires_authentication():
    with TestClient(app) as anon:
        assert anon.get("/api/alert-config").status_code == 401
        assert anon.put("/api/alert-config", json={}).status_code == 401


# --- defaults ---------------------------------------------------------------

def test_get_returns_defaults_on_first_access(client, admin):
    r = client.get("/api/alert-config")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["email_enabled"] is True
    assert body["sms_enabled"] is False
    assert body["severity_threshold"] == "HIGH"          # proposal default
    assert body["email_recipient"] == admin["email"]     # seeded from login email
    assert body["quiet_start"] is None and body["quiet_end"] is None


def test_get_does_not_create_a_row(client, admin):
    """GET is read-only. It used to INSERT a default row on first access.

    That was harmless while every authenticated caller could also write, but
    VIEWER is now read-only (Section 2.1), and a read route that writes makes
    "read-only" untrue. GET now returns unsaved defaults, with config_id and
    updated_at null to mark them as not persisted.
    """
    body = client.get("/api/alert-config").json()
    assert body["config_id"] is None
    assert body["email_enabled"] is True          # defaults still rendered
    with SessionLocal() as db:
        rows = db.scalars(
            select(AlertConfig).where(AlertConfig.admin_id == admin["admin_id"])
        ).all()
    assert rows == []


def test_saving_creates_exactly_one_row_and_get_is_then_stable(client, admin):
    """The row is created by the first save, and only one ever exists."""
    client.patch("/api/alert-config", json={"severity_threshold": "MEDIUM"})
    first = client.get("/api/alert-config").json()
    second = client.get("/api/alert-config").json()
    assert first["config_id"] is not None
    assert first["config_id"] == second["config_id"]
    with SessionLocal() as db:
        rows = db.scalars(
            select(AlertConfig).where(AlertConfig.admin_id == admin["admin_id"])
        ).all()
    assert len(rows) == 1


def test_unique_constraint_blocks_a_second_row(client, admin):
    # A save, not a GET: GET no longer creates the row (see above).
    client.patch("/api/alert-config", json={"severity_threshold": "MEDIUM"})
    from sqlalchemy.exc import IntegrityError
    with SessionLocal() as db:
        db.add(AlertConfig(admin_id=admin["admin_id"], email_recipient="dup@example.com"))
        with pytest.raises(IntegrityError):
            db.commit()


# --- updates ----------------------------------------------------------------

def test_put_replaces_all_fields(client):
    client.get("/api/alert-config")
    r = client.put("/api/alert-config", json={
        "email_enabled": True,
        "email_recipient": "soc@securesmb.com.au",
        "severity_threshold": "CRITICAL",
        "quiet_start": "22:00:00",
        "quiet_end": "06:00:00",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["email_recipient"] == "soc@securesmb.com.au"
    assert body["severity_threshold"] == "CRITICAL"
    assert body["quiet_start"] == "22:00:00"
    assert body["quiet_end"] == "06:00:00"


def test_patch_changes_only_what_is_sent(client):
    client.put("/api/alert-config", json={
        "email_recipient": "keep@example.com", "severity_threshold": "MEDIUM",
    })
    r = client.patch("/api/alert-config", json={"severity_threshold": "ALL"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["severity_threshold"] == "ALL"
    assert body["email_recipient"] == "keep@example.com"   # untouched


def test_email_is_normalised(client):
    r = client.patch("/api/alert-config", json={"email_recipient": "  SOC@Example.COM  "})
    assert r.json()["email_recipient"] == "soc@example.com"


def test_updated_at_advances_on_change(client):
    # Save first: an unsaved default has updated_at = None by design.
    before = client.patch("/api/alert-config",
                          json={"severity_threshold": "HIGH"}).json()["updated_at"]
    after = client.patch("/api/alert-config",
                         json={"severity_threshold": "MEDIUM"}).json()["updated_at"]
    assert after > before


# --- validation -------------------------------------------------------------

def test_rejects_invalid_email(client):
    r = client.patch("/api/alert-config", json={"email_recipient": "not-an-email"})
    assert r.status_code == 422


def test_rejects_enabling_email_without_recipient(client):
    """The merged-state check: clearing the recipient while email stays on."""
    client.get("/api/alert-config")
    r = client.patch("/api/alert-config", json={"email_recipient": None})
    assert r.status_code == 422
    assert "email_recipient is required" in r.text


def test_toggle_on_with_empty_stored_recipient_is_rejected(client):
    """PATCH that only flips the toggle must still validate the stored row."""
    client.put("/api/alert-config", json={"email_enabled": False, "email_recipient": None})
    r = client.patch("/api/alert-config", json={"email_enabled": True})
    assert r.status_code == 422


def test_email_can_be_disabled_without_a_recipient(client):
    r = client.put("/api/alert-config", json={"email_enabled": False, "email_recipient": None})
    assert r.status_code == 200
    assert r.json()["email_enabled"] is False


def test_rejects_enabling_sms(client):
    r = client.patch("/api/alert-config", json={"sms_enabled": True})
    assert r.status_code == 422
    assert "planned enhancement" in r.text


def test_sms_recipient_stored_but_channel_stays_off(client):
    r = client.patch("/api/alert-config", json={"sms_recipient": "+61412345678"})
    assert r.status_code == 200
    assert r.json()["sms_recipient"] == "+61412345678"
    assert r.json()["sms_enabled"] is False


def test_rejects_bad_e164(client):
    assert client.patch("/api/alert-config",
                        json={"sms_recipient": "0412 345 678"}).status_code == 422


def test_rejects_half_a_quiet_window(client):
    assert client.patch("/api/alert-config",
                        json={"quiet_start": "22:00:00"}).status_code == 422


def test_rejects_zero_length_quiet_window(client):
    r = client.patch("/api/alert-config",
                     json={"quiet_start": "22:00:00", "quiet_end": "22:00:00"})
    assert r.status_code == 422


def test_overnight_quiet_window_is_valid(client):
    r = client.patch("/api/alert-config",
                     json={"quiet_start": "22:00:00", "quiet_end": "06:00:00"})
    assert r.status_code == 200


def test_rejects_unknown_severity(client):
    assert client.patch("/api/alert-config",
                        json={"severity_threshold": "URGENT"}).status_code == 422


def test_rejects_empty_patch(client):
    assert client.patch("/api/alert-config", json={}).status_code == 422


# --- auditing ---------------------------------------------------------------

def test_change_writes_config_change_audit_row(client, admin):
    client.get("/api/alert-config")
    client.patch("/api/alert-config", json={"severity_threshold": "CRITICAL"})
    with SessionLocal() as db:
        rows = db.scalars(
            select(AuditLog).where(AuditLog.admin_id == admin["admin_id"],
                                   AuditLog.action == AuditAction.CONFIG_CHANGE)
        ).all()
    assert any("severity_threshold" in (r.details or "") for r in rows)


def test_no_op_save_writes_no_audit_row(client, admin):
    current = client.get("/api/alert-config").json()
    before = _audit_count(admin["admin_id"])
    client.put("/api/alert-config", json={
        "email_enabled": current["email_enabled"],
        "email_recipient": current["email_recipient"],
        "severity_threshold": current["severity_threshold"],
    })
    assert _audit_count(admin["admin_id"]) == before


def _audit_count(admin_id) -> int:
    with SessionLocal() as db:
        return len(db.scalars(
            select(AuditLog).where(AuditLog.admin_id == admin_id)
        ).all())


# --- cache ------------------------------------------------------------------

def test_cache_reflects_update_immediately(client, admin):
    client.put("/api/alert-config", json={
        "email_recipient": "cache@example.com", "severity_threshold": "MEDIUM"})
    with SessionLocal() as db:
        cached = config_cache.get(db, admin["admin_id"])
    assert cached is not None
    assert cached.email_recipient == "cache@example.com"
    assert cached.severity_threshold.value == "MEDIUM"


def test_cache_entry_dropped_on_delete(client, admin):
    client.get("/api/alert-config")
    assert client.delete("/api/alert-config").status_code == 204
    with SessionLocal() as db:
        assert db.scalar(
            select(AlertConfig).where(AlertConfig.admin_id == admin["admin_id"])) is None
    r = client.get("/api/alert-config")   # recreated with defaults
    assert r.status_code == 200
    assert r.json()["severity_threshold"] == "HIGH"


def test_prime_loads_existing_rows(client):
    client.get("/api/alert-config")
    with SessionLocal() as db:
        loaded = config_cache.prime(db)
    assert loaded >= 1
