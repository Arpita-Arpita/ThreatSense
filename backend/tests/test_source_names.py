"""Source name uniqueness per administrator (task 4.1 follow-up).

Names identify collectors in the Log Sources table and are the only source
reference recorded in audit_logs, so duplicates make both ambiguous.

    cd backend && source .venv/bin/activate
    pytest tests/test_source_names.py -v
"""
from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.security import hash_password
from app.database import SessionLocal
from app.main import app
from app.models import (
    AdminRole, Administrator, AuditLog, DataSource, SourceStatus, SourceType,
)

PASSWORD = "TestPassw0rd!"


def _make_admin():
    email = f"names-{uuid.uuid4().hex[:8]}@threatsense.local"
    with SessionLocal() as db:
        admin = Administrator(full_name="Names Test", email=email,
                              password_hash=hash_password(PASSWORD),
                              role=AdminRole.ADMIN)
        db.add(admin)
        db.commit()
        return {"admin_id": admin.admin_id, "email": email}


def _teardown(ids):
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


@pytest.fixture()
def admin():
    ids = _make_admin()
    yield ids
    _teardown(ids)


@pytest.fixture()
def client(admin):
    c = _client(admin)
    yield c
    c.__exit__(None, None, None)


def _payload(name="edge-firewall", **over):
    body = {"name": name, "type": "SYSLOG", "transport": "TLS",
            "ip_address": "192.168.1.20", "port": 6514, "status": "ACTIVE"}
    body.update(over)
    return body


def test_duplicate_name_is_rejected_with_409(client):
    assert client.post("/api/sources", json=_payload()).status_code == 201
    r = client.post("/api/sources", json=_payload())
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert "edge-firewall" in detail
    assert "unique" in detail.lower()


def test_rejection_leaves_exactly_one_source(client, admin):
    client.post("/api/sources", json=_payload())
    client.post("/api/sources", json=_payload(ip_address="10.0.0.9"))
    with SessionLocal() as db:
        rows = db.scalars(select(DataSource).where(
            DataSource.admin_id == admin["admin_id"])).all()
    assert len(rows) == 1
    assert str(rows[0].ip_address) == "192.168.1.20", "the first insert must survive"


def test_renaming_onto_an_existing_name_is_rejected(client):
    first = client.post("/api/sources", json=_payload("alpha")).json()
    client.post("/api/sources", json=_payload("beta"))
    r = client.patch(f"/api/sources/{first['source_id']}", json={"name": "beta"})
    assert r.status_code == 409
    # the rollback must not lose the original name
    assert client.get(f"/api/sources/{first['source_id']}").json()["name"] == "alpha"


def test_renaming_a_source_to_a_free_name_still_works(client):
    src = client.post("/api/sources", json=_payload("alpha")).json()
    r = client.patch(f"/api/sources/{src['source_id']}", json={"name": "gamma"})
    assert r.status_code == 200
    assert r.json()["name"] == "gamma"


def test_a_source_can_be_saved_without_changing_its_own_name(client):
    """Editing port/IP must not trip the constraint against the row itself."""
    src = client.post("/api/sources", json=_payload("alpha")).json()
    r = client.patch(f"/api/sources/{src['source_id']}",
                     json={"name": "alpha", "port": 1514, "transport": "UDP"})
    assert r.status_code == 200
    assert r.json()["port"] == 1514


def test_two_admins_may_each_use_the_same_name(admin):
    """Uniqueness is per admin, not global — one tenant must not consume
    another tenant's names."""
    other = _make_admin()
    try:
        a = _client(admin)
        b = _client(other)
        try:
            assert a.post("/api/sources", json=_payload("shared-name")).status_code == 201
            assert b.post("/api/sources", json=_payload("shared-name")).status_code == 201
        finally:
            a.__exit__(None, None, None)
            b.__exit__(None, None, None)
    finally:
        _teardown(other)


def test_a_failed_create_writes_no_source_audit_row(client, admin):
    """The audit entry is added in the same transaction as the source, so a
    rejected duplicate must not leave a 'create source' record behind."""
    client.post("/api/sources", json=_payload("alpha"))
    client.post("/api/sources", json=_payload("alpha"))
    with SessionLocal() as db:
        rows = db.scalars(select(AuditLog).where(
            AuditLog.admin_id == admin["admin_id"])).all()
    creates = [r for r in rows if "create source 'alpha'" in (r.details or "")]
    assert len(creates) == 1, "the rejected duplicate must not be audited as created"
