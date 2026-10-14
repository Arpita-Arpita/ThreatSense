"""Account management and self-service password change (Section 2.1).

    cd backend && source .venv/bin/activate
    pytest tests/test_accounts.py -v

WHY THIS EXISTS
---------------
Section 2.1 requires two things this file covers:

    "Direct registration is available only for the initial administrator.
     Additional accounts are created by an authenticated SUPER_ADMIN through
     a controlled account-management workflow"

Initial setup covered the first. Until now there was no workflow for the
second, so the three-role design was unreachable in practice: a VIEWER account
could only be produced by inserting a row into PostgreSQL by hand. That is not
a controlled workflow, and it is not something an SMB operator could do.

The password-change endpoint is the other half. It is distinct from the reset
flow, which exists for someone who cannot sign in; this is for someone already
signed in, and it therefore has to verify the current password. Without that
check, an unattended unlocked screen is a permanent account takeover rather
than a temporary one.

ISOLATION
---------
Own scratch database per test, autouse, same pattern as the setup and
source-resolution suites — these tests create and delete administrator
accounts, which must never touch a configured system.
"""
from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.security import hash_password
from app.main import app
from app.models import AdminRole, Administrator, AuditLog

SCRATCH_DB_PREFIX = "threatsense_accounts_test_"
PASSWORD = "OwnerPass1!"


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
    """An isolated, empty database for every test in this module."""
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


def _make(role: AdminRole, password: str = PASSWORD) -> dict:
    email = f"{role.value.lower()}-{uuid.uuid4().hex[:6]}@threatsense.local"
    with _sessions()() as db:
        row = Administrator(full_name=f"{role.value} User", email=email,
                            password_hash=hash_password(password), role=role)
        db.add(row)
        db.commit()
        return {"admin_id": row.admin_id, "email": email, "role": role}


def _client(account, password: str = PASSWORD) -> TestClient:
    c = TestClient(app)
    c.__enter__()
    r = c.post("/api/auth/login",
               json={"email": account["email"], "password": password})
    assert r.status_code == 200, r.text
    return c


def _count() -> int:
    with _sessions()() as db:
        return db.scalar(select(func.count()).select_from(Administrator))


def _payload(**over):
    body = {"full_name": "Demo Viewer",
            "email": f"viewer-{uuid.uuid4().hex[:6]}@threatsense.local",
            "password": "ViewerPass1!", "role": "VIEWER"}
    body.update(over)
    return body


# --- change your own password -------------------------------------------------

def test_change_password_requires_authentication():
    with TestClient(app) as anon:
        r = anon.post("/api/auth/change-password",
                      json={"current_password": PASSWORD, "new_password": "NewPass1!"})
    assert r.status_code == 401


def test_wrong_current_password_is_refused():
    """Without this check, an unlocked unattended screen is a permanent
    takeover rather than a temporary one."""
    me = _make(AdminRole.ADMIN)
    c = _client(me)
    try:
        r = c.post("/api/auth/change-password",
                   json={"current_password": "NotMyPassword1!", "new_password": "NewPass1!"})
    finally:
        c.__exit__(None, None, None)
    assert r.status_code == 400


@pytest.mark.parametrize("weak", ["short", "alllowercase1!", "NOUPPERCASE1!",
                                  "NoDigitsHere!", "NoSpecialChar1"])
def test_new_password_must_satisfy_the_policy(weak):
    """NFR-11 applies at every entry point, not only at setup and reset."""
    me = _make(AdminRole.ADMIN)
    c = _client(me)
    try:
        r = c.post("/api/auth/change-password",
                   json={"current_password": PASSWORD, "new_password": weak})
    finally:
        c.__exit__(None, None, None)
    assert r.status_code == 422


def test_password_change_takes_effect():
    me = _make(AdminRole.ADMIN)
    c = _client(me)
    try:
        assert c.post("/api/auth/change-password",
                      json={"current_password": PASSWORD,
                            "new_password": "Rotated1!"}).status_code == 200
        c.post("/api/auth/logout")
        old = c.post("/api/auth/login", json={"email": me["email"], "password": PASSWORD})
        new = c.post("/api/auth/login", json={"email": me["email"], "password": "Rotated1!"})
    finally:
        c.__exit__(None, None, None)
    assert old.status_code == 401, "the old password still works"
    assert new.status_code == 200, "the new password does not work"


def test_password_change_is_audited():
    """Section 2.7: every administrator action is tracked in audit_logs."""
    me = _make(AdminRole.ADMIN)
    c = _client(me)
    try:
        c.post("/api/auth/change-password",
               json={"current_password": PASSWORD, "new_password": "Rotated1!"})
    finally:
        c.__exit__(None, None, None)
    with _sessions()() as db:
        entries = db.scalars(select(AuditLog).where(
            AuditLog.details.like("password changed%"))).all()
    assert entries


def test_a_viewer_may_change_their_own_password():
    """Read-only applies to system state, not to your own credentials."""
    me = _make(AdminRole.VIEWER)
    c = _client(me)
    try:
        r = c.post("/api/auth/change-password",
                   json={"current_password": PASSWORD, "new_password": "Rotated1!"})
    finally:
        c.__exit__(None, None, None)
    assert r.status_code == 200


# --- account management is SUPER_ADMIN only -----------------------------------

@pytest.mark.parametrize("role", [AdminRole.ADMIN, AdminRole.VIEWER])
def test_only_super_admin_may_list_accounts(role):
    """Knowing who holds an account, and with what role, is reconnaissance for
    anyone who has compromised a lesser account."""
    c = _client(_make(role))
    try:
        r = c.get("/api/accounts")
    finally:
        c.__exit__(None, None, None)
    assert r.status_code == 403


@pytest.mark.parametrize("role", [AdminRole.ADMIN, AdminRole.VIEWER])
def test_only_super_admin_may_create_accounts(role):
    c = _client(_make(role))
    before = _count()          # after the acting account exists
    try:
        r = c.post("/api/accounts", json=_payload())
    finally:
        c.__exit__(None, None, None)
    assert r.status_code == 403
    assert _count() == before, "a refused request created an account"


def test_unauthenticated_account_management_is_401():
    with TestClient(app) as anon:
        assert anon.get("/api/accounts").status_code == 401
        assert anon.post("/api/accounts", json=_payload()).status_code == 401


# --- creating accounts --------------------------------------------------------

def test_super_admin_can_create_a_viewer():
    """The workflow Section 2.1 asks for, and what makes the VIEWER role
    reachable without hand-editing the database."""
    c = _client(_make(AdminRole.SUPER_ADMIN))
    body = _payload()
    try:
        r = c.post("/api/accounts", json=body)
    finally:
        c.__exit__(None, None, None)
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "VIEWER"
    assert r.json()["email"] == body["email"].lower()


def test_the_created_account_can_sign_in():
    c = _client(_make(AdminRole.SUPER_ADMIN))
    body = _payload()
    try:
        assert c.post("/api/accounts", json=body).status_code == 201
    finally:
        c.__exit__(None, None, None)
    with TestClient(app) as c2:
        r = c2.post("/api/auth/login",
                    json={"email": body["email"], "password": body["password"]})
    assert r.status_code == 200, "a created account cannot log in"


def test_created_viewer_cannot_mutate():
    """End to end: the account created through the UI really is read-only."""
    c = _client(_make(AdminRole.SUPER_ADMIN))
    body = _payload()
    try:
        c.post("/api/accounts", json=body)
    finally:
        c.__exit__(None, None, None)
    with TestClient(app) as v:
        v.post("/api/auth/login",
               json={"email": body["email"], "password": body["password"]})
        assert v.post("/api/settings/scan").status_code == 403


def test_super_admin_cannot_be_created_here():
    """Escalation should be a deliberate act, not a dropdown option."""
    c = _client(_make(AdminRole.SUPER_ADMIN))
    before = _count()
    try:
        r = c.post("/api/accounts", json=_payload(role="SUPER_ADMIN"))
    finally:
        c.__exit__(None, None, None)
    assert r.status_code == 422
    assert _count() == before


@pytest.mark.parametrize("field,value", [
    ("full_name", ""), ("full_name", "   "), ("full_name", "x" * 151),
    ("email", ""), ("email", "not-an-email"), ("email", "x" * 252 + "@b.co"),
    ("role", "WIZARD"),
])
def test_invalid_account_details_are_refused(field, value):
    c = _client(_make(AdminRole.SUPER_ADMIN))
    before = _count()
    try:
        r = c.post("/api/accounts", json=_payload(**{field: value}))
    finally:
        c.__exit__(None, None, None)
    assert r.status_code == 422
    assert _count() == before


def test_weak_initial_password_is_refused():
    c = _client(_make(AdminRole.SUPER_ADMIN))
    before = _count()
    try:
        r = c.post("/api/accounts", json=_payload(password="weak"))
    finally:
        c.__exit__(None, None, None)
    assert r.status_code == 422
    assert _count() == before


def test_duplicate_email_is_refused():
    c = _client(_make(AdminRole.SUPER_ADMIN))
    body = _payload()
    try:
        assert c.post("/api/accounts", json=body).status_code == 201
        again = c.post("/api/accounts", json=body)
    finally:
        c.__exit__(None, None, None)
    assert again.status_code == 409


def test_account_creation_is_audited():
    c = _client(_make(AdminRole.SUPER_ADMIN))
    try:
        c.post("/api/accounts", json=_payload())
    finally:
        c.__exit__(None, None, None)
    with _sessions()() as db:
        entries = db.scalars(select(AuditLog).where(
            AuditLog.details.like("created account%"))).all()
    assert entries

# --- deletion is deliberately not offered -------------------------------------

def test_account_deletion_is_not_exposed():
    """No DELETE route, by design.

    audit_logs.admin_id has no cascade rule and every login writes a row, so
    any account that has actually been used cannot be deleted — the attempt
    fails on the foreign key. A Remove button that works only for accounts
    nobody has ever signed into is worse than no button. When lifecycle
    management is added it should disable an account, not erase an
    administrator who appears in the audit history.
    """
    c = _client(_make(AdminRole.SUPER_ADMIN))
    body = _payload()
    try:
        created = c.post("/api/accounts", json=body).json()
        r = c.delete(f"/api/accounts/{created['admin_id']}")
    finally:
        c.__exit__(None, None, None)
    assert r.status_code in (404, 405), \
        "a delete route is exposed; see the module docstring in routers/accounts.py"
