"""Initial administrator setup (Section 2.1, NFR-08, Figure 3).

    cd backend && source .venv/bin/activate
    pytest tests/test_initial_setup.py -v

WHY THIS EXISTS
---------------
Section 2.1, verbatim:

    "Direct registration is available only for the initial administrator.
     Additional accounts are created by an authenticated SUPER_ADMIN through
     a controlled account-management workflow"

Figure 3 shows the login screen carrying an Initial Setup link "Available
only before the first administrator account is created".

Neither existed. The only route to an account was db/seed.py, which creates
admin@threatsense.local with a hard-coded password — a development fixture
standing in for the product's first-run experience.

That also left NFR-08 unmeasurable. Table 11 asks that "a first-time
administrator with basic IT knowledge must be able to complete initial setup
or sign in, configure a Syslog source, and view their first detection result
within 15 minutes of initial access, without consulting external
documentation". With no setup to perform, the clock could not start.

THE SECURITY QUESTION
---------------------
POST /api/auth/setup must be public — nobody can authenticate before the
first account exists — so "exactly one" is the entire boundary. A
count-then-insert check in Python does not hold it: two requests arriving
together both read zero administrators and both create a SUPER_ADMIN.

Enforcement is therefore a partial unique index
(db/migrations/002_single_initial_admin.sql). The concurrency test below is
the one that matters; the rest describe the surrounding behaviour.
"""
from __future__ import annotations

import asyncio
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.database import SessionLocal
from app.main import app
from app.models import (
    AdminRole, Administrator, AuditLog, DataSource, DetectionSettings,
)

GOOD_PASSWORD = "SetupFlow1!"


# The setup path is only reachable when NO administrator exists, so these
# tests need an empty database. The first version of this fixture emptied the
# REAL one — nine DELETE statements across every table, then a re-seed. On a
# development machine holding months of captured detections and the project's
# own evidence, running the suite would have destroyed it.
#
# A skip guard was the obvious alternative and the wrong one: it would leave
# the concurrency test silently not running, which is how a security test
# becomes decoration.
#
# So these tests build their own scratch database instead, apply the real
# schema and migrations to it, point the app at it for the duration, and drop
# it afterwards.  If the configured PostgreSQL role lacks CREATEDB the module
# is skipped explicitly; otherwise no configured application database is read
# or written.

# A unique name per fixture invocation. A fixed name meant the fixture began
# with DROP DATABASE IF EXISTS, which would destroy a pre-existing database
# that happened to share the name — a smaller version of the mistake this
# whole fixture exists to undo. A unique name also lets the suite run in
# parallel without workers fighting over one database.
SCRATCH_DB_PREFIX = "threatsense_setup_test_"


def _admin_db_url() -> str:
    """The configured URL with the database name replaced by 'postgres'.

    CREATE DATABASE cannot run inside the database being created, so the
    maintenance connection goes to the always-present 'postgres' database.
    """
    from app.config import settings as app_settings
    base, _, _name = app_settings.database_url.rpartition("/")
    return f"{base}/postgres"


def _scratch_url(name: str) -> str:
    from app.config import settings as app_settings
    base, _, _name = app_settings.database_url.rpartition("/")
    return f"{base}/{name}"


@pytest.fixture(autouse=True)
def empty_system():
    """An isolated, empty database for EVERY test in this module.

    Both ``app.database.SessionLocal`` and the copy imported into
    ``app.main`` are redirected.  The latter matters because TestClient runs
    the FastAPI lifespan and ``config_cache.prime()`` uses the SessionLocal
    name captured by app.main at import time.  Without overriding that copy,
    every setup test still read alert_config from the configured database.

    The cleanup boundary begins immediately after CREATE DATABASE succeeds,
    so a schema/migration failure cannot strand a scratch database.
    """
    import sqlalchemy
    from pathlib import Path
    from app.database import get_db
    import app.database as database_mod
    import app.main as main_mod

    scratch_db = f"{SCRATCH_DB_PREFIX}{uuid.uuid4().hex[:12]}"
    admin_engine = sqlalchemy.create_engine(
        _admin_db_url(), isolation_level="AUTOCOMMIT")
    scratch_engine = None
    created = False
    original_database_sessionlocal = database_mod.SessionLocal
    original_main_sessionlocal = main_mod.SessionLocal

    try:
        try:
            with admin_engine.connect() as conn:
                # CREATE only.  The random name means there is no reason to
                # delete any pre-existing database before the test starts.
                conn.execute(sqlalchemy.text(f'CREATE DATABASE "{scratch_db}"'))
            created = True
        except Exception as exc:                  # pragma: no cover
            pytest.skip(
                f"cannot create the scratch database ({exc}); the configured "
                f"user needs CREATEDB")

        scratch_engine = sqlalchemy.create_engine(
            _scratch_url(scratch_db), pool_pre_ping=True)
        scratch_sessions = sqlalchemy.orm.sessionmaker(
            bind=scratch_engine, autoflush=False, expire_on_commit=False)

        # Real schema + real migrations, so setup is tested against deployment
        # DDL, including the single-initial-admin partial unique index.
        db_dir = Path(__file__).resolve().parent.parent / "db"
        sql_files = [db_dir / "schema.sql"] + sorted(
            (db_dir / "migrations").glob("*.sql"))
        with scratch_engine.connect() as conn:
            for path in sql_files:
                conn.exec_driver_sql(path.read_text())
                conn.commit()

        database_mod.SessionLocal = scratch_sessions
        main_mod.SessionLocal = scratch_sessions
        globals()["SessionLocal"] = scratch_sessions

        def _override_get_db():
            db = scratch_sessions()
            try:
                yield db
            finally:
                db.close()

        main_mod.app.dependency_overrides[get_db] = _override_get_db
        yield
    finally:
        main_mod.app.dependency_overrides.pop(get_db, None)
        database_mod.SessionLocal = original_database_sessionlocal
        main_mod.SessionLocal = original_main_sessionlocal
        globals()["SessionLocal"] = original_database_sessionlocal

        if scratch_engine is not None:
            scratch_engine.dispose()
        if created:
            try:
                with admin_engine.connect() as conn:
                    conn.execute(sqlalchemy.text(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        f"WHERE datname = '{scratch_db}' "
                        "AND pid <> pg_backend_pid()"))
                    conn.execute(sqlalchemy.text(
                        f'DROP DATABASE IF EXISTS "{scratch_db}"'))
            finally:
                admin_engine.dispose()
        else:
            admin_engine.dispose()


def _sessions():
    """Resolve the session factory at CALL time.

    empty_system swaps app.database.SessionLocal for the scratch factory, so
    a module-level import captured at collection time would still point at
    the real database — which is exactly the mistake this fixture exists to
    prevent.
    """
    import app.database as database_mod
    return database_mod.SessionLocal


def _admin_count() -> int:
    with _sessions()() as db:
        return db.scalar(select(func.count()).select_from(Administrator))


def _configure_system() -> dict:
    """Create the first administrator INSIDE the scratch database.

    Tests asserting "already configured" behaviour previously relied on the
    real database happening to contain an administrator. That made them
    dependent on external state and, on an empty database, turned a test that
    claimed to check refusal into one that created the system's first
    SUPER_ADMIN.
    """
    body = _payload()
    with TestClient(app) as c:
        r = c.post("/api/auth/setup", json=body)
    assert r.status_code == 201, f"could not configure the scratch system: {r.text}"
    return body


def _payload(**over):
    body = {"full_name": "First Operator",
            "email": f"setup-test-{uuid.uuid4().hex[:8]}@threatsense.local",
            "password": GOOD_PASSWORD}
    body.update(over)
    return body


# --- setup-status drives the Initial Setup link (Figure 3) -------------------

def test_setup_status_is_public():
    """The login screen calls it before anyone can authenticate."""
    with TestClient(app) as c:
        r = c.get("/api/auth/setup-status")
    assert r.status_code == 200
    assert "setup_required" in r.json()


def test_setup_status_is_true_on_an_unconfigured_system():
    with TestClient(app) as c:
        assert c.get("/api/auth/setup-status").json()["setup_required"] is True


def test_setup_status_is_false_once_an_administrator_exists():
    _configure_system()
    with TestClient(app) as c:
        assert c.get("/api/auth/setup-status").json()["setup_required"] is False


# --- setup is refused once complete ------------------------------------------

def test_setup_is_refused_when_an_administrator_already_exists():
    _configure_system()
    before = _admin_count()
    with TestClient(app) as c:
        r = c.post("/api/auth/setup", json=_payload())
    assert r.status_code == 409, r.text
    assert _admin_count() == before, "a second administrator was created"


def test_refusal_names_the_route_to_an_account():
    """A dead end is a usability failure; Section 2.1 says a SUPER_ADMIN
    creates later accounts, so the message should say so."""
    _configure_system()
    with TestClient(app) as c:
        detail = c.post("/api/auth/setup", json=_payload()).json()["detail"]
    assert "SUPER_ADMIN" in detail


# --- the happy path on an unconfigured system --------------------------------

def test_first_administrator_can_be_created():
    body = _payload()
    with TestClient(app) as c:
        r = c.post("/api/auth/setup", json=body)
    assert r.status_code == 201, r.text
    assert r.json()["email"] == body["email"].lower()


def test_first_administrator_is_super_admin():
    """Section 2.1 reserves account creation for SUPER_ADMIN. A first account
    with any lesser role could never create the second."""
    body = _payload()
    with TestClient(app) as c:
        c.post("/api/auth/setup", json=body)
    with _sessions()() as db:
        admin = db.scalar(select(Administrator).where(
            Administrator.email == body["email"].lower()))
    assert admin.role == AdminRole.SUPER_ADMIN
    assert admin.is_initial_admin is True


def test_the_new_administrator_can_log_in():
    body = _payload()
    with TestClient(app) as c:
        assert c.post("/api/auth/setup", json=body).status_code == 201
        r = c.post("/api/auth/login",
                   json={"email": body["email"], "password": body["password"]})
    assert r.status_code == 200, r.text


def test_fresh_setup_bootstraps_detection_settings_atomically():
    """A fresh product install must be usable without db/seed.py.

    NFR-08 requires a first-time operator to progress from setup to a first
    detection without external documentation.  The engine cannot run unless
    the singleton detection_settings row exists.
    """
    body = _payload()
    with TestClient(app) as c:
        assert c.post("/api/auth/setup", json=body).status_code == 201

    with _sessions()() as db:
        admins = db.scalars(select(Administrator)).all()
        settings_rows = db.scalars(select(DetectionSettings)).all()

    assert len(admins) == 1
    assert len(settings_rows) == 1
    cfg = settings_rows[0]
    assert float(cfg.sensitivity_threshold) == 0.75
    assert cfg.active_model_version == "IF_v1.0"
    assert cfg.detection_interval_seconds == 60
    assert cfg.updated_by == admins[0].admin_id


def test_settings_endpoint_works_immediately_after_fresh_setup():
    body = _payload()
    with TestClient(app) as c:
        assert c.post("/api/auth/setup", json=body).status_code == 201
        login = c.post("/api/auth/login",
                       json={"email": body["email"],
                             "password": body["password"]})
        assert login.status_code == 200, login.text
        response = c.get("/api/settings")

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["sensitivity_threshold"] == 0.75
    assert payload["active_model_version"] == "IF_v1.0"
    assert payload["detection_interval_seconds"] == 60


def test_seed_helper_does_not_create_a_second_administrator_after_setup(monkeypatch):
    body = _payload()
    with TestClient(app) as c:
        assert c.post("/api/auth/setup", json=body).status_code == 201

    before = _admin_count()
    from db import seed as seed_module

    def _must_not_hash(_password):
        raise AssertionError(
            "seed tried to create another administrator instead of reusing "
            "the account created by Initial Setup")

    monkeypatch.setattr(seed_module, "hash_password", _must_not_hash)
    with _sessions()() as db:
        seed_module.seed(db)
        db.commit()
    after = _admin_count()

    assert before == 1
    assert after == 1, (
        "the development seed helper created another administrator after "
        "Initial Setup")


def test_bootstrap_failure_rolls_back_the_administrator(monkeypatch):
    """Setup must not close itself with a half-configured database."""
    from app.services.auth.setup import create_first_administrator

    with _sessions()() as db:
        def _failed_commit():
            raise RuntimeError("simulated bootstrap commit failure")

        monkeypatch.setattr(db, "commit", _failed_commit)
        with pytest.raises(RuntimeError, match="simulated bootstrap"):
            create_first_administrator(
                db, full_name="Rollback Test",
                email="rollback@example.com", password=GOOD_PASSWORD)

    with _sessions()() as db:
        assert db.scalar(select(func.count()).select_from(Administrator)) == 0
        assert db.scalar(select(func.count()).select_from(DetectionSettings)) == 0


def test_setup_status_flips_after_setup():
    with TestClient(app) as c:
        assert c.get("/api/auth/setup-status").json()["setup_required"] is True
        c.post("/api/auth/setup", json=_payload())
        assert c.get("/api/auth/setup-status").json()["setup_required"] is False


def test_setup_is_audited():
    """Section 2.7: "Every administrator action is tracked in audit_logs"."""
    body = _payload()
    with TestClient(app) as c:
        c.post("/api/auth/setup", json=body)
    with _sessions()() as db:
        entries = db.scalars(select(AuditLog).where(
            AuditLog.details.like("initial administrator setup%"))).all()
    assert entries, "setup wrote no audit entry"


# --- NFR-11 applies to the registration form ---------------------------------

@pytest.mark.parametrize("password,missing", [
    ("Short1!", "fewer than 8 characters"),
    ("alllowercase1!", "no uppercase letter"),
    ("ALLUPPERCASE1!", "no lowercase letter"),
    ("NoDigitsHere!", "no digit"),
    ("NoSpecialChar1", "no special character"),
])
def test_weak_passwords_are_rejected_at_setup(password, missing):
    """Table 11, NFR-11, verbatim: "a minimum of 8 characters, with at least
    one uppercase letter, one lowercase letter, one digit, and one special
    character ... validated on both the client side and the server side".

    The proposal names the REGISTRATION FORM as the client-side site. That
    form did not exist, which is why NFR-11's evidence previously came from
    the password-reset screen instead.
    """
    with TestClient(app) as c:
        r = c.post("/api/auth/setup", json=_payload(password=password))
    assert r.status_code == 422, f"accepted a password with {missing}"
    assert isinstance(r.json()["detail"], str), "detail must stay readable"
    assert _admin_count() == 0, "a rejected setup created an administrator"


def test_rejection_lists_what_is_missing():
    with TestClient(app) as c:
        detail = c.post("/api/auth/setup",
                        json=_payload(password="short")).json()["detail"]
    assert len(detail) > 10, "the message should say what is wrong"


# --- the security boundary ----------------------------------------------------

def test_concurrent_setup_requests_create_only_one_administrator():
    """The test this endpoint exists to survive.

    /api/auth/setup is public, so "exactly one administrator" is the entire
    boundary. A count-then-insert check cannot hold it: both requests read
    zero and both proceed. Enforcement is a partial unique index, so the
    second insert fails in the database whatever the timing.

    Threads rather than asyncio: the handler is synchronous and each needs
    its own database session, which is how the race happens in production.
    """

    import threading
    results: list[int] = []
    barrier = threading.Barrier(4)

    def _attempt():
        with TestClient(app) as c:
            barrier.wait()                       # fire together
            results.append(c.post("/api/auth/setup", json=_payload()).status_code)

    threads = [threading.Thread(target=_attempt) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    created = _admin_count()
    assert created == 1, (
        f"{created} administrators created by 4 concurrent setup requests; "
        f"responses were {sorted(results)}")
    assert results.count(201) == 1, f"expected one 201, got {sorted(results)}"


def test_database_refuses_a_second_initial_admin_directly():
    """Prove the index, not just the endpoint.

    If the guard were only in the router, any other code path creating an
    administrator could still produce a second initial account.
    """
    from sqlalchemy.exc import IntegrityError

    with _sessions()() as db:
        for i in range(2):
            db.add(Administrator(
                full_name=f"Direct {i}",
                email=f"setup-test-direct-{i}-{uuid.uuid4().hex[:6]}@x.local",
                password_hash="x" * 60, role=AdminRole.SUPER_ADMIN,
                is_initial_admin=True))
        with pytest.raises(IntegrityError):
            db.commit()


# --- Fix 5b: server-side identity validation (public endpoint) ---------------
#
# /api/auth/setup is public and creates the most privileged account in the
# platform, so the browser's type="email" is a convenience, not a boundary.
# Before this, a direct caller could create the first SUPER_ADMIN with
# full_name="" (a whitespace-only value strips to empty, and NOT NULL does
# not reject an empty string) and email="not-an-email"; a 10,000-character
# value passed Pydantic and failed inside PostgreSQL as a 500.

@pytest.mark.parametrize("field,value,why", [
    ("full_name", "", "empty name"),
    ("full_name", "   ", "whitespace-only name strips to empty"),
    ("full_name", "x" * 151, "name exceeds Table 2's VARCHAR(150)"),
    ("email", "", "empty email"),
    ("email", "   ", "whitespace-only email"),
    ("email", "not-an-email", "no @ or domain"),
    ("email", "no-domain@", "missing domain"),
    ("email", "@no-local.com", "missing local part"),
    ("email", "has space@x.com", "whitespace inside the address"),
    ("email", "x" * 252 + "@b.co", "email exceeds Table 2's VARCHAR(255)"),
])
def test_invalid_identity_fields_are_rejected(field, value, why):
    with TestClient(app) as c:
        r = c.post("/api/auth/setup", json=_payload(**{field: value}))
    assert r.status_code == 422, f"accepted {why}"
    assert _admin_count() == 0, f"a rejected setup created an administrator ({why})"


def test_identity_fields_are_trimmed_and_normalised():
    with TestClient(app) as c:
        r = c.post("/api/auth/setup", json=_payload(
            full_name="  Ada Lovelace  ", email="  Ada@Example.COM  "))
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["full_name"] == "Ada Lovelace"
    assert body["email"] == "ada@example.com"


@pytest.mark.parametrize("length,expected", [(150, 201), (151, 422)])
def test_full_name_length_boundary_matches_table_2(length, expected):
    with TestClient(app) as c:
        r = c.post("/api/auth/setup", json=_payload(full_name="x" * length))
    assert r.status_code == expected


@pytest.mark.parametrize("length,expected", [(255, 201), (256, 422)])
def test_email_length_boundary_matches_table_2(length, expected):
    local = "x" * (length - len("@example.com"))
    with TestClient(app) as c:
        r = c.post("/api/auth/setup", json=_payload(email=f"{local}@example.com"))
    assert r.status_code == expected


# --- Fix 5b: the response must not depend on the password once setup is done -

def test_completed_setup_returns_409_regardless_of_password():
    """The route's contract is "409 once setup is complete".

    Validating the password first made the answer depend on it: a strong
    password got 409, a weak one 422, on a system where neither could create
    an account. Availability is answered first now.
    """
    _configure_system()
    with TestClient(app) as c:
        strong = c.post("/api/auth/setup", json=_payload())
        weak = c.post("/api/auth/setup", json=_payload(password="short"))
    assert strong.status_code == 409
    assert weak.status_code == 409, (
        "a weak password changed the answer on an already-configured system")


# --- Fix 5b: the fixture must not touch the real database --------------------

def test_the_scratch_fixture_does_not_use_the_configured_database():
    """Guard on the guard.

    The first version of this fixture emptied the REAL database — nine
    DELETEs and a re-seed — which on a development machine would have
    destroyed months of captured detections. If someone later "simplifies"
    the fixture back to that, this fails.
    """
    import app.database as database_mod
    import app.main as main_mod
    from app.config import settings as app_settings

    database_url = str(database_mod.SessionLocal.kw["bind"].url)
    lifespan_url = str(main_mod.SessionLocal.kw["bind"].url)
    for label, url in (("database", database_url), ("lifespan", lifespan_url)):
        assert SCRATCH_DB_PREFIX in url, (
            f"{label} SessionLocal points at {url!r}, not the scratch database")
        assert url != app_settings.database_url
