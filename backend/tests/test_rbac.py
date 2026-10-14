"""Role-based access control (Section 2.1).

    cd backend && source .venv/bin/activate
    pytest tests/test_rbac.py -v

WHY THIS EXISTS
---------------
Section 2.1 states each administrator holds "one of three roles
(SUPER_ADMIN, ADMIN, or VIEWER) that determines their access permissions
across the system".

An external audit found the roles were decorative: they existed on the model
and in the JWT, and no endpoint checked them. A VIEWER could add and delete
sources, upload logs, change the shared detection threshold and model, run
manual scans, rewrite alert configuration, send external email, acknowledge
detections and generate AI reports that spend OpenAI quota.

POLICY (agreed before implementation, since the proposal does not enumerate
per-endpoint permissions):

    SUPER_ADMIN   everything ADMIN can do, plus account management
    ADMIN         full operational administration
    VIEWER        read-only

ROLE AND OWNERSHIP ARE SEPARATE CHECKS

Role decides which actions an account may perform; ownership decides whose
data it may act on. SUPER_ADMIN deliberately does NOT bypass ownership —
widening it to organisation-wide visibility would change the approved design.
test_super_admin_does_not_bypass_ownership pins that.

STATUS CODES

    401  no/invalid session
    403  authenticated, role insufficient
    404  object outside this account's ownership scope

404 for a wrong-owner object is deliberate: it does not confirm the object
exists. 403 for a role failure is safe, because the caller knows their role.
"""
from __future__ import annotations

import io
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.security import hash_password
from app.database import SessionLocal
from app.main import app
from app.middleware import rbac
from app.models import (AdminRole, Administrator, AlertConfig, AuditLog,
                        DataSource, Detection, DetectionSettings, SourceStatus)

PASSWORD = "RbacTest1!"


def _make_admin(role: AdminRole):
    email = f"rbac-{role.value.lower()}-{uuid.uuid4().hex[:6]}@threatsense.local"
    with SessionLocal() as db:
        row = Administrator(full_name=f"RBAC {role.value}", email=email,
                            password_hash=hash_password(PASSWORD), role=role)
        db.add(row)
        db.commit()
        return {"admin_id": row.admin_id, "email": email, "role": role}


def _cleanup(admin_id):
    with SessionLocal() as db:
        src_ids = list(db.scalars(
            select(DataSource.source_id).where(DataSource.admin_id == admin_id)))
        if src_ids:
            db.query(Detection).filter(Detection.source_id.in_(src_ids)).delete(
                synchronize_session=False)
            db.query(DataSource).filter(
                DataSource.source_id.in_(src_ids)).delete(synchronize_session=False)
        db.query(AlertConfig).filter(AlertConfig.admin_id == admin_id).delete()
        db.query(AuditLog).filter(AuditLog.admin_id == admin_id).delete()
        # detection_settings is a single shared row whose updated_by points at
        # whoever last changed it. An operator test that patches settings or
        # runs a scan becomes that referent, so re-point it before deleting the
        # account or the FK blocks the cleanup.
        cfg = db.scalar(select(DetectionSettings))
        if cfg is not None and cfg.updated_by == admin_id:
            other = db.scalar(select(Administrator).where(
                Administrator.admin_id != admin_id))
            if other is not None:
                cfg.updated_by = other.admin_id
                db.flush()
        db.query(Administrator).filter(Administrator.admin_id == admin_id).delete()
        db.commit()


@pytest.fixture()
def viewer():
    a = _make_admin(AdminRole.VIEWER)
    yield a
    _cleanup(a["admin_id"])


@pytest.fixture()
def operator():
    a = _make_admin(AdminRole.ADMIN)
    yield a
    _cleanup(a["admin_id"])


@pytest.fixture()
def superadmin():
    a = _make_admin(AdminRole.SUPER_ADMIN)
    yield a
    _cleanup(a["admin_id"])


def _client(admin):
    c = TestClient(app)
    c.__enter__()
    r = c.post("/api/auth/login",
               json={"email": admin["email"], "password": PASSWORD})
    assert r.status_code == 200, r.text
    return c


def _source_for(admin):
    with SessionLocal() as db:
        src = DataSource(admin_id=admin["admin_id"],
                         name=f"rbac-src-{uuid.uuid4().hex[:6]}", type="SYSLOG",
                         ip_address="10.7.7.7", port=1514, transport="UDP",
                         status=SourceStatus.ACTIVE)
        db.add(src)
        db.commit()
        return src.source_id


# Every mutating endpoint, as (label, method, path-template, json, files).
MUTATIONS = [
    ("create source",  "post",   "/api/sources",
     {"name": "x-{u}", "type": "SYSLOG", "ip_address": "10.1.1.1",
      "port": 1514, "transport": "UDP"}, None),
    ("update source",  "patch",  "/api/sources/{src}", {"name": "renamed-{u}"}, None),
    ("delete source",  "delete", "/api/sources/{src}", None, None),
    ("upload logs",    "post",   "/api/sources/{src}/upload", None, "file"),
    ("update settings", "patch", "/api/settings", {"sensitivity_threshold": 0.8}, None),
    ("manual scan",    "post",   "/api/settings/scan", None, None),
    ("replace alert config", "put", "/api/alert-config",
     {"email_enabled": True, "sms_enabled": False,
      "email_recipient": "x@y.local", "severity_threshold": "HIGH"}, None),
    ("update alert config", "patch", "/api/alert-config", {"email_enabled": False}, None),
    ("delete alert config", "delete", "/api/alert-config", None, None),
    ("send test alert", "post", "/api/alert-config/test", None, None),
    ("acknowledge",    "patch",  "/api/detections/{det}/acknowledge", None, None),
    ("generate report", "post",  "/api/detections/{det}/reports", None, None),
]

READS = [
    "/api/dashboard/health", "/api/dashboard/alerts", "/api/dashboard/analytics",
    "/api/sources", "/api/settings", "/api/settings/models", "/api/settings/metrics",
    "/api/detections", "/api/detections/stats", "/api/alert-config",
]


def _call(client, method, path, body, files):
    fn = getattr(client, method)
    if files:
        return client.post(path, files={"file": ("logs.txt", io.BytesIO(b"x"), "text/plain")})
    if body is None:
        return fn(path)
    return fn(path, json=body)


def _fill(path, src, det):
    return (path.replace("{src}", str(src)).replace("{det}", str(det)))


# --- VIEWER is denied every mutation -----------------------------------------

@pytest.mark.parametrize("label,method,path,body,files", MUTATIONS,
                         ids=[m[0] for m in MUTATIONS])
def test_viewer_is_denied_every_mutation(viewer, label, method, path, body, files):
    src = _source_for(viewer)
    det = uuid.uuid4()          # never reached: 403 must precede the lookup
    c = _client(viewer)
    try:
        b = body
        if isinstance(b, dict):
            b = {k: (v.replace("{u}", uuid.uuid4().hex[:6]) if isinstance(v, str) else v)
                 for k, v in b.items()}
        r = _call(c, method, _fill(path, src, det), b, files)
    finally:
        c.__exit__(None, None, None)
    assert r.status_code == 403, f"{label}: expected 403, got {r.status_code} {r.text[:200]}"


def test_viewer_denial_changes_no_state(viewer):
    """403 must be refusal, not refusal-after-doing-it."""
    src = _source_for(viewer)
    with SessionLocal() as db:
        before_name = db.get(DataSource, src).name

    c = _client(viewer)
    # Counted AFTER logging in: the login itself writes a LOGIN audit row
    # (Section 2.1), which is expected and must not be mistaken for a
    # side effect of the refused requests below.
    with SessionLocal() as db:
        audits_before = db.query(AuditLog).filter(
            AuditLog.admin_id == viewer["admin_id"]).count()
    try:
        assert c.patch(f"/api/sources/{src}", json={"name": "hacked"}).status_code == 403
        assert c.delete(f"/api/sources/{src}").status_code == 403
    finally:
        c.__exit__(None, None, None)

    with SessionLocal() as db:
        row = db.get(DataSource, src)
        assert row is not None, "source was deleted despite 403"
        assert row.name == before_name, "source was renamed despite 403"
        after = db.query(AuditLog).filter(
            AuditLog.admin_id == viewer["admin_id"]).count()
    assert after == audits_before, "a 403 wrote an audit entry"


def test_viewer_cannot_send_external_email(viewer, monkeypatch):
    """The test-alert route must not reach the sender at all."""
    from app.routers import alerts as alerts_router
    called = []
    monkeypatch.setattr(alerts_router, "get_sender",
                        lambda: called.append(1) or (_ for _ in ()).throw(
                            AssertionError("sender was constructed for a VIEWER")))
    c = _client(viewer)
    try:
        assert c.post("/api/alert-config/test").status_code == 403
    finally:
        c.__exit__(None, None, None)
    assert called == []


# --- VIEWER keeps every read --------------------------------------------------

@pytest.mark.parametrize("path", READS)
def test_viewer_may_read(viewer, path):
    c = _client(viewer)
    try:
        r = c.get(path)
    finally:
        c.__exit__(None, None, None)
    assert r.status_code == 200, f"{path}: {r.status_code} {r.text[:200]}"


def test_reading_alert_config_does_not_create_a_row(viewer):
    """A read-only role must not write. The GET used to insert a default row."""
    c = _client(viewer)
    try:
        assert c.get("/api/alert-config").status_code == 200
    finally:
        c.__exit__(None, None, None)
    with SessionLocal() as db:
        assert db.scalar(select(AlertConfig).where(
            AlertConfig.admin_id == viewer["admin_id"])) is None


# --- operator roles are allowed ----------------------------------------------

@pytest.mark.parametrize("role_fixture", ["operator", "superadmin"])
def test_operator_roles_may_mutate(role_fixture, request):
    admin = request.getfixturevalue(role_fixture)
    c = _client(admin)
    try:
        r = c.post("/api/sources", json={
            "name": f"ok-{uuid.uuid4().hex[:6]}", "type": "SYSLOG",
            "ip_address": "10.2.2.2", "port": 1514, "transport": "UDP"})
        assert r.status_code == 201, r.text
        assert c.patch("/api/settings",
                       json={"sensitivity_threshold": 0.77}).status_code == 200
        assert c.post("/api/settings/scan").status_code == 200
    finally:
        c.__exit__(None, None, None)


# --- the three status codes stay distinct ------------------------------------

def test_unauthenticated_is_401_not_403():
    with TestClient(app) as anon:
        assert anon.get("/api/sources").status_code == 401
        assert anon.post("/api/settings/scan").status_code == 401


def test_wrong_owner_is_404_even_for_a_permitted_role(operator, superadmin):
    """Ownership is a separate check from role, and it answers 404."""
    other_src = _source_for(superadmin)
    c = _client(operator)
    try:
        assert c.get(f"/api/sources/{other_src}").status_code == 404
        assert c.patch(f"/api/sources/{other_src}",
                       json={"name": "nope"}).status_code == 404
    finally:
        c.__exit__(None, None, None)


def test_super_admin_does_not_bypass_ownership(operator, superadmin):
    """SUPER_ADMIN is a wider ROLE, not wider data visibility.

    Section 2.1 gives SUPER_ADMIN the account-management workflow, not
    organisation-wide access to other administrators' sources and detections.
    Granting that would be a change to the approved design.
    """
    others_src = _source_for(operator)
    c = _client(superadmin)
    try:
        assert c.get(f"/api/sources/{others_src}").status_code == 404
        listed = c.get("/api/sources").json()
    finally:
        c.__exit__(None, None, None)
    assert str(others_src) not in str(listed)


# --- the matrix itself --------------------------------------------------------

def test_every_operational_route_declares_a_role_policy():
    """No operational route may be registered without a role dependency.

    Guard that outlives us: an endpoint added later without a require_*
    dependency fails here rather than shipping unprotected.

    DELIBERATE EXCLUSIONS, and why each is safe:

      auth public routes  login, password-reset request/confirm, and the
                          password policy must work before authentication.
      /api/auth/me        every authenticated role may read its own account;
      /api/auth/logout    every authenticated role may end its own session.
                          Both use bare get_current_admin, which is
                          equivalent to require_read for them. Adding a role
                          dependency would be cosmetic.
      /health (root)      the unauthenticated liveness probe NFR-06 measures
                          against.

    The routers below are every router that serves per-account data.
    """
    import inspect
    from app.routers import (alerts, dashboard, detections, reports,
                             settings as settings_router, sources)

    missing = []
    for mod in (dashboard, sources, settings_router, detections, alerts, reports):
        for route in mod.router.routes:
            roles = None
            for p in inspect.signature(route.endpoint).parameters.values():
                dep = getattr(p.default, "dependency", None)
                roles = getattr(dep, "allowed_roles", None) or roles
            if roles is None:
                missing.append(f"{sorted(route.methods)} {route.path}")
    assert missing == [], f"routes without a role policy: {missing}"


def test_mutating_routes_exclude_viewer():
    """Every non-GET API route must be operator-only."""
    import inspect
    from app.routers import (alerts, dashboard, detections, reports,
                             settings as settings_router, sources)

    offenders = []
    for mod in (dashboard, sources, settings_router, detections, alerts, reports):
        for route in mod.router.routes:
            if route.methods <= {"GET", "HEAD", "OPTIONS"}:
                continue
            roles = None
            for p in inspect.signature(route.endpoint).parameters.values():
                dep = getattr(p.default, "dependency", None)
                roles = getattr(dep, "allowed_roles", None) or roles
            if roles is None or AdminRole.VIEWER in roles:
                offenders.append(f"{sorted(route.methods)} {route.path}")
    assert offenders == [], f"mutating routes reachable by VIEWER: {offenders}"


def test_role_sets_are_what_was_agreed():
    assert set(rbac.READ_ROLES) == {AdminRole.SUPER_ADMIN, AdminRole.ADMIN,
                                    AdminRole.VIEWER}
    assert set(rbac.OPERATOR_ROLES) == {AdminRole.SUPER_ADMIN, AdminRole.ADMIN}
    assert set(rbac.SUPER_ADMIN_ONLY) == {AdminRole.SUPER_ADMIN}


def test_authorisation_uses_the_database_row_not_the_token(operator):
    """A demotion must take effect immediately, not after the JWT expires.

    The token issued below carries role=ADMIN. Demoting the account in the
    database must cause the very next request to be refused, because
    get_current_admin re-reads the row and require_roles checks that.
    """
    c = _client(operator)
    try:
        assert c.post("/api/settings/scan").status_code == 200
        with SessionLocal() as db:
            row = db.get(Administrator, operator["admin_id"])
            row.role = AdminRole.VIEWER
            db.commit()
        assert c.post("/api/settings/scan").status_code == 403, \
            "stale JWT role was honoured after the account was demoted"
    finally:
        c.__exit__(None, None, None)


# --- the acknowledge verb -----------------------------------------------------

def test_acknowledge_is_patch_per_section_2_4(operator):
    """Section 2.4: "PATCH /api/detections/:id/acknowledge". It shipped as POST."""
    det = uuid.uuid4()
    c = _client(operator)
    try:
        # 404 (unknown id), not 405 — proves PATCH is routed.
        assert c.patch(f"/api/detections/{det}/acknowledge").status_code == 404
        assert c.post(f"/api/detections/{det}/acknowledge").status_code == 405
    finally:
        c.__exit__(None, None, None)
