"""Detection settings, metrics and manual scan (task 4.2, Figure 8).

    cd backend && source .venv/bin/activate
    pytest tests/test_settings.py -v

The metrics tests write a temporary artefact into ml/metrics/ and remove it
again, so they cover the populated path without needing a trained model.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.security import hash_password
from app.database import SessionLocal
from app.main import app
from app.models import (
    AdminRole, Administrator, AuditAction, AuditLog, DetectionSettings,
)
from app.services.detection import metrics as metrics_service

PASSWORD = "TestPassw0rd!"
FAKE_VERSION = "TEST_v9.9"


def _make_admin():
    email = f"settings-{uuid.uuid4().hex[:8]}@threatsense.local"
    with SessionLocal() as db:
        admin = Administrator(full_name="Settings Test", email=email,
                              password_hash=hash_password(PASSWORD),
                              role=AdminRole.ADMIN)
        db.add(admin)
        db.commit()
        return {"admin_id": admin.admin_id, "email": email}


@pytest.fixture()
def admin():
    ids = _make_admin()
    # detection_settings is a single global row; snapshot it so a test that
    # changes settings cannot leak into the rest of the suite.
    with SessionLocal() as db:
        cfg = db.scalar(select(DetectionSettings))
        if cfg is None:
            cfg = DetectionSettings(sensitivity_threshold=0.75,
                                    active_model_version="IF_v1.0",
                                    detection_interval_seconds=60,
                                    updated_by=ids["admin_id"])
            db.add(cfg)
            db.commit()
        before = (float(cfg.sensitivity_threshold), cfg.active_model_version,
                  cfg.detection_interval_seconds, cfg.updated_by)
    yield ids
    with SessionLocal() as db:
        cfg = db.scalar(select(DetectionSettings))
        (cfg.sensitivity_threshold, cfg.active_model_version,
         cfg.detection_interval_seconds, cfg.updated_by) = before
        # detection_settings.updated_by has no ON DELETE, so the row must not
        # point at the admin we are about to remove. Re-attribute if it does.
        if cfg.updated_by == ids["admin_id"]:
            other = db.scalar(select(Administrator).where(
                Administrator.admin_id != ids["admin_id"]))
            if other is not None:
                cfg.updated_by = other.admin_id
            else:
                # Virgin database: this fixture created the settings row above
                # (that is the only way updated_by points at our own admin),
                # and no other administrator exists to re-attribute it to.
                # Deleting the row restores the pre-test state exactly, which
                # is what this fixture's snapshot/restore contract promises.
                # Without this branch the suite errors on its first run
                # against a schema-only database and passes on every run
                # after — so "N passed" was not reproducible from a clean
                # checkout.
                db.delete(cfg)
        db.flush()          # apply the restore BEFORE the deletes
        db.query(AuditLog).filter(AuditLog.admin_id == ids["admin_id"]).delete()
        db.query(Administrator).filter(
            Administrator.admin_id == ids["admin_id"]).delete()
        db.commit()


@pytest.fixture()
def client(admin):
    with TestClient(app) as c:
        r = c.post("/api/auth/login",
                   json={"email": admin["email"], "password": PASSWORD})
        assert r.status_code == 200, r.text
        yield c


@pytest.fixture()
def artefact(monkeypatch):
    """A metrics artefact whose numbers are unmistakably synthetic.

    The fake version must also look INSTALLED, otherwise update_settings
    rejects it with 422 and these tests silently exercise the real model
    instead. That made them pass on a machine with no trained model and fail
    on one with a model present — so the patch below is what keeps them
    deterministic, not a convenience.
    """
    monkeypatch.setattr(
        metrics_service, "available_versions",
        lambda: sorted(set(metrics_service.available_versions.__wrapped__()
                           if hasattr(metrics_service.available_versions, "__wrapped__")
                           else []) | {FAKE_VERSION, "IF_v1.0"}),
    )
    metrics_service.METRICS_DIR.mkdir(parents=True, exist_ok=True)
    path = metrics_service.METRICS_DIR / f"{FAKE_VERSION}.metrics.json"
    sweep = [{"threshold": round(t / 100, 2),
              "tp": 600 - t, "fp": t, "tn": 600 - t, "fn": t,
              "precision": round(0.50 + t / 300, 4),
              "recall": round(0.99 - t / 400, 4),
              "f1": round(0.60 + t / 500, 4)}
             for t in range(50, 100)]
    path.write_text(json.dumps({
        "model_version": FAKE_VERSION,
        "generated_at": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat(),
        "dataset": {"normal_windows": 600, "attack_windows": 600},
        "sweep": sweep,
        "recall_by_attack_kind": {
            "port_scan": {f"{t/100:.2f}": 0.95 for t in range(50, 100)},
            "ddos": {f"{t/100:.2f}": 0.88 for t in range(50, 100)},
        },
    }, indent=2), encoding="utf-8")
    metrics_service._cached.cache_clear()
    yield path
    path.unlink(missing_ok=True)
    metrics_service._cached.cache_clear()


# --- settings ---------------------------------------------------------------

def test_get_returns_the_single_settings_row(client):
    r = client.get("/api/settings")
    assert r.status_code == 200
    body = r.json()
    assert 0.50 <= body["sensitivity_threshold"] <= 0.99
    assert body["active_model_version"]
    assert body["detection_interval_seconds"] > 0


def test_update_persists_and_reports_who_changed_it(client):
    # Pick a value that differs from whatever is stored: an unchanged value
    # is a no-op by design and would not re-attribute updated_by.
    current = client.get("/api/settings").json()["sensitivity_threshold"]
    target = 0.80 if current != 0.80 else 0.85

    r = client.patch("/api/settings", json={"sensitivity_threshold": target})
    assert r.status_code == 200, r.text
    assert r.json()["sensitivity_threshold"] == target
    assert r.json()["updated_by_name"] == "Settings Test"
    assert client.get("/api/settings").json()["sensitivity_threshold"] == target


@pytest.mark.parametrize("value", [0.49, 0.999, 1.5, 0.0, -0.2])
def test_threshold_outside_the_allowed_band_is_rejected(client, value):
    """The band is 0.50-0.99 (ck_settings_threshold). The API must reject
    before Postgres does, so the admin gets a 422 rather than a 500."""
    r = client.patch("/api/settings", json={"sensitivity_threshold": value})
    assert r.status_code == 422


def test_interval_must_be_positive(client):
    assert client.patch("/api/settings",
                        json={"detection_interval_seconds": 0}).status_code == 422


def test_unknown_model_version_is_rejected_when_models_are_installed(client, monkeypatch):
    monkeypatch.setattr(metrics_service, "available_versions", lambda: ["IF_v1.0"])
    r = client.patch("/api/settings", json={"active_model_version": "IF_v9.9"})
    assert r.status_code == 422
    assert "not installed" in r.json()["detail"]


def test_change_is_audit_logged_with_before_and_after(client, admin):
    """The screen tells the admin changes are audit-logged. 'Changed
    sensitivity' would not be an audit trail; the values must be recorded."""
    current = client.get("/api/settings").json()["sensitivity_threshold"]
    assert current != 0.9, "fixture should not start at the target value"
    client.patch("/api/settings", json={"sensitivity_threshold": 0.9})
    with SessionLocal() as db:
        rows = db.scalars(select(AuditLog).where(
            AuditLog.admin_id == admin["admin_id"],
            AuditLog.action == AuditAction.CONFIG_CHANGE)).all()
    assert len(rows) == 1
    assert "sensitivity_threshold" in rows[0].details
    assert "0.9" in rows[0].details


def test_a_no_op_update_writes_no_audit_row(client, admin):
    current = client.get("/api/settings").json()["sensitivity_threshold"]
    r = client.patch("/api/settings", json={"sensitivity_threshold": current})
    assert r.status_code == 200
    with SessionLocal() as db:
        rows = db.scalars(select(AuditLog).where(
            AuditLog.admin_id == admin["admin_id"],
            AuditLog.action == AuditAction.CONFIG_CHANGE)).all()
    assert rows == [], "saving an unchanged value must not pollute the audit log"


def test_settings_require_authentication():
    with TestClient(app) as anon:
        assert anon.get("/api/settings").status_code == 401
        assert anon.patch("/api/settings", json={}).status_code == 401


# --- metrics ----------------------------------------------------------------

def test_metrics_report_unavailable_rather_than_inventing_numbers(client, monkeypatch):
    monkeypatch.setattr(metrics_service, "has_metrics", lambda v: False)
    monkeypatch.setattr(metrics_service, "_cached", lambda key: None)
    body = client.get("/api/settings/metrics").json()
    assert body["available"] is False
    assert body["at_threshold"] is None
    assert body["sweep"] == []
    assert "evaluate.py" in body["message"]


def test_metrics_are_served_for_the_configured_threshold(client, artefact):
    client.patch("/api/settings", json={"active_model_version": FAKE_VERSION})
    client.patch("/api/settings", json={"sensitivity_threshold": 0.75})
    body = client.get("/api/settings/metrics").json()
    assert body["available"] is True
    assert body["threshold"] == 0.75
    assert body["at_threshold"]["precision"] == pytest.approx(0.50 + 75 / 300, abs=1e-3)
    assert len(body["sweep"]) == 50
    assert body["stale_days"] == 3
    assert body["recall_by_attack_kind"]["port_scan"] == 0.95


def test_threshold_query_previews_without_saving(client, artefact):
    """The slider previews metrics before the admin commits the change."""
    client.patch("/api/settings", json={"active_model_version": FAKE_VERSION})
    client.patch("/api/settings", json={"sensitivity_threshold": 0.60})
    preview = client.get("/api/settings/metrics?threshold=0.9").json()
    assert preview["threshold"] == 0.90
    assert client.get("/api/settings").json()["sensitivity_threshold"] == 0.60


def test_regenerating_the_artefact_busts_the_cache(client, artefact):
    client.patch("/api/settings", json={"active_model_version": FAKE_VERSION})
    first = client.get("/api/settings/metrics").json()["at_threshold"]["f1"]

    data = json.loads(artefact.read_text())
    for row in data["sweep"]:
        row["f1"] = 0.1234
    artefact.write_text(json.dumps(data))
    # mtime is part of the cache key, so no manual clear here on purpose.
    import os, time as _t
    _t.sleep(0.01)
    os.utime(artefact, None)

    second = client.get("/api/settings/metrics").json()["at_threshold"]["f1"]
    assert first != second and second == 0.1234


def test_models_endpoint_lists_the_active_version(client):
    rows = client.get("/api/settings/models").json()
    assert rows, "the configured version must always appear"
    active = [r for r in rows if r["is_active"]]
    assert len(active) == 1
    assert set(rows[0]) == {"version", "is_active", "has_metrics"}


# --- manual scan ------------------------------------------------------------

def test_manual_scan_runs_the_engine_cycle_and_audits(client, admin, monkeypatch):
    """The endpoint must call the same run_cycle the scheduler uses, so a
    manual scan and a scheduled one cannot diverge."""
    calls = {}

    def fake_cycle(session):
        calls["ran"] = True
        return 42, 3, 60

    monkeypatch.setattr("app.services.detection.engine.run_cycle", fake_cycle)
    r = client.post("/api/settings/scan")
    assert r.status_code == 200, r.text
    body = r.json()
    assert calls.get("ran") is True
    assert body["logs_processed"] == 42
    assert body["detections_created"] == 3
    assert body["duration_ms"] >= 0

    with SessionLocal() as db:
        rows = db.scalars(select(AuditLog).where(
            AuditLog.admin_id == admin["admin_id"])).all()
    assert any("manual scan" in (r.details or "") for r in rows)


def test_missing_model_file_returns_an_actionable_503(client, monkeypatch):
    def boom(session):
        raise FileNotFoundError("ml/models/IF_v1.0.joblib")

    monkeypatch.setattr("app.services.detection.engine.run_cycle", boom)
    r = client.post("/api/settings/scan")
    assert r.status_code == 503
    assert "train.py" in r.json()["detail"]


def test_scan_requires_authentication():
    with TestClient(app) as anon:
        assert anon.post("/api/settings/scan").status_code == 401
