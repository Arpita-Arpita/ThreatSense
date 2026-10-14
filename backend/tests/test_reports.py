"""Integration tests for AI-assisted incident reports (task 3.2, UC 4.4).

Runs against real PostgreSQL with the mock LLM client, so the full path —
prompt building (minimum metadata, no raw logs), 15s-budget transport
failures, sanitisation, four-section validation, immutable storage, rate
limiting and audit rows — is exercised without an OpenAI account (task 3.1).

    cd backend && source .venv/bin/activate
    pytest tests/test_reports.py -v
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.security import hash_password
from app.database import SessionLocal
from app.main import app
from app.middleware.rate_limit import RateLimitExceeded, check_report_rate
from app.models import (
    AdminRole, Administrator, AuditAction, AuditLog, DataSource, Detection,
    IncidentReport, NetworkLog, SeverityLevel, SourceStatus, SourceType,
    ThreatType,
)
from app.services.reporting import generator
from app.services.reporting.generator import (
    ReportValidationError, generate_report, sanitise, split_sections,
)
from app.services.reporting.llm_client import (
    LLMAPIError, LLMTimeout, MockLLMClient, REPORT_SECTIONS,
)
from app.services.reporting.prompt import build_user_prompt, summarise_related_logs

PASSWORD = "TestPassw0rd!"


# --- fixtures ---------------------------------------------------------------

@pytest.fixture()
def env():
    """A throwaway admin + source + one CRITICAL detection with related logs."""
    email = f"report-{uuid.uuid4().hex[:8]}@threatsense.local"
    # Pinned to :50 within the minute, not the wall clock. The related-log
    # scope is the detection's own CALENDAR-MINUTE bucket, so a fixture that
    # placed the detection at an arbitrary second could put its own log
    # records in the preceding bucket whenever the suite happened to run near
    # the top of a minute — a test that passes or fails depending on the time
    # of day. Fixing the seconds makes the boundary explicit.
    now = datetime.now(timezone.utc).replace(second=50, microsecond=0)
    with SessionLocal() as db:
        admin = Administrator(full_name="Report Test", email=email,
                              password_hash=hash_password(PASSWORD),
                              role=AdminRole.ADMIN)
        db.add(admin)
        db.flush()
        source = DataSource(admin_id=admin.admin_id,
                            name=f"src-{uuid.uuid4().hex[:6]}",
                            type=SourceType.SYSLOG, status=SourceStatus.ACTIVE)
        db.add(source)
        db.flush()
        det = Detection(
            source_id=source.source_id, source_ip="203.0.113.50",
            destination_ip="192.168.1.20", timestamp=now, anomaly_score=0.93,
            severity=SeverityLevel.CRITICAL, threat_type=ThreatType.PORT_SCAN,
            model_version="IF_v1.0", model_type="IF",
            feature_vector={"distinct_ports": 0.91, "conn_rate": 0.84,
                            "syn_ratio": 0.77, "label": "should-be-skipped"},
        )
        db.add(det)
        db.flush()
        for i in range(6):
            db.add(NetworkLog(
                source_id=source.source_id, batch_id=uuid.uuid4(),
                src_ip="203.0.113.50", dst_ip="192.168.1.20",
                src_port=40000 + i, dst_port=20 + i, protocol="TCP",
                packet_size=60 + i,
                raw_message=f"SECRET-RAW-LINE-{i} user=jsmith",
                # Inside the detection's own one-minute window. These used to
                # be spread across six MINUTES, which only summarised into the
                # report because the related-log scope was fifteen minutes
                # wide while Algorithm 2 scores a single minute. The scope now
                # matches the detection (prompt.RELATED_LOG_WINDOW_MINUTES),
                # so the fixture places the traffic where traffic behind a real
                # detection actually is.
                timestamp=now - timedelta(seconds=5 + i * 5),
            ))
        db.commit()
        ids = {"admin_id": admin.admin_id, "email": email,
               "source_id": source.source_id, "detection_id": det.detection_id}
    yield ids
    with SessionLocal() as db:
        det_ids = db.scalars(select(Detection.detection_id)
                             .where(Detection.source_id == ids["source_id"])).all()
        if det_ids:
            db.query(IncidentReport).filter(
                IncidentReport.detection_id.in_(det_ids)).delete(
                synchronize_session=False)
        db.query(NetworkLog).filter(NetworkLog.source_id == ids["source_id"]).delete(
            synchronize_session=False)
        db.query(Detection).filter(Detection.source_id == ids["source_id"]).delete(
            synchronize_session=False)
        db.query(DataSource).filter(DataSource.source_id == ids["source_id"]).delete()
        db.query(AuditLog).filter(AuditLog.admin_id == ids["admin_id"]).delete()
        db.query(Administrator).filter(
            Administrator.admin_id == ids["admin_id"]).delete()
        db.commit()


@pytest.fixture()
def client(env):
    with TestClient(app) as c:
        r = c.post("/api/auth/login",
                   json={"email": env["email"], "password": PASSWORD})
        assert r.status_code == 200, r.text
        yield c


def _load(env):
    with SessionLocal() as db:
        det = db.get(Detection, env["detection_id"])
        admin = db.get(Administrator, env["admin_id"])
        return db, det, admin


def _audit_rows(admin_id, action):
    with SessionLocal() as db:
        return db.scalars(select(AuditLog).where(
            AuditLog.admin_id == admin_id, AuditLog.action == action)).all()


# --- prompt: minimum metadata only ------------------------------------------

def test_prompt_contains_required_metadata_and_no_raw_logs(env):
    db, det, admin = _load(env)
    with db:
        summary = summarise_related_logs(db, det)
        prompt = build_user_prompt(det, summary)
    assert "Port scan" in prompt and "PORT_SCAN" in prompt
    assert "0.93" in prompt and "CRITICAL" in prompt
    assert "203.0.113.50" in prompt and "192.168.1.20" in prompt
    assert "Protocol distribution" in prompt and "TCP: 6" in prompt
    assert "distinct_ports" in prompt and "conn_rate" in prompt
    # raw log lines and their contents must never reach the prompt
    assert "SECRET-RAW-LINE" not in prompt
    assert "jsmith" not in prompt
    # non-numeric feature values are skipped defensively
    assert "should-be-skipped" not in prompt


def test_related_log_summary_aggregates(env):
    db, det, _ = _load(env)
    with db:
        s = summarise_related_logs(db, det)
    assert s["events"] == 6
    assert s["protocols"] == {"TCP": 6}
    assert s["distinct_dst_ports"] == 6
    assert s["packet_size_bytes"]["min"] == 60
    assert s["packet_size_bytes"]["max"] == 65


# --- sanitisation + validation ----------------------------------------------

def test_sanitise_normalises_heading_variants_and_strips_markup():
    raw = ("```markdown\n**Executive Summary**\nAn event was detected on the "
           "network segment.\n\n1. Threat Details:\n<script>x</script>Suspicious "
           "scanning behaviour was observed here.\n\nRISK ASSESSMENT\nModerate "
           "risk to the exposed host if unaddressed.\n\n### Recommended Actions\n"
           "Investigate and acknowledge the alert promptly.\n```")
    text = sanitise(raw)
    sections = split_sections(text)
    assert list(sections) == list(REPORT_SECTIONS)
    assert "<script>" not in text and "```" not in text


def test_split_sections_rejects_missing_or_empty():
    with pytest.raises(ReportValidationError):
        split_sections("## Executive Summary\nOnly one section present here.")
    ok = "\n".join(f"## {s}\nBody long enough to pass validation." for s in REPORT_SECTIONS)
    assert split_sections(ok)
    with pytest.raises(ReportValidationError):
        split_sections(ok.replace("## Risk Assessment\nBody long enough to pass validation.",
                                  "## Risk Assessment\nshort"))


# --- generation happy path ---------------------------------------------------

def test_generate_stores_report_and_audits(env):
    db, det, admin = _load(env)
    mock = MockLLMClient()
    with db:
        report = generate_report(db, det, admin, client=mock)
        assert report.report_id is not None
        assert report.model_used == "mock-llm"
        assert report.token_count and report.token_count > 0
        sections = split_sections(report.report_text)
        assert list(sections) == list(REPORT_SECTIONS)
    # the prompt actually reached the client
    assert mock.calls and "Port scan" in mock.calls[0]["user"]
    rows = _audit_rows(env["admin_id"], AuditAction.REPORT_GENERATED)
    assert len(rows) == 1 and str(report.report_id) in rows[0].details


def test_regenerate_inserts_new_row_never_overwrites(env):
    db, det, admin = _load(env)
    with db:
        first = generate_report(db, det, admin, client=MockLLMClient())
        second = generate_report(db, det, admin, client=MockLLMClient())
        assert first.report_id != second.report_id
    with SessionLocal() as check:
        rows = check.scalars(select(IncidentReport).where(
            IncidentReport.detection_id == env["detection_id"])).all()
        assert len(rows) == 2
        assert check.get(IncidentReport, first.report_id).report_text  # intact


# --- failure paths: audit + retryable, never crash ---------------------------

@pytest.mark.parametrize("mock,kind,exc", [
    (MockLLMClient(fail_times=1), "api_error", LLMAPIError),
    (MockLLMClient(timeout_times=1), "timeout", LLMTimeout),
    (MockLLMClient(malformed_times=1), "validation", ReportValidationError),
])
def test_failures_audit_and_store_nothing(env, mock, kind, exc):
    db, det, admin = _load(env)
    with db:
        with pytest.raises(exc):
            generate_report(db, det, admin, client=mock)
    with SessionLocal() as check:
        assert check.scalar(select(IncidentReport).where(
            IncidentReport.detection_id == env["detection_id"])) is None
    rows = _audit_rows(env["admin_id"], AuditAction.REPORT_GENERATION_FAILED)
    assert len(rows) == 1 and kind in rows[0].details


# --- rate limiting -----------------------------------------------------------

def _insert_reports(env, n, minutes_ago=1):
    with SessionLocal() as db:
        for _ in range(n):
            db.add(IncidentReport(
                detection_id=env["detection_id"], generated_by=env["admin_id"],
                report_text="x" * 100, model_used="mock-llm",
                created_at=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
            ))
        db.commit()


def test_rate_limit_allows_under_10_blocks_at_10(env):
    _insert_reports(env, 9)
    with SessionLocal() as db:
        assert check_report_rate(db, env["admin_id"]) == 0  # 10th is allowed
    _insert_reports(env, 1)
    with SessionLocal() as db:
        with pytest.raises(RateLimitExceeded) as exc:
            check_report_rate(db, env["admin_id"])
        assert 0 < exc.value.retry_after_seconds <= 3600


def test_rate_limit_window_slides(env):
    _insert_reports(env, 10, minutes_ago=61)  # all outside the rolling hour
    with SessionLocal() as db:
        assert check_report_rate(db, env["admin_id"]) == 9


def test_failed_attempts_do_not_consume_quota(env):
    _insert_reports(env, 9)
    db, det, admin = _load(env)
    with db:
        with pytest.raises(LLMTimeout):
            generate_report(db, det, admin, client=MockLLMClient(timeout_times=1))
    # the failure stored no row, so the 10th successful attempt still fits
    with SessionLocal() as db:
        assert check_report_rate(db, env["admin_id"]) == 0


# --- API surface -------------------------------------------------------------

def test_api_generate_and_history(client, env):
    r = client.post(f"/api/detections/{env['detection_id']}/reports")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["detection_id"] == str(env["detection_id"])
    assert list(body["sections"]) == list(REPORT_SECTIONS)
    assert body["model_used"] == "mock-llm"

    r2 = client.post(f"/api/detections/{env['detection_id']}/reports")
    assert r2.status_code == 201
    hist = client.get(f"/api/detections/{env['detection_id']}/reports").json()
    assert hist["total"] == 2
    assert hist["items"][0]["report_id"] == r2.json()["report_id"]  # newest first

    one = client.get(f"/api/reports/{body['report_id']}")
    assert one.status_code == 200
    assert one.json()["report_id"] == body["report_id"]


def test_api_llm_failure_returns_retryable_502(client, env, monkeypatch):
    monkeypatch.setattr("app.routers.reports.generate_report",
                        lambda *a, **k: (_ for _ in ()).throw(LLMTimeout("boom")))
    r = client.post(f"/api/detections/{env['detection_id']}/reports")
    assert r.status_code == 502
    body = r.json()
    assert body["retryable"] is True and body["reason"] == "timeout"


def test_api_rate_limit_429_with_retry_after(client, env):
    _insert_reports(env, 10)
    r = client.post(f"/api/detections/{env['detection_id']}/reports")
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) > 0


def test_api_requires_auth_and_ownership(env):
    with TestClient(app) as anon:
        assert anon.post(
            f"/api/detections/{env['detection_id']}/reports").status_code == 401

    # a different admin must get 404, not another admin's detection
    other_email = f"other-{uuid.uuid4().hex[:8]}@threatsense.local"
    with SessionLocal() as db:
        other = Administrator(full_name="Other", email=other_email,
                              password_hash=hash_password(PASSWORD),
                              role=AdminRole.ADMIN)
        db.add(other)
        db.commit()
        other_id = other.admin_id
    try:
        with TestClient(app) as c:
            c.post("/api/auth/login",
                   json={"email": other_email, "password": PASSWORD})
            assert c.post(
                f"/api/detections/{env['detection_id']}/reports").status_code == 404
            assert c.get(
                f"/api/detections/{env['detection_id']}/reports").status_code == 404
    finally:
        with SessionLocal() as db:
            db.query(AuditLog).filter(AuditLog.admin_id == other_id).delete()
            db.query(Administrator).filter(
                Administrator.admin_id == other_id).delete()
            db.commit()
