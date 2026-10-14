"""Tests for incident report PDF export (task 3.3, UC 4.4 / Figure 7).

Runs against real PostgreSQL. The HTML assembly is tested separately from the
WeasyPrint call, so a missing system library degrades to one skipped test
instead of hiding markup regressions.

    cd backend && source .venv/bin/activate
    pytest tests/test_report_pdf.py -v
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.security import hash_password
from app.database import SessionLocal
from app.main import app
from app.models import (
    AdminRole, Administrator, AuditAction, AuditLog, DataSource, Detection,
    IncidentReport, SeverityLevel, SourceStatus, SourceType, ThreatType,
)
from app.services.reporting import pdf as pdfmod
from app.services.reporting.llm_client import REPORT_SECTIONS

PASSWORD = "TestPassw0rd!"

REPORT_TEXT = """## Executive Summary
An anomalous network event was flagged and requires administrator attention.
This summary is written for a non-technical reader.

## Threat Details
The traffic pattern deviated from the learned baseline for this environment,
consistent with a **port scan** against internal hosts.

## Risk Assessment
If this activity is genuine rather than a false positive, the affected hosts
could be exposed to follow-up intrusion attempts.

## Recommended Actions
- Verify whether the source address is known and authorised.
- Restrict the source at the perimeter firewall if it is not.
- Review authentication logs on the destination host.
"""


def _make_env(threat=ThreatType.PORT_SCAN, severity=SeverityLevel.CRITICAL,
              report_text=REPORT_TEXT):
    """Admin + source + detection + one stored report. Returns plain ids."""
    email = f"pdf-{uuid.uuid4().hex[:8]}@threatsense.local"
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        admin = Administrator(full_name="Pdf Test", email=email,
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
            severity=severity, threat_type=threat,
            model_version="IF_v1.0", model_type="IF",
            feature_vector={"unique_dst_ports": 0.91, "syn_ratio": 0.77},
        )
        db.add(det)
        db.flush()
        report = IncidentReport(
            detection_id=det.detection_id, generated_by=admin.admin_id,
            report_text=report_text, model_used="mock-llm", token_count=210,
        )
        db.add(report)
        db.commit()
        return {"admin_id": admin.admin_id, "email": email,
                "source_id": source.source_id,
                "detection_id": det.detection_id,
                "report_id": report.report_id}


def _teardown(ids):
    with SessionLocal() as db:
        det_ids = db.scalars(select(Detection.detection_id)
                             .where(Detection.source_id == ids["source_id"])).all()
        if det_ids:
            db.query(IncidentReport).filter(
                IncidentReport.detection_id.in_(det_ids)).delete(
                synchronize_session=False)
        db.query(Detection).filter(
            Detection.source_id == ids["source_id"]).delete(synchronize_session=False)
        db.query(DataSource).filter(DataSource.source_id == ids["source_id"]).delete()
        db.query(AuditLog).filter(AuditLog.admin_id == ids["admin_id"]).delete()
        db.query(Administrator).filter(
            Administrator.admin_id == ids["admin_id"]).delete()
        db.commit()


@pytest.fixture()
def env():
    ids = _make_env()
    yield ids
    _teardown(ids)


@pytest.fixture()
def client(env):
    with TestClient(app) as c:
        r = c.post("/api/auth/login",
                   json={"email": env["email"], "password": PASSWORD})
        assert r.status_code == 200, r.text
        yield c


def _load(ids):
    db = SessionLocal()
    return (db,
            db.get(IncidentReport, ids["report_id"]),
            db.get(Detection, ids["detection_id"]))


# --- HTML assembly ----------------------------------------------------------

def test_html_contains_all_four_sections_and_detection_metadata(env):
    db, report, det = _load(env)
    try:
        html = pdfmod.build_html(report, det, "Pdf Test")
    finally:
        db.close()

    for title in REPORT_SECTIONS:
        assert f"<h2>{title}</h2>" in html
    # Figure 7 metadata must survive into the export
    assert "203.0.113.50" in html and "192.168.1.20" in html
    assert "0.93" in html
    assert "CRITICAL" in html
    assert "Port scan" in html
    assert "Isolation Forest (IF_v1.0)" in html
    assert str(det.detection_id) in html
    assert str(report.report_id) in html
    assert "mock-llm" in html          # provenance: which model wrote it
    assert "Open — not yet acknowledged" in html


def test_model_type_codes_render_as_readable_names():
    """Detections store the model as a code (IF or ISOLATION_FOREST); neither
    should reach a non-technical reader in raw form."""
    assert pdfmod.model_label("ISOLATION_FOREST") == "Isolation Forest"
    assert pdfmod.model_label("IF") == "Isolation Forest"
    # unknown future codes still degrade gracefully
    assert pdfmod.model_label("ONE_CLASS_SVM") == "One Class Svm"


def test_short_report_fits_on_a_single_page(env):
    """A four-section report of typical length must not spill a near-empty
    second page carrying only the provenance block."""
    from weasyprint import HTML
    db, report, det = _load(env)
    try:
        document = HTML(string=pdfmod.build_html(report, det),
                        base_url=None, url_fetcher=pdfmod._no_network).render()
    except Exception as exc:  # pragma: no cover - env dependent
        pytest.skip(f"WeasyPrint unavailable: {exc}")
    finally:
        db.close()
    assert len(document.pages) == 1


def test_sections_render_in_the_fixed_order(env):
    db, report, det = _load(env)
    try:
        html = pdfmod.build_html(report, det)
    finally:
        db.close()
    positions = [html.index(f"<h2>{t}</h2>") for t in REPORT_SECTIONS]
    assert positions == sorted(positions)


def test_bullet_lines_become_list_items(env):
    db, report, det = _load(env)
    try:
        html = pdfmod.build_html(report, det)
    finally:
        db.close()
    assert "<ul>" in html
    assert html.count("<li>") == 3
    assert "Verify whether the source address is known" in html


def test_markup_in_report_text_is_escaped_not_rendered():
    ids = _make_env(report_text=REPORT_TEXT.replace(
        "This summary is written for a non-technical reader.",
        'Injected <script>alert("x")</script> & <img src="http://evil.test/p">'))
    try:
        db, report, det = _load(ids)
        try:
            html = pdfmod.build_html(report, det)
        finally:
            db.close()
        assert "<script>" not in html
        assert "&lt;script&gt;" in html
        assert "<img" not in html
        assert "&amp;" in html
    finally:
        _teardown(ids)


def test_bold_markers_survive_as_strong(env):
    db, report, det = _load(env)
    try:
        html = pdfmod.build_html(report, det)
    finally:
        db.close()
    assert "<strong>port scan</strong>" in html
    assert "**" not in html.split("<h2>Risk Assessment</h2>")[0].split(
        "<h2>Threat Details</h2>")[-1]


def test_template_references_no_external_resources(env):
    """The renderer runs with a blocking URL fetcher, so any http(s) reference
    in the markup would raise at render time rather than fetch."""
    db, report, det = _load(env)
    try:
        html = pdfmod.build_html(report, det)
    finally:
        db.close()
    for marker in ("http://", "https://", "@import", "<link"):
        assert marker not in html, f"external resource reference: {marker}"

    with pytest.raises(ValueError):
        pdfmod._no_network("https://fonts.googleapis.com/css?family=Inter")


def test_unparseable_report_still_exports(env):
    """A row that does not split into four sections falls back to raw body
    rather than failing the export."""
    ids = _make_env(report_text="Just some text with no headings at all.")
    try:
        db, report, det = _load(ids)
        try:
            html = pdfmod.build_html(report, det)
        finally:
            db.close()
        assert "Just some text with no headings at all." in html
    finally:
        _teardown(ids)


def test_filename_is_descriptive_and_safe(env):
    db, report, det = _load(env)
    try:
        name = pdfmod.pdf_filename(report, det)
    finally:
        db.close()
    assert name.startswith("threatsense-incident-report-port_scan-")
    assert name.endswith(".pdf")
    assert '"' not in name and " " not in name and "/" not in name


# --- actual rendering -------------------------------------------------------

def test_render_produces_a_real_pdf(env):
    db, report, det = _load(env)
    try:
        blob = pdfmod.render_report_pdf(report, det, "Pdf Test")
    except pdfmod.PDFUnavailable as exc:  # pragma: no cover - env dependent
        pytest.skip(f"WeasyPrint unavailable: {exc}")
    finally:
        db.close()
    assert blob.startswith(b"%PDF-")
    assert blob.rstrip().endswith(b"%%EOF")
    assert len(blob) > 3000
    # Object streams are Flate-compressed, so page objects are not greppable
    # in the raw bytes — inspect the document tree instead.
    from weasyprint import HTML
    db2, report2, det2 = _load(env)
    try:
        document = HTML(string=pdfmod.build_html(report2, det2),
                        base_url=None, url_fetcher=pdfmod._no_network).render()
    finally:
        db2.close()
    assert len(document.pages) >= 1
    # WeasyPrint reports page geometry in CSS pixels at 96dpi, not points:
    # A4 is 210 x 297 mm -> 794 x 1123 px.
    width, height = document.pages[0].width, document.pages[0].height
    assert round(width) == 794 and round(height) == 1123, "expected A4 portrait"


# --- API --------------------------------------------------------------------

def test_api_export_returns_pdf_and_writes_export_audit(client, env):
    r = client.get(f"/api/reports/{env['report_id']}/pdf")
    if r.status_code == 503:  # pragma: no cover - env dependent
        pytest.skip("WeasyPrint unavailable in this environment")

    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf"
    disposition = r.headers["content-disposition"]
    assert disposition.startswith("attachment;")
    assert "threatsense-incident-report-port_scan-" in disposition
    assert r.content.startswith(b"%PDF-")
    assert int(r.headers["content-length"]) == len(r.content)

    with SessionLocal() as db:
        rows = db.scalars(select(AuditLog).where(
            AuditLog.admin_id == env["admin_id"],
            AuditLog.action == AuditAction.EXPORT)).all()
    assert len(rows) == 1
    assert str(env["report_id"]) in rows[0].details


def test_api_export_is_repeatable_and_not_rate_limited(client, env):
    """Export re-renders stored, immutable text and costs no LLM tokens, so
    the 10/hour report limit must not apply to it."""
    codes = [client.get(f"/api/reports/{env['report_id']}/pdf").status_code
             for _ in range(3)]
    if 503 in codes:  # pragma: no cover - env dependent
        pytest.skip("WeasyPrint unavailable in this environment")
    assert codes == [200, 200, 200]


def test_api_export_requires_authentication(env):
    with TestClient(app) as anon:
        r = anon.get(f"/api/reports/{env['report_id']}/pdf")
    assert r.status_code == 401


def test_api_export_404s_for_another_admins_report(client, env):
    other = _make_env()
    try:
        r = client.get(f"/api/reports/{other['report_id']}/pdf")
        assert r.status_code == 404
    finally:
        _teardown(other)


def test_api_export_404s_for_unknown_report(client):
    r = client.get(f"/api/reports/{uuid.uuid4()}/pdf")
    assert r.status_code == 404


def test_api_returns_503_when_renderer_unavailable(client, env, monkeypatch):
    def boom(*_a, **_k):
        raise pdfmod.PDFUnavailable("brew install pango")

    monkeypatch.setattr("app.routers.reports.render_report_pdf", boom)
    r = client.get(f"/api/reports/{env['report_id']}/pdf")
    assert r.status_code == 503
    assert "pango" in r.json()["detail"]

    with SessionLocal() as db:
        rows = db.scalars(select(AuditLog).where(
            AuditLog.admin_id == env["admin_id"],
            AuditLog.action == AuditAction.EXPORT)).all()
    assert rows == [], "a failed export must not write an EXPORT audit row"
