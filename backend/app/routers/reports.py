"""Incident report generate / history endpoints. Task 3.2 (UC 4.4).

Admin-scoped like the detections router: an admin can only generate or read
reports for detections whose data source they own. Regenerate is simply a
second POST — storage is insert-only, so history accumulates and the newest
report is the "current" one.

Status map (UC 4.4 + extensions):
    201  report generated and stored
    404  detection/report not found or not owned
    429  rate limit (10/admin/rolling hour) — Retry-After header set
    502  LLM API error, timeout, or unusable completion — body carries
         reason + retryable:true and the attempt does NOT consume quota
    503  PDF export only: WeasyPrint or its system libraries are unavailable

Task 3.3 added GET /api/reports/{report_id}/pdf (Export PDF, Figure 7).
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..middleware.rbac import require_operator, require_read
from ..middleware.rate_limit import RateLimitExceeded, check_report_rate
from ..models import (
    Administrator, AuditAction, AuditLog, DataSource, Detection, IncidentReport,
)
from ..schemas.report import (
    ReportGenerationFailed, ReportHistoryItem, ReportHistoryList, ReportList,
    ReportOut,
)
from ..services.reporting.generator import (
    ReportValidationError, generate_report, split_sections,
)
from ..services.reporting.llm_client import LLMError
from ..services.reporting.pdf import PDFUnavailable, pdf_filename, render_report_pdf

router = APIRouter(prefix="/api", tags=["reports"])


def _owned_detection(db: Session, detection_id: uuid.UUID,
                     admin: Administrator) -> Detection:
    det = db.scalar(
        select(Detection)
        .join(DataSource, Detection.source_id == DataSource.source_id)
        .where(DataSource.admin_id == admin.admin_id,
               Detection.detection_id == detection_id)
    )
    if det is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Detection not found")
    return det


def _owned_report(db: Session, report_id: uuid.UUID,
                  admin: Administrator) -> IncidentReport:
    """One report, or 404 — ownership runs through its detection's source."""
    report = db.scalar(
        select(IncidentReport)
        .join(Detection, IncidentReport.detection_id == Detection.detection_id)
        .join(DataSource, Detection.source_id == DataSource.source_id)
        .where(DataSource.admin_id == admin.admin_id,
               IncidentReport.report_id == report_id)
    )
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    return report


def _to_out(report: IncidentReport) -> ReportOut:
    out = ReportOut.model_validate(report)
    try:
        out.sections = split_sections(report.report_text)
    except ReportValidationError:  # pragma: no cover - stored reports are valid
        out.sections = {}
    return out


@router.post("/detections/{detection_id}/reports",
             response_model=ReportOut, status_code=status.HTTP_201_CREATED,
             responses={429: {"description": "Rate limit"},
                        502: {"model": ReportGenerationFailed}})
def create_report(detection_id: uuid.UUID, db: Session = Depends(get_db),
                  admin: Administrator = Depends(require_operator)):
    """Generate (or regenerate) the incident report for a detection."""
    det = _owned_detection(db, detection_id, admin)

    try:
        check_report_rate(db, admin.admin_id)
    except RateLimitExceeded as exc:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, str(exc),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        )

    try:
        report = generate_report(db, det, admin)
    except (LLMError, ReportValidationError) as exc:
        body = ReportGenerationFailed(
            detail=("The report could not be generated. This attempt does not "
                    "count against your report limit — you can retry now."),
            reason=getattr(exc, "kind", "api_error"),
        )
        return JSONResponse(status_code=status.HTTP_502_BAD_GATEWAY,
                            content=body.model_dump())

    return _to_out(report)


@router.get("/detections/{detection_id}/reports", response_model=ReportList)
def report_history(detection_id: uuid.UUID, db: Session = Depends(get_db),
                   admin: Administrator = Depends(require_read)) -> ReportList:
    """All reports ever generated for a detection, newest first."""
    det = _owned_detection(db, detection_id, admin)
    items = db.scalars(
        select(IncidentReport)
        .where(IncidentReport.detection_id == det.detection_id)
        .order_by(IncidentReport.created_at.desc())
    ).all()
    total = db.scalar(
        select(func.count()).select_from(IncidentReport)
        .where(IncidentReport.detection_id == det.detection_id)
    ) or 0
    return ReportList(items=[_to_out(r) for r in items], total=total)


@router.get("/reports", response_model=ReportHistoryList)
def all_reports(db: Session = Depends(get_db),
                admin: Administrator = Depends(require_read),
                limit: int = 100, offset: int = 0) -> ReportHistoryList:
    """Every incident report the signed-in administrator owns, newest first.

    Backs the Incident Reports navigation destination required by Section 2.1.
    The existing history endpoint is scoped to a single detection, so a
    top-level list had no way to answer "what has been generated across all my
    detections". Ownership runs through the same detection -> data_source ->
    admin_id join used everywhere else in this router, so an administrator
    cannot see another administrator's reports, and VIEWER may read (require_read)
    but cannot generate (create_report uses require_operator).
    """
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    joined = (
        select(IncidentReport, Detection)
        .join(Detection, IncidentReport.detection_id == Detection.detection_id)
        .join(DataSource, Detection.source_id == DataSource.source_id)
        .where(DataSource.admin_id == admin.admin_id)
    )
    rows = db.execute(
        joined.order_by(IncidentReport.created_at.desc())
        .limit(limit).offset(offset)
    ).all()
    total = db.scalar(
        select(func.count())
        .select_from(IncidentReport)
        .join(Detection, IncidentReport.detection_id == Detection.detection_id)
        .join(DataSource, Detection.source_id == DataSource.source_id)
        .where(DataSource.admin_id == admin.admin_id)
    ) or 0

    items = [
        ReportHistoryItem(
            report_id=report.report_id,
            detection_id=report.detection_id,
            created_at=report.created_at,
            model_used=report.model_used,
            token_count=report.token_count,
            threat_type=str(getattr(det.threat_type, "value", det.threat_type)),
            severity=str(getattr(det.severity, "value", det.severity)),
            source_ip=str(det.source_ip),
            detection_timestamp=det.timestamp,
        )
        for report, det in rows
    ]
    return ReportHistoryList(items=items, total=total)


@router.get("/reports/{report_id}", response_model=ReportOut)
def get_report(report_id: uuid.UUID, db: Session = Depends(get_db),
               admin: Administrator = Depends(require_read)):
    """One report by id (ownership enforced through its detection's source)."""
    return _to_out(_owned_report(db, report_id, admin))


@router.get("/reports/{report_id}/pdf",
            response_class=Response,
            responses={200: {"content": {"application/pdf": {}},
                             "description": "The rendered report"},
                       404: {"description": "Report not found"},
                       503: {"description": "PDF rendering unavailable"}})
def export_report_pdf(report_id: uuid.UUID, db: Session = Depends(get_db),
                      admin: Administrator = Depends(require_read)):
    """Export PDF (task 3.3, Use Case 4.4 / Figure 7).

    Rendered server-side so the file is identical whoever downloads it and
    whatever browser they use. Not rate limited: it costs no LLM tokens and
    re-renders an already-stored, immutable report.
    """
    report = _owned_report(db, report_id, admin)
    detection = db.get(Detection, report.detection_id)
    author = db.get(Administrator, report.generated_by)
    author_name = author.full_name if author else "ThreatSense administrator"

    try:
        pdf = render_report_pdf(report, detection, author_name)
    except PDFUnavailable as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))

    db.add(AuditLog(admin_id=admin.admin_id, action=AuditAction.EXPORT,
                    details=f"exported report {report.report_id} for "
                            f"detection {report.detection_id} as PDF"))
    db.commit()

    filename = pdf_filename(report, detection)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"',
                 "Content-Length": str(len(pdf))},
    )
