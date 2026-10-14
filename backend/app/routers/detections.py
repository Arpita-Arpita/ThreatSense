"""Dashboard read APIs + acknowledge action for detections (task 1.14).

All endpoints are admin-scoped: an admin only sees detections whose source they
own (Detection -> DataSource.admin_id). Feeds the detections table, the
dashboard summary cards/charts, and the analyst acknowledge action.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..middleware.rbac import require_operator, require_read
from ..models import (
    Administrator, AuditAction, AuditLog, DataSource, Detection,
    SeverityLevel, ThreatType,
)
from ..schemas.detection import (
    DetectionList, DetectionOut, DetectionStats, TrafficSummary,
)
from ..services.reporting.prompt import summarise_related_logs

router = APIRouter(prefix="/api/detections", tags=["detections"])


def _scoped(admin: Administrator):
    """Base select for detections owned by this admin (via their sources)."""
    return (
        select(Detection)
        .join(DataSource, Detection.source_id == DataSource.source_id)
        .where(DataSource.admin_id == admin.admin_id)
    )


def _owned(db: Session, detection_id: uuid.UUID, admin: Administrator) -> Detection:
    det = db.scalar(_scoped(admin).where(Detection.detection_id == detection_id))
    if det is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Detection not found")
    return det


@router.get("", response_model=DetectionList)
def list_detections(
    db: Session = Depends(get_db),
    admin: Administrator = Depends(require_read),
    severity: SeverityLevel | None = None,
    threat_type: ThreatType | None = None,
    acknowledged: bool | None = None,
    source_id: uuid.UUID | None = None,
    q: str | None = Query(None, max_length=100,
                          description="Free-text match on source IP, destination IP or threat type"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> DetectionList:
    stmt = _scoped(admin)
    if severity is not None:
        stmt = stmt.where(Detection.severity == severity)
    if threat_type is not None:
        stmt = stmt.where(Detection.threat_type == threat_type)
    if acknowledged is not None:
        stmt = stmt.where(Detection.is_acknowledged.is_(acknowledged))
    if source_id is not None:
        stmt = stmt.where(Detection.source_id == source_id)
    if q:
        # Server-side so the whole history is searched, not just the page the
        # client happens to be holding. Filtering on the client after paging
        # can report "no matches" while a match sits on another page, and it
        # leaves the total — and therefore the page count — describing the
        # unfiltered set.
        #
        # host() casts INET to text without the /32 suffix that str() adds, so
        # a search for "10.0.0.5" matches rather than needing "10.0.0.5/32".
        needle = f"%{q.strip().lower()}%"
        stmt = stmt.where(or_(
            func.lower(func.host(Detection.source_ip)).like(needle),
            func.lower(func.host(Detection.destination_ip)).like(needle),
            func.lower(cast(Detection.threat_type, String)).like(needle),
            func.lower(cast(Detection.severity, String)).like(needle),
        ))

    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    items = db.scalars(
        stmt.order_by(Detection.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return DetectionList(items=items, total=total or 0, limit=limit, offset=offset)


@router.get("/stats", response_model=DetectionStats)
def detection_stats(db: Session = Depends(get_db),
                    admin: Administrator = Depends(require_read)) -> DetectionStats:
    base = _scoped(admin).subquery()
    total = db.scalar(select(func.count()).select_from(base)) or 0
    unack = db.scalar(
        select(func.count()).select_from(base).where(base.c.is_acknowledged.is_(False))
    ) or 0
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    last_24h = db.scalar(
        select(func.count()).select_from(base).where(base.c.created_at >= since)
    ) or 0

    by_sev = {s.value: 0 for s in SeverityLevel}
    for sev, n in db.execute(
        select(base.c.severity, func.count()).select_from(base).group_by(base.c.severity)
    ):
        by_sev[sev.value if hasattr(sev, "value") else str(sev)] = n

    by_type = {t.value: 0 for t in ThreatType}
    for tt, n in db.execute(
        select(base.c.threat_type, func.count()).select_from(base).group_by(base.c.threat_type)
    ):
        by_type[tt.value if hasattr(tt, "value") else str(tt)] = n

    return DetectionStats(total=total, unacknowledged=unack, last_24h=last_24h,
                          by_severity=by_sev, by_threat_type=by_type)


@router.get("/{detection_id}", response_model=DetectionOut)
def get_detection(detection_id: uuid.UUID, db: Session = Depends(get_db),
                  admin: Administrator = Depends(require_read)) -> Detection:
    return _owned(db, detection_id, admin)


@router.get("/{detection_id}/traffic", response_model=TrafficSummary)
def detection_traffic(detection_id: uuid.UUID, db: Session = Depends(get_db),
                      admin: Administrator = Depends(require_read)) -> TrafficSummary:
    """Protocol distribution and volume behind a detection (Figure 7).

    Reuses the report prompt's aggregate query so the screen and the AI report
    describe the same traffic — one definition, no drift. Returns zeroed
    fields when no matching logs remain (e.g. an injected test detection).
    """
    det = _owned(db, detection_id, admin)
    return TrafficSummary(**summarise_related_logs(db, det))


# PATCH, not POST. Section 2.4 names the endpoint literally:
#   "The acknowledge endpoint, PATCH /api/detections/:id/acknowledge, updates
#    is_acknowledged and logs the action in audit_logs"
# and Figure 2c draws the same verb. It shipped as POST; PATCH is also the
# correct verb for a partial state change on an existing resource.
@router.patch("/{detection_id}/acknowledge", response_model=DetectionOut)
def acknowledge_detection(detection_id: uuid.UUID, db: Session = Depends(get_db),
                          admin: Administrator = Depends(require_operator)) -> Detection:
    det = _owned(db, detection_id, admin)
    if not det.is_acknowledged:
        det.is_acknowledged = True
        det.acknowledged_by = admin.admin_id
        db.add(AuditLog(admin_id=admin.admin_id, action=AuditAction.ACKNOWLEDGE,
                        details=f"acknowledged detection {detection_id}"))
        db.commit()
        db.refresh(det)
    return det
