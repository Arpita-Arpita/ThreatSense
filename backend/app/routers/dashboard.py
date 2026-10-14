"""Dashboard panel endpoints (Section 2.4, Algorithm 4, Figure 2c).

Section 2.4 names three routes:

    "RESTful API endpoints provide data for each panel through routes such as
     /api/dashboard/health, /api/dashboard/alerts, and /api/dashboard/analytics"

and Figure 2c draws the browser calling all three on dashboard load. The
functionality existed but was reachable only under /api/detections, so the
implemented route shape did not match the design. These endpoints close that
gap.

/alerts DELEGATES to detections.list_detections rather than re-querying, so a
detection cannot appear differently depending on which route asked for it —
ownership scoping, ordering and pagination stay defined in exactly one place.

/health and /analytics are not wrappers. They aggregate network_logs and
data_sources, which no existing endpoint did: the only traffic route was
per-detection (/api/detections/{id}/traffic).

Both aggregate over network_logs, which is the largest table in the schema, so
both are bounded — /health to a fixed one-hour window, /analytics to a caller
range capped at 24 hours. Section 2.7 lists the composite index on
(source_id, timestamp) that these rely on.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Interval, cast, func, select
from sqlalchemy.orm import Session

from ..core.source_status import is_effectively_active
from ..database import get_db
from ..models import (Administrator, DataSource, Detection, NetworkLog,
                      SourceStatus)

from ..routers.detections import list_detections
from ..schemas.dashboard import (DashboardAnalytics, DashboardHealth,
                                 TopTalker, TrafficPoint)
from ..schemas.detection import DetectionList
from ..middleware.rbac import require_operator, require_read

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

_HEALTH_WINDOW_SECONDS = 3600


def _owned_source_ids(db: Session, admin: Administrator):
    """Source IDs belonging to this admin.

    network_logs has no admin_id; ownership runs through data_sources, the
    same path _scoped() uses for detections.
    """
    return db.scalars(
        select(DataSource.source_id).where(DataSource.admin_id == admin.admin_id)
    ).all()


@router.get("/health", response_model=DashboardHealth)
def dashboard_health(db: Session = Depends(get_db),
                     admin: Administrator = Depends(require_read)) -> DashboardHealth:
    """Network Health panel.

    Section 2.4: "summary cards display total logs processed during the last
    hour, active data sources, current ingestion rate, and the number of
    unacknowledged alerts".

    Distinct from GET /health at the application root, which is the liveness
    probe NFR-06 measures against. This one is per-administrator and requires
    a session.
    """
    source_ids = _owned_source_ids(db, admin)
    if not source_ids:
        return DashboardHealth()

    since = datetime.now(timezone.utc) - timedelta(seconds=_HEALTH_WINDOW_SECONDS)
    logs_last_hour = db.scalar(
        select(func.count())
        .select_from(NetworkLog)
        .where(NetworkLog.source_id.in_(source_ids),
               NetworkLog.ingested_at >= since)
    ) or 0

    # Use Case 4.2's 60-second INACTIVE transition is applied at read time
    # (core/source_status.py), so this card cannot be a COUNT on the stored
    # status column — that would report a source as active long after it went
    # quiet, and would disagree with the Log Sources table on the same data.
    active_sources = sum(
        1 for src in db.scalars(
            select(DataSource).where(DataSource.admin_id == admin.admin_id)
        ) if is_effectively_active(src)
    )

    unacknowledged = db.scalar(
        select(func.count())
        .select_from(Detection)
        .where(Detection.source_id.in_(source_ids),
               Detection.is_acknowledged.is_(False))
    ) or 0

    return DashboardHealth(
        logs_last_hour=logs_last_hour,
        active_sources=active_sources,
        ingestion_rate_per_sec=round(logs_last_hour / _HEALTH_WINDOW_SECONDS, 3),
        unacknowledged_alerts=unacknowledged,
    )


@router.get("/alerts", response_model=DetectionList)
def dashboard_alerts(db: Session = Depends(get_db),
                     admin: Administrator = Depends(require_read),
                     limit: int = Query(50, ge=1, le=200),
                     offset: int = Query(0, ge=0)) -> DetectionList:
    """Alert Timeline panel.

    Delegates to the detections list handler. Deliberately not a second query:
    duplicating the ownership scoping and ordering would let the two routes
    drift, and a detection visible on one but not the other is the kind of
    inconsistency nobody notices until a demo.
    """
    # q is passed explicitly: list_detections gained a free-text search
    # parameter, and FastAPI's Query default is only applied when the
    # framework resolves the signature, not when we call it directly.
    return list_detections(db=db, admin=admin, q=None,
                           limit=limit, offset=offset)


@router.get("/analytics", response_model=DashboardAnalytics)
def dashboard_analytics(
    db: Session = Depends(get_db),
    admin: Administrator = Depends(require_read),
    hours: int = Query(1, ge=1, le=24),
    bucket_minutes: int = Query(5, ge=1, le=60),
) -> DashboardAnalytics:
    """Traffic Analytics panel.

    Section 2.4: "an interactive line chart displays traffic volume across
    selectable time ranges, supported by a protocol-distribution chart and a
    top-talkers bar chart". Algorithm 4: "AGGREGATE traffic volume, protocol
    distribution, top source IPs".

    'hours' is the selectable range and is capped at 24: this scans
    network_logs, and an uncapped range would let one dashboard load walk the
    entire table.
    """
    empty = DashboardAnalytics(range_hours=hours, bucket_minutes=bucket_minutes)
    source_ids = _owned_source_ids(db, admin)
    if not source_ids:
        return empty

    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    scoped = (NetworkLog.source_id.in_(source_ids), NetworkLog.timestamp >= since)

    # Volume: bucket by truncating to the requested interval. date_bin needs
    # PostgreSQL 14+; the project targets 16.
    bucket = func.date_bin(
        cast(f"{bucket_minutes} minutes", Interval), NetworkLog.timestamp, since)
    volume = [
        TrafficPoint(bucket=b, events=n)
        for b, n in db.execute(
            select(bucket.label("b"), func.count())
            .where(*scoped).group_by("b").order_by("b")
        )
    ]

    protocols = {
        str(p): n
        for p, n in db.execute(
            select(NetworkLog.protocol, func.count())
            .where(*scoped).group_by(NetworkLog.protocol)
        )
    }

    # host() rather than a plain cast: casting INET to text yields the CIDR
    # form ("10.9.9.10/32"), which would render as the label on every bar of
    # the top-talkers chart. host() returns the bare address.
    src_host = func.host(NetworkLog.src_ip)
    top_talkers = [
        TopTalker(src_ip=str(ip), events=n)
        for ip, n in db.execute(
            select(src_host.label("ip"), func.count().label("n"))
            .where(*scoped)
            .group_by(src_host)
            .order_by(func.count().desc())
            .limit(10)
        )
    ]

    return DashboardAnalytics(range_hours=hours, bucket_minutes=bucket_minutes,
                              volume=volume, protocols=protocols,
                              top_talkers=top_talkers)
