"""Detection settings, model metrics and manual scan (task 4.2, Figure 8).

There is exactly one detection_settings row — it is global engine
configuration, not per-admin preference (alert_config is the per-admin one).
Every change is written to audit_logs as CONFIG_CHANGE, which is what the
screen's audit note refers to.

Manual scan calls the same run_cycle() the background engine calls, so a
scan triggered from the UI and a scheduled cycle cannot diverge.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..middleware.rbac import require_operator, require_read
from ..models import Administrator, AuditAction, AuditLog, DetectionSettings
from ..schemas.settings import (
    MetricsOut, ModelVersion, ScanResult, SettingsOut, SettingsUpdate,
)
from ..services.detection import metrics as metrics_service

router = APIRouter(prefix="/api/settings", tags=["settings"])


def _current(db: Session) -> DetectionSettings:
    cfg = db.scalar(select(DetectionSettings))
    if cfg is None:
        # Initial Setup creates this mandatory singleton.  If it is missing
        # later, the database is incomplete/corrupted; normal product users
        # must never be told to run the development seed script, which can
        # create sample data and historically could create another SUPER_ADMIN.
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Detection settings are not initialized. Restore the platform "
            "configuration before running detection.",
        )
    return cfg


def _out(db: Session, cfg: DetectionSettings) -> SettingsOut:
    who = db.get(Administrator, cfg.updated_by)
    data = SettingsOut.model_validate(cfg)
    data.updated_by_name = who.full_name if who else None
    return data


@router.get("", response_model=SettingsOut)
def get_settings(db: Session = Depends(get_db),
                 admin: Administrator = Depends(require_read)) -> SettingsOut:
    return _out(db, _current(db))


@router.patch("", response_model=SettingsOut)
def update_settings(payload: SettingsUpdate, db: Session = Depends(get_db),
                    admin: Administrator = Depends(require_operator)) -> SettingsOut:
    cfg = _current(db)
    changes = payload.model_dump(exclude_unset=True)

    if "active_model_version" in changes:
        version = changes["active_model_version"]
        installed = metrics_service.available_versions()
        # Accepting a version with no .joblib would leave the engine throwing
        # on every cycle, with nothing in the UI to explain why.
        if installed and version not in installed:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"Model '{version}' is not installed. Available: {', '.join(installed)}.",
            )

    # Record what actually changed — "changed sensitivity" is not an audit
    # trail; "0.75 -> 0.85" is.
    diffs = [f"{k} {getattr(cfg, k)} -> {v}"
             for k, v in changes.items() if getattr(cfg, k) != v]
    if not diffs:
        return _out(db, cfg)

    for key, value in changes.items():
        setattr(cfg, key, value)
    cfg.updated_by = admin.admin_id

    db.add(AuditLog(admin_id=admin.admin_id, action=AuditAction.CONFIG_CHANGE,
                    details="detection settings: " + "; ".join(diffs)))
    db.commit()
    db.refresh(cfg)
    return _out(db, cfg)


@router.get("/models", response_model=list[ModelVersion])
def list_models(db: Session = Depends(get_db),
                admin: Administrator = Depends(require_read)):
    """Model versions installed in ml/models, for the version selector."""
    cfg = _current(db)
    versions = metrics_service.available_versions()
    if cfg.active_model_version not in versions:
        # Surface the configured version even when its file is missing, so the
        # selector shows the truth rather than silently dropping it.
        versions.append(cfg.active_model_version)
    return [ModelVersion(version=v, is_active=v == cfg.active_model_version,
                         has_metrics=metrics_service.has_metrics(v))
            for v in sorted(set(versions))]


@router.get("/metrics", response_model=MetricsOut)
def get_metrics(threshold: float | None = None, db: Session = Depends(get_db),
                admin: Administrator = Depends(require_read)) -> MetricsOut:
    """Precision / recall / F1 from task 1.10's evaluation.

    `threshold` lets the screen preview the metrics for a slider position
    before the admin commits the change.
    """
    cfg = _current(db)
    at = threshold if threshold is not None else float(cfg.sensitivity_threshold)
    return MetricsOut(**metrics_service.metrics_for(cfg.active_model_version, at))


@router.post("/scan", response_model=ScanResult)
def manual_scan(db: Session = Depends(get_db),
                admin: Administrator = Depends(require_operator)) -> ScanResult:
    """Run one detection cycle now, over whatever is unanalysed.

    Same code path as the scheduled engine. Runs in FastAPI's threadpool
    because run_cycle is synchronous and can take a few seconds on a large
    backlog; the UI shows a progress indicator for exactly that reason.
    """
    cfg = _current(db)
    started = time.perf_counter()
    try:
        from ..services.detection.engine import run_cycle
        processed, created, _interval = run_cycle(db)
    except FileNotFoundError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"Model file for '{cfg.active_model_version}' is missing from ml/models. "
            f"Train it with `cd ml && python train.py`. ({exc})",
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the admin, not swallowed
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            f"Scan failed: {type(exc).__name__}: {exc}")

    elapsed = int((time.perf_counter() - started) * 1000)
    db.add(AuditLog(admin_id=admin.admin_id, action=AuditAction.CONFIG_CHANGE,
                    details=f"manual scan: {processed} logs analysed, "
                            f"{created} detections created in {elapsed}ms"))
    db.commit()
    return ScanResult(logs_processed=processed, detections_created=created,
                      duration_ms=elapsed,
                      threshold=float(cfg.sensitivity_threshold),
                      model_version=cfg.active_model_version)
