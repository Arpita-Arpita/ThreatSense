"""Alert configuration API (task 2.1, Section 2.5, Figure 6).

One row per administrator, enforced by the UNIQUE constraint on
alert_config.admin_id. Each admin reads and writes only their own row, matching
the ownership model used by sources.py and detections.py.

    GET    /api/alert-config    read-only (returns unsaved defaults if no row)
    PUT    /api/alert-config    full replace
    PATCH  /api/alert-config    partial update
    DELETE /api/alert-config    reset — removes the row; next save recreates it

Every write refreshes the cached settings and records a CONFIG_CHANGE audit row.
POST /api/alert-config/test is the "Send Test Alert" control from Figure 6.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import get_db
from ..middleware.rbac import require_operator, require_read
from ..models import (
    Administrator, AlertConfig, AlertSeverityThreshold, AuditAction, AuditLog,
)
from ..schemas.alert import (
    AlertConfigOut, AlertConfigReplace, AlertConfigUpdate, TestAlertResult,
)
from ..services.alerting import config_cache
from ..services.alerting.sender import get_sender

router = APIRouter(prefix="/api/alert-config", tags=["alert-config"])

_EDITABLE = (
    "email_enabled", "sms_enabled", "email_recipient", "sms_recipient",
    "severity_threshold", "quiet_start", "quiet_end",
)


def _load(db: Session, admin: Administrator) -> AlertConfig | None:
    return db.scalar(select(AlertConfig).where(AlertConfig.admin_id == admin.admin_id))


def _create_default(db: Session, admin: Administrator) -> AlertConfig:
    """First-WRITE default: email on, addressed to the admin's own login email.

    Called by the write routes only. GET stopped calling this when it became
    read-only, so a row now appears on the first save rather than the first
    page view.

    The UNIQUE constraint on admin_id is the authority — if a concurrent request
    wins the race, fall back to reading the row it created.
    """
    cfg = AlertConfig(
        admin_id=admin.admin_id,
        email_enabled=True,
        sms_enabled=False,
        email_recipient=admin.email,
        severity_threshold=AlertSeverityThreshold.HIGH,
    )
    db.add(cfg)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = _load(db, admin)
        if existing is None:
            raise
        return existing
    db.refresh(cfg)
    return cfg


def _validate(cfg: AlertConfig) -> None:
    """Validate the MERGED state, not just the submitted fields.

    This has to run after the changes are applied: a PATCH that only flips
    email_enabled to true is invalid if the stored recipient is empty, and no
    amount of per-field validation on the payload would catch that.
    """
    if cfg.email_enabled and not cfg.email_recipient:
        raise HTTPException(
            422,
            "email_recipient is required when email_enabled is true",
        )
    if cfg.sms_enabled:
        raise HTTPException(
            422,
            "SMS alerting is a planned enhancement and cannot be enabled yet",
        )
    if (cfg.quiet_start is None) != (cfg.quiet_end is None):
        raise HTTPException(
            422,
            "quiet_start and quiet_end must be set together, or both left empty",
        )
    if cfg.quiet_start is not None and cfg.quiet_start == cfg.quiet_end:
        raise HTTPException(
            422,
            "quiet_start and quiet_end must differ (a zero-length quiet period "
            "has no effect; clear both fields to disable quiet hours)",
        )


def _apply(db: Session, admin: Administrator, cfg: AlertConfig,
           values: dict) -> AlertConfig:
    """Apply changes, validate the result, audit what actually changed, cache it."""
    changed: list[str] = []
    for field in _EDITABLE:
        if field not in values:
            continue
        new = values[field]
        if getattr(cfg, field) != new:
            setattr(cfg, field, new)
            changed.append(field)

    try:
        _validate(cfg)
    except HTTPException:
        db.rollback()  # discard the rejected in-memory changes
        raise

    if not changed:
        return cfg  # no-op save; nothing to audit

    # The model has no onupdate hook, so stamp updated_at here.
    cfg.updated_at = datetime.now(timezone.utc)
    db.add(AuditLog(
        admin_id=admin.admin_id,
        action=AuditAction.CONFIG_CHANGE,
        details=f"update alert_config ({', '.join(sorted(changed))})",
    ))
    db.commit()
    db.refresh(cfg)
    config_cache.refresh(db, admin.admin_id)
    return cfg


@router.get("", response_model=AlertConfigOut)
def get_alert_config(db: Session = Depends(get_db),
                     admin: Administrator = Depends(require_read)) -> AlertConfig:
    """Return this admin's settings, or unsaved defaults if none exist yet.

    This GET used to CREATE the row on first access, which is a write on a
    read route. Harmless while every caller could write anyway; not harmless
    once VIEWER exists, because "read-only" would still be inserting rows.

    The defaults are now built in memory and not added to the session, so the
    screen renders identically and the row is created by the first PUT/PATCH
    that actually saves something — which is where creation belonged.
    """
    cfg = _load(db, admin)
    if cfg is not None:
        return cfg
    # Same field values as _create_default, so the screen renders identically
    # whether or not the row has been saved yet. Not added to the session.
    return AlertConfig(
        admin_id=admin.admin_id,
        email_enabled=True,
        sms_enabled=False,
        email_recipient=admin.email,
        severity_threshold=AlertSeverityThreshold.HIGH,
    )


@router.put("", response_model=AlertConfigOut)
def replace_alert_config(payload: AlertConfigReplace, db: Session = Depends(get_db),
                         admin: Administrator = Depends(require_operator)) -> AlertConfig:
    """Full replace — the shape the Alert Configuration screen submits (task 2.4)."""
    cfg = _load(db, admin) or _create_default(db, admin)
    return _apply(db, admin, cfg, payload.model_dump())


@router.patch("", response_model=AlertConfigOut)
def update_alert_config(payload: AlertConfigUpdate, db: Session = Depends(get_db),
                        admin: Administrator = Depends(require_operator)) -> AlertConfig:
    """Partial update — e.g. flipping the email toggle on its own."""
    cfg = _load(db, admin) or _create_default(db, admin)
    return _apply(db, admin, cfg, payload.model_dump(exclude_unset=True))


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
def delete_alert_config(db: Session = Depends(get_db),
                        admin: Administrator = Depends(require_operator)) -> None:
    """Reset to defaults by removing the row.

    The next GET renders unsaved defaults; it no longer recreates the row —
    the row comes back on the next save. See get_alert_config.
    """
    cfg = _load(db, admin)
    if cfg is None:
        return
    db.delete(cfg)
    db.add(AuditLog(admin_id=admin.admin_id, action=AuditAction.CONFIG_CHANGE,
                    details="reset alert_config to defaults"))
    db.commit()
    config_cache.invalidate(admin.admin_id)


@router.post("/test", response_model=TestAlertResult)
def send_test_alert(db: Session = Depends(get_db),
                    admin: Administrator = Depends(require_operator)) -> TestAlertResult:
    """Send a sample notification to the configured recipient (Figure 6).

    Deliberately creates neither a detection nor an alerts row: this proves the
    delivery path works without polluting the detection history or the audit
    trail of genuine outbound alerts (Section 2.5).
    """
    cfg = _load(db, admin) or _create_default(db, admin)
    if not cfg.email_enabled or not cfg.email_recipient:
        raise HTTPException(
            422, "Enable email notifications and set a recipient before sending a test")

    sender = get_sender()
    result = sender.send(
        cfg.email_recipient,
        "[ThreatSense] Test alert",
        _TEST_BODY.replace("{recipient}", cfg.email_recipient)
                  .replace("{threshold}", cfg.severity_threshold.value),
    )
    return TestAlertResult(
        delivered=result.success,
        channel="EMAIL",
        recipient=cfg.email_recipient,
        sender=sender.name,
        detail=result.detail,
    )


_TEST_BODY = """<!DOCTYPE html><html><body style="font-family:-apple-system,Segoe UI,Arial,sans-serif;background:#f1f5f9;padding:24px;">
  <table role="presentation" width="100%" style="max-width:560px;margin:auto;background:#fff;border:1px solid #e2e8f0;border-radius:8px;">
    <tr><td style="background:#0f172a;padding:18px 22px;color:#fff;font-size:16px;font-weight:600;">ThreatSense &middot; Test Alert</td></tr>
    <tr><td style="padding:22px;color:#0f172a;font-size:14px;line-height:21px;">
      <p style="margin:0 0 12px;">This is a test notification confirming that alert delivery is configured correctly.</p>
      <p style="margin:0 0 12px;">Alerts will be delivered to <strong>{recipient}</strong> at severity <strong>{threshold}</strong> and above.</p>
      <p style="margin:0;color:#64748b;font-size:12px;">No detection record was created for this message.</p>
    </td></tr>
  </table></body></html>"""
