"""Authentication service: verify, lockout, last_login, audit (task 1.4)."""
from __future__ import annotations
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import settings
from ...core.security import create_access_token, verify_password
from ...models import Administrator, AuditAction, AuditLog

logger = logging.getLogger("threatsense.auth")


class AuthError(Exception):
    ...


class InvalidCredentials(AuthError):
    ...


class AccountLocked(AuthError):
    """Raised while an account is inside its lockout window.

    Carries the seconds remaining so the caller can tell the administrator
    when to come back, matching how NFR-05's 429 reports Retry-After.
    """

    def __init__(self, retry_after_seconds: int = 0) -> None:
        super().__init__()
        self.retry_after_seconds = retry_after_seconds


_FAILED_LOGIN_DETAIL = "login failed"


def _seconds_left_in_lockout(db: Session, admin: Administrator) -> int:
    """Seconds remaining before a locked account unlocks; 0 if it has expired.

    The lockout clock is the timestamp of the most recent failed-login
    audit entry. audit_logs is written on every failed attempt already
    (Section 2.1), so no column is added to administrators — Table 2 of the
    proposal defines that table's fields exactly, and this avoids deviating
    from it.

    If no failed-login entry survives (audit pruning), the lockout is treated
    as expired. That is deliberately fail-open: the alternative is an account
    locked forever with no record of why, which is the defect being fixed.
    The per-IP throttle in NFR-05 still applies underneath, so an attacker
    gains no free attempts from this.
    """
    window = timedelta(minutes=settings.account_lockout_minutes)
    last_failure = db.scalar(
        select(AuditLog.created_at)
        .where(AuditLog.admin_id == admin.admin_id,
               AuditLog.action == AuditAction.LOGIN,
               AuditLog.details == _FAILED_LOGIN_DETAIL)
        .order_by(AuditLog.created_at.desc())
        .limit(1)
    )
    if last_failure is None:
        logger.warning(
            "admin %s has failed_attempts=%d but no failed-login audit entry; "
            "treating the lockout as expired",
            admin.admin_id, admin.failed_attempts)
        return 0
    if last_failure.tzinfo is None:
        last_failure = last_failure.replace(tzinfo=timezone.utc)
    remaining = (last_failure + window) - datetime.now(timezone.utc)
    return max(0, int(remaining.total_seconds()))


def _audit(db: Session, admin_id, detail: str, ip: str | None) -> None:
    db.add(AuditLog(admin_id=admin_id, action=AuditAction.LOGIN, details=detail, ip_address=ip))


def authenticate(db: Session, email: str, password: str, ip: str | None = None) -> tuple[Administrator, str]:
    admin = db.scalar(select(Administrator).where(Administrator.email == email))
    # Uniform error to avoid user enumeration.
    if admin is None:
        raise InvalidCredentials()

    if admin.failed_attempts >= settings.max_failed_attempts:
        seconds_left = _seconds_left_in_lockout(db, admin)
        if seconds_left > 0:
            raise AccountLocked(retry_after_seconds=seconds_left)
        # Window has elapsed: clear the counter and let this attempt proceed
        # normally. Cleared here rather than by a scheduled job so that no
        # background process is required for an account to recover.
        admin.failed_attempts = 0
        db.commit()

    if not verify_password(password, admin.password_hash):
        admin.failed_attempts += 1
        _audit(db, admin.admin_id, "login failed", ip)
        db.commit()
        raise InvalidCredentials()

    # success: reset lockout counter, stamp last_login, audit, issue token
    admin.failed_attempts = 0
    admin.last_login = datetime.now(timezone.utc)
    _audit(db, admin.admin_id, "login success", ip)
    db.commit()
    token = create_access_token(admin.admin_id, admin.role.value)
    return admin, token
