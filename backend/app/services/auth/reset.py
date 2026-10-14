"""
Password reset via a short-lived, server-side token store (task 1.5).

The proposal specifies: cryptographically random 256-bit tokens, stored as
SHA-256 hashes in a short-lived server-side token store, expiring after 15
minutes. The administrators table holds NO reset columns by design, so this
lives entirely in the service layer.

MVP NOTE — the store is an in-memory dict (single Uvicorn process). Pending
tokens are lost on restart and not shared across instances; acceptable for a
solo MVP where tokens live only 15 minutes. The endpoints depend only on
issue()/consume(), so swapping in a `password_reset_tokens` table or Redis
later is a contained change.

SECURITY TODO (production) — a completed reset does NOT invalidate existing
JWT sessions; they expire naturally within JWT_EXPIRY_MINUTES (60m). A
production build should force logout via password_changed_at / token_version /
a Redis blacklist / server-side session tracking.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import settings
from ...core.security import hash_password
from ...models import Administrator, AuditAction, AuditLog
from ..alerting.sender import get_sender

logger = logging.getLogger("threatsense.auth.reset")

TOKEN_TTL_MINUTES = 15


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


class ResetTokenStore:
    """In-memory store of {sha256(token): (admin_id, expiry)}."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[UUID, datetime]] = {}

    def _sweep(self, now: datetime) -> None:
        for h in [h for h, (_, exp) in self._store.items() if exp <= now]:
            self._store.pop(h, None)

    def issue(self, admin_id: UUID) -> str:
        """Generate a 256-bit token, store its hash + expiry, return the RAW token."""
        now = datetime.now(timezone.utc)
        self._sweep(now)
        raw = secrets.token_urlsafe(32)  # 32 bytes = 256 bits
        self._store[hash_token(raw)] = (admin_id, now + timedelta(minutes=TOKEN_TTL_MINUTES))
        return raw

    def consume(self, raw: str) -> UUID | None:
        """Return admin_id for a valid, unexpired token and remove it (single-use)."""
        now = datetime.now(timezone.utc)
        self._sweep(now)
        entry = self._store.pop(hash_token(raw), None)
        if entry is None:
            return None
        admin_id, exp = entry
        return admin_id if exp > now else None


# Module-level singleton.
reset_token_store = ResetTokenStore()


def request_reset(db: Session, email: str) -> str | None:
    """If the email matches an admin, issue a token and return the RAW token to email."""
    admin = db.scalar(select(Administrator).where(Administrator.email == email))
    if admin is None:
        return None
    return reset_token_store.issue(admin.admin_id)


def confirm_reset(db: Session, raw_token: str, new_password: str) -> bool:
    """Verify token, set new bcrypt password, clear lockout. Single-use."""
    admin_id = reset_token_store.consume(raw_token)
    if admin_id is None:
        return False
    admin = db.get(Administrator, admin_id)
    if admin is None:
        return False
    admin.password_hash = hash_password(new_password)
    admin.failed_attempts = 0  # reset doubles as lockout recovery
    db.add(AuditLog(admin_id=admin.admin_id, action=AuditAction.CONFIG_CHANGE, details="password reset"))
    db.commit()
    return True


_RESET_EMAIL = """<!DOCTYPE html><html><body style="font-family:-apple-system,Segoe UI,Arial,sans-serif;background:#f1f5f9;padding:24px;">
  <table role="presentation" width="100%" style="max-width:560px;margin:auto;background:#fff;border:1px solid #e2e8f0;border-radius:8px;">
    <tr><td style="background:#0f172a;padding:18px 22px;color:#fff;font-size:16px;font-weight:600;">ThreatSense &middot; Password Reset</td></tr>
    <tr><td style="padding:22px;color:#0f172a;font-size:14px;line-height:21px;">
      <p style="margin:0 0 12px;">A password reset was requested for this ThreatSense administrator account.</p>
      <p style="margin:0 0 18px;">This link can be used once and expires in {ttl} minutes.</p>
      <p style="margin:0 0 18px;"><a href="{link}" style="background:#2b54ff;color:#fff;text-decoration:none;padding:10px 18px;border-radius:6px;display:inline-block;">Reset password</a></p>
      <p style="margin:0;color:#64748b;font-size:12px;">If you did not request this, no action is needed — the link expires on its own and your current password still works.</p>
    </td></tr>
  </table></body></html>"""


def send_reset_link(recipient: str, raw_token: str) -> bool:
    """Email the reset link through the same sender the alerting module uses.

    SECURITY: the raw token and the assembled link are NEVER logged, at any
    level. They are a bearer credential for the account for TOKEN_TTL_MINUTES;
    anyone able to read application logs could complete the reset. An earlier
    build logged the full link at WARNING "so you can test locally", which put
    a live credential into every log sink the deployment had.

    That guarantee covers strings this function controls AND strings it does
    not. The failure branch deliberately logs no provider-supplied text,
    because the provider's exception message or response body is derived from
    a request whose body contained the link. See the comment there.

    Returns the delivery result for the caller's telemetry — the HTTP response
    stays generic either way, so that a failure cannot be used to probe which
    addresses have accounts.
    """
    link = f"{settings.frontend_origin}/reset-password?token={raw_token}"
    body = _RESET_EMAIL.replace("{link}", link).replace("{ttl}", str(TOKEN_TTL_MINUTES))
    sender = get_sender()
    result = sender.send(recipient, "[ThreatSense] Password reset", body)
    if result.success:
        logger.info("password reset link sent to %s", recipient)
    else:
        # Only fields this code controls. result.detail is NOT logged: it
        # carries the provider's exception text or raw response body, and the
        # request that produced it contained the reset link. An earlier
        # version logged it with a comment asserting it was token-free —
        # an assumption about a third party's error strings, which is not a
        # guarantee. The status code and sender name give the same
        # diagnostic value without depending on anyone else's behaviour.
        logger.warning(
            "password reset email delivery failed for %s (sender=%s, status=%s)",
            recipient, getattr(sender, "name", "unknown"),
            getattr(result, "status_code", None))
    return result.success
