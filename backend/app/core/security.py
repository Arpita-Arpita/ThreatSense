"""Password hashing + JWT helpers (task 1.4)."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from ..config import settings
from .password_policy import validate_password


def hash_password(plain: str) -> str:
    """Bcrypt-hash a password, enforcing NFR-11 first.

    Proposal Section 3, Table 11, NFR-11 — Measurement / Metric (verbatim):
        "Implementation: client-side regex validation on the registration
        form, and server-side validation immediately before bcrypt hashing."

    The check sits here, immediately before bcrypt.hashpw, rather than only in
    the request schema, because this is the single choke point every password
    passes through: the reset flow (services/auth/reset.py) and any future
    admin-creation endpoint both call it. A schema-only check would leave
    those paths able to store a non-compliant hash.

    Raises PasswordPolicyError (a ValueError) on a non-compliant password.
    """
    validate_password(plain)
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=settings.bcrypt_cost_factor)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except (ValueError, TypeError):
        return False


def create_access_token(admin_id, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(admin_id),
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_expiry_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
