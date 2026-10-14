"""Account-management schemas (Section 2.1)."""
from __future__ import annotations

import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, field_validator

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AccountOut(BaseModel):
    """An administrator account as shown in the management list."""

    admin_id: UUID
    full_name: str
    email: str
    role: str
    last_login: datetime | None = None
    created_at: datetime | None = None

    model_config = {"from_attributes": True}


class AccountCreate(BaseModel):
    """A new ADMIN or VIEWER account created by a SUPER_ADMIN.

    SUPER_ADMIN is not an allowed value. Creating another account with full
    privileges is an escalation that should be a deliberate act, not a
    dropdown option, and Section 2.1 does not ask for it.
    """

    full_name: str
    email: str
    password: str
    role: str

    @field_validator("full_name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("Full name is required.")
        if len(v) > 150:
            raise ValueError("Full name must be 150 characters or fewer.")
        return v

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if not v:
            raise ValueError("Email address is required.")
        if len(v) > 255:
            raise ValueError("Email address must be 255 characters or fewer.")
        if not _EMAIL_RE.match(v):
            raise ValueError("Enter a valid email address.")
        return v

    @field_validator("role")
    @classmethod
    def _role(cls, v: str) -> str:
        v = (v or "").strip().upper()
        if v not in {"ADMIN", "VIEWER"}:
            raise ValueError("Role must be either ADMIN or VIEWER.")
        return v
