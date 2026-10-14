"""Auth request/response schemas (task 1.4)."""
from datetime import datetime
from uuid import UUID
import re

from pydantic import BaseModel, field_validator


class LoginRequest(BaseModel):
    email: str
    password: str


class AdminOut(BaseModel):
    admin_id: UUID
    full_name: str
    email: str
    role: str
    # Surfaced so Account Settings can show it. The column already existed and
    # is updated on every successful login (Section 2.1); it simply was not
    # exposed, so the page rendered an empty field.
    last_login: datetime | None = None

    model_config = {"from_attributes": True}


class PasswordResetRequest(BaseModel):
    email: str


class PasswordResetConfirm(BaseModel):
    token: str
    # NFR-11 validation lives in routers/auth.py (readable message) and in
    # core/security.hash_password (immediately before bcrypt, per Table 11's
    # measurement column). A Field(min_length=8) here would fire FIRST and
    # emit Pydantic's array-shaped 422 body, which frontend/src/api/client.js
    # renders as "[object Object]" — the administrator would see nothing
    # useful. Length is checked with the other four classes instead.
    new_password: str


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class SetupRequest(BaseModel):
    """Initial administrator registration (Section 2.1, Figure 3).

    This endpoint is PUBLIC and creates the most privileged account in the
    platform, so the identity fields are validated here rather than relying
    on the browser. type="email" on the form is a convenience for the
    operator, not a boundary.

    The limits mirror Table 2 exactly — full_name VARCHAR(150), email
    VARCHAR(255). Without them an over-long value passes Pydantic and fails
    inside PostgreSQL, turning a user error into a 500.
    """

    full_name: str
    # Plain str rather than EmailStr: the project does not depend on
    # email-validator, so the shape is checked by the validator below.
    email: str
    # The real policy (NFR-11) is applied server-side by validate_password
    # immediately before bcrypt, so the caller gets the specific list of what
    # is missing rather than a bare length complaint.
    password: str

    @field_validator("full_name")
    @classmethod
    def _check_full_name(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            # "   " previously stripped to "" and was stored: NOT NULL does
            # not reject an empty string.
            raise ValueError("Full name is required.")
        if len(v) > 150:
            raise ValueError("Full name must be 150 characters or fewer.")
        return v

    @field_validator("email")
    @classmethod
    def _check_email(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if not v:
            raise ValueError("Email address is required.")
        if len(v) > 255:
            raise ValueError("Email address must be 255 characters or fewer.")
        # Deliberately minimal: one @, something either side, a dot in the
        # domain, no whitespace. Full RFC 5322 validation belongs in a
        # library, and over-strict patterns reject valid addresses.
        if not _EMAIL_RE.match(v):
            raise ValueError("Enter a valid email address.")
        return v


class SetupStatus(BaseModel):
    """Whether the system still needs its first administrator."""

    setup_required: bool


class PasswordChange(BaseModel):
    """Change your own password while signed in (Section 2.1, Account Settings).

    Requires the current password: without it, anyone who walks up to an
    unlocked screen could take the account over permanently.
    """

    current_password: str
    new_password: str
