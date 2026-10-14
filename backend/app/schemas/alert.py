"""Alert configuration schemas (task 2.1, Section 2.5).

One alert_config row per administrator (UNIQUE on admin_id). The MVP ships the
email channel only; the SMS fields exist in the schema as reserved space for the
planned enhancement, so they are accepted and stored but cannot be enabled.
"""
from __future__ import annotations

import re
from datetime import datetime, time
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator

from ..models import AlertSeverityThreshold

# Practical email check. Deliberately hand-rolled (like the IP validator in
# schemas/source.py) so Phase 2 does not add an email-validator dependency.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+(\.[^@\s.]+)+$")
# E.164: leading +, 8-15 digits, first digit non-zero.
_E164_RE = re.compile(r"^\+[1-9]\d{7,14}$")


def _clean_email(v: str | None) -> str | None:
    if v is None:
        return None
    v = v.strip().lower()
    if v == "":
        return None
    if len(v) > 255 or not _EMAIL_RE.match(v):
        raise ValueError("email_recipient must be a valid email address")
    return v


def _clean_phone(v: str | None) -> str | None:
    if v is None:
        return None
    v = v.strip().replace(" ", "")
    if v == "":
        return None
    if not _E164_RE.match(v):
        raise ValueError("sms_recipient must be in E.164 format, e.g. +61412345678")
    return v


class AlertConfigBase(BaseModel):
    """Shared field definitions and per-field validation."""

    email_enabled: bool = True
    sms_enabled: bool = False
    email_recipient: str | None = None
    sms_recipient: str | None = Field(default=None, max_length=20)
    severity_threshold: AlertSeverityThreshold = AlertSeverityThreshold.HIGH
    quiet_start: time | None = None
    quiet_end: time | None = None

    @field_validator("email_recipient")
    @classmethod
    def _email(cls, v):
        return _clean_email(v)

    @field_validator("sms_recipient")
    @classmethod
    def _phone(cls, v):
        return _clean_phone(v)


class AlertConfigReplace(AlertConfigBase):
    """PUT body — full replacement. Omitted fields fall back to the defaults above."""


class AlertConfigUpdate(BaseModel):
    """PATCH body — every field optional; only what is sent is changed."""

    email_enabled: bool | None = None
    sms_enabled: bool | None = None
    email_recipient: str | None = None
    sms_recipient: str | None = Field(default=None, max_length=20)
    severity_threshold: AlertSeverityThreshold | None = None
    quiet_start: time | None = None
    quiet_end: time | None = None

    @field_validator("email_recipient")
    @classmethod
    def _email(cls, v):
        return _clean_email(v)

    @field_validator("sms_recipient")
    @classmethod
    def _phone(cls, v):
        return _clean_phone(v)

    @model_validator(mode="after")
    def _not_empty(self):
        if not self.model_fields_set:
            raise ValueError("no fields supplied")
        return self


class AlertConfigOut(BaseModel):
    # Nullable because GET returns unsaved defaults when no row exists yet.
    # The GET used to CREATE the row, which is a write on a read route — fine
    # while every caller could write anyway, wrong once VIEWER is read-only.
    # null here means "these are defaults, nothing is persisted"; the row is
    # created by the first save.
    config_id: UUID | None = None
    admin_id: UUID
    email_enabled: bool
    sms_enabled: bool
    email_recipient: str | None
    sms_recipient: str | None
    severity_threshold: AlertSeverityThreshold
    quiet_start: time | None
    quiet_end: time | None
    updated_at: datetime | None = None

    model_config = {"from_attributes": True}


class TestAlertResult(BaseModel):
    """Outcome of the Send Test Alert control (Figure 6)."""

    delivered: bool
    channel: str
    recipient: str
    sender: str
    detail: str = ""
