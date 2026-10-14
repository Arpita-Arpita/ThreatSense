"""Data-source schemas (task 1.8)."""
from __future__ import annotations

import ipaddress
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from ..models import SourceStatus, SourceType, TransportType


def _validate_ip(v: str | None) -> str | None:
    if v in (None, ""):
        return None
    try:
        ipaddress.ip_address(v)
    except ValueError as exc:
        raise ValueError("ip_address must be a valid IP address") from exc
    return v


class SourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    type: SourceType
    transport: TransportType | None = None
    ip_address: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    status: SourceStatus = SourceStatus.ACTIVE

    @field_validator("ip_address")
    @classmethod
    def _ip(cls, v):
        return _validate_ip(v)


class SourceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    type: SourceType | None = None
    transport: TransportType | None = None
    ip_address: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    status: SourceStatus | None = None

    @field_validator("ip_address")
    @classmethod
    def _ip(cls, v):
        return _validate_ip(v)


class SourceOut(BaseModel):
    source_id: UUID
    admin_id: UUID
    name: str
    type: SourceType
    transport: TransportType | None
    ip_address: str | None
    port: int | None
    status: SourceStatus
    last_received: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}

    @field_validator("ip_address", mode="before")
    @classmethod
    def _stringify_ip(cls, v):
        return str(v) if v is not None else None


class UploadResult(BaseModel):
    source_id: UUID
    batch_id: UUID
    parsed: int
    skipped: int
