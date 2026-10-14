"""Pydantic schemas for report endpoints (tasks 3.2-3.4, UC 4.4)."""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ReportOut(BaseModel):
    """One immutable incident report, with the four sections pre-split so the
    Figure 7 screen renders them directly."""

    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    report_id: UUID
    detection_id: UUID
    generated_by: UUID
    report_text: str
    sections: dict[str, str] = {}
    model_used: str
    token_count: int | None = None
    created_at: datetime


class ReportList(BaseModel):
    """Report history for one detection, newest first (Report History tab)."""

    items: list[ReportOut]
    total: int


class ReportGenerationFailed(BaseModel):
    """502 body when the LLM call or validation fails. retryable is always
    true — these attempts are not counted against the rate limit, so the UI
    should surface a Retry action (UC 4.4 extension)."""

    detail: str
    reason: str          # "timeout" | "api_error" | "validation"
    retryable: bool = True


class ReportHistoryItem(BaseModel):
    """One row of the Incident Reports screen.

    Carries the detection context the list needs (threat type, severity, the
    source IP) so the page renders from a single request instead of fetching
    each detection separately. report_text is deliberately NOT included: the
    list shows metadata, and the full text is one click away on the detection
    detail screen.
    """

    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    report_id: UUID
    detection_id: UUID
    created_at: datetime
    model_used: str
    token_count: int | None = None
    threat_type: str
    severity: str
    source_ip: str
    detection_timestamp: datetime


class ReportHistoryList(BaseModel):
    """Every report the signed-in administrator owns, newest first."""

    items: list[ReportHistoryItem]
    total: int
