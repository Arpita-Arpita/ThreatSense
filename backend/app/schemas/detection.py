"""Detection read + acknowledge schemas (task 1.14)."""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, field_validator

from ..models import SeverityLevel, ThreatType


class DetectionOut(BaseModel):
    detection_id: UUID
    source_id: UUID
    source_ip: str
    destination_ip: str
    timestamp: datetime
    anomaly_score: float
    severity: SeverityLevel
    threat_type: ThreatType
    model_version: str
    model_type: str
    feature_vector: dict
    is_acknowledged: bool
    acknowledged_by: UUID | None
    created_at: datetime

    model_config = {"from_attributes": True}

    @field_validator("source_ip", "destination_ip", mode="before")
    @classmethod
    def _stringify_ip(cls, v):
        return str(v) if v is not None else None


class DetectionList(BaseModel):
    items: list[DetectionOut]
    total: int
    limit: int
    offset: int


class DetectionStats(BaseModel):
    total: int
    unacknowledged: int
    last_24h: int
    by_severity: dict[str, int]
    by_threat_type: dict[str, int]


class TrafficSummary(BaseModel):
    """Aggregated traffic behind one detection (task 3.4, Figure 7).

    Same aggregate the report prompt builder uses, exposed for the Detection
    Detail screen's protocol distribution. Aggregates only — no log rows, no
    raw messages, so nothing here can leak a payload into the browser.
    """

    events: int = 0
    protocols: dict[str, int] = {}
    distinct_dst_ports: int = 0
    distinct_dst_ips: int = 0
    top_dst_ports: list[int] = []
    packet_size_bytes: dict[str, float] = {}
    # Width of the detection's calendar-minute bucket, not a rolling
    # look-back: the summary runs from the start of that minute to the
    # detection timestamp.
    window_minutes: int = 0
