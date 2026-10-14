"""Pydantic schemas for dashboard endpoints (Section 2.4, Algorithm 4).

Shapes follow the three panels named in Section 2.4:

    Network Health Panel   "summary cards display total logs processed during
                            the last hour, active data sources, current
                            ingestion rate, and the number of unacknowledged
                            alerts"
    Alert Timeline Panel   chronological detections (reuses DetectionList)
    Traffic Analytics      "traffic volume across selectable time ranges,
                            supported by a protocol-distribution chart and a
                            top-talkers bar chart"

Aggregates only. No raw_message and no log rows cross this boundary, matching
the reasoning already applied to TrafficSummary.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class DashboardHealth(BaseModel):
    """The four Network Health summary cards."""

    logs_last_hour: int = 0
    active_sources: int = 0
    # Derived from logs_last_hour, so it is an average over the hour rather
    # than an instantaneous rate. Section 2.4 says "current ingestion rate";
    # a true instantaneous figure would need a sampling window this schema
    # does not carry, and an hourly average is the honest reading of the
    # data actually available.
    ingestion_rate_per_sec: float = 0.0
    unacknowledged_alerts: int = 0


class TrafficPoint(BaseModel):
    """One bucket of the traffic-volume line chart."""

    bucket: datetime
    events: int


class TopTalker(BaseModel):
    """One bar of the top-talkers chart."""

    src_ip: str
    events: int


class DashboardAnalytics(BaseModel):
    """Traffic Analytics panel: volume over time, protocols, top talkers."""

    range_hours: int
    bucket_minutes: int
    volume: list[TrafficPoint] = []
    protocols: dict[str, int] = {}
    top_talkers: list[TopTalker] = []
