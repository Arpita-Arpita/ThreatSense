"""Detection settings, model metrics and manual-scan schemas (task 4.2)."""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class SettingsOut(BaseModel):
    settings_id: UUID
    sensitivity_threshold: float
    active_model_version: str
    detection_interval_seconds: int
    updated_by: UUID
    updated_by_name: str | None = None
    updated_at: datetime

    model_config = {"from_attributes": True}


class SettingsUpdate(BaseModel):
    # Bounds mirror ck_settings_threshold so the API rejects out-of-range
    # values with a 422 before Postgres rejects them with a 500.
    sensitivity_threshold: float | None = Field(default=None, ge=0.50, le=0.99)
    active_model_version: str | None = Field(default=None, min_length=1, max_length=20)
    detection_interval_seconds: int | None = Field(default=None, ge=1, le=86400)


class ModelVersion(BaseModel):
    version: str
    is_active: bool
    has_metrics: bool


class MetricPoint(BaseModel):
    threshold: float
    precision: float
    recall: float
    f1: float
    tp: int
    fp: int
    tn: int
    fn: int


class MetricsOut(BaseModel):
    """Evaluation metrics for the active model at the configured threshold.

    `available` is false when the artefact has not been generated — the screen
    shows the command to run rather than inventing numbers.
    """

    available: bool
    model_version: str | None = None
    generated_at: datetime | None = None
    stale_days: int | None = None
    threshold: float | None = None
    at_threshold: MetricPoint | None = None
    sweep: list[MetricPoint] = []
    recall_by_attack_kind: dict[str, float] = {}
    dataset: dict[str, object] = {}
    message: str | None = None


class ScanResult(BaseModel):
    logs_processed: int
    detections_created: int
    duration_ms: int
    threshold: float
    model_version: str
