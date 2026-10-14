"""ORM model: detection_settings table (Section 2.3)."""
from datetime import datetime
from uuid import UUID
from sqlalchemy import Integer, String, Float, ForeignKey, DateTime, func, CheckConstraint
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column
from .base import Base


class DetectionSettings(Base):
    __tablename__ = "detection_settings"
    __table_args__ = (
        CheckConstraint("sensitivity_threshold BETWEEN 0.50 AND 0.99", name="ck_settings_threshold"),
        CheckConstraint("detection_interval_seconds > 0", name="ck_settings_interval"),
    )

    settings_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())
    sensitivity_threshold: Mapped[float] = mapped_column(Float, nullable=False, default=0.75)
    active_model_version: Mapped[str] = mapped_column(String(20), nullable=False)
    detection_interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    updated_by: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("administrators.admin_id"), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
