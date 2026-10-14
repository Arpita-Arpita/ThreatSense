"""ORM model: detections table (Section 2.3)."""
from datetime import datetime
from uuid import UUID
from sqlalchemy import String, Boolean, Float, ForeignKey, DateTime, func, CheckConstraint
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base
from .enums import SeverityLevel, ThreatType


class Detection(Base):
    __tablename__ = "detections"
    __table_args__ = (CheckConstraint("anomaly_score BETWEEN 0 AND 1", name="ck_detections_score"),)

    detection_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())
    source_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("data_sources.source_id"), nullable=False)
    source_ip: Mapped[str] = mapped_column(INET, nullable=False)
    destination_ip: Mapped[str] = mapped_column(INET, nullable=False)
    timestamp: Mapped[datetime] = mapped_column("timestamp", DateTime(timezone=True), nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[SeverityLevel] = mapped_column(
        SQLEnum(SeverityLevel, name="severity_level", create_type=False,
                values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    threat_type: Mapped[ThreatType] = mapped_column(
        SQLEnum(ThreatType, name="threat_type", create_type=False,
                values_callable=lambda e: [m.value for m in e]),
        nullable=False, default=ThreatType.UNKNOWN_ANOMALY,
    )
    model_version: Mapped[str] = mapped_column(String(20), nullable=False)
    model_type: Mapped[str] = mapped_column(String(20), nullable=False)
    feature_vector: Mapped[dict] = mapped_column(JSONB, nullable=False)
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    acknowledged_by: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey("administrators.admin_id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    alerts: Mapped[list["Alert"]] = relationship(back_populates="detection")
    incident_reports: Mapped[list["IncidentReport"]] = relationship(back_populates="detection")
