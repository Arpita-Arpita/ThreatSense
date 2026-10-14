"""ORM model: incident_reports table (Section 2.6). Immutable: regenerate = new row."""
from datetime import datetime
from uuid import UUID
from sqlalchemy import Integer, String, Text, ForeignKey, DateTime, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base


class IncidentReport(Base):
    __tablename__ = "incident_reports"

    report_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())
    detection_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("detections.detection_id", ondelete="CASCADE"), nullable=False)
    generated_by: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("administrators.admin_id"), nullable=False)
    report_text: Mapped[str] = mapped_column(Text, nullable=False)
    model_used: Mapped[str] = mapped_column(String(30), nullable=False)
    token_count: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    detection: Mapped["Detection"] = relationship(back_populates="incident_reports")
