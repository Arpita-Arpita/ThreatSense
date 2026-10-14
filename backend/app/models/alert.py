"""ORM model: alerts table (Section 2.5). Single status field PENDING/SENT/FAILED."""
from datetime import datetime
from uuid import UUID
from sqlalchemy import Integer, String, Text, ForeignKey, DateTime, func
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base
from .enums import AlertChannel, AlertStatus


class Alert(Base):
    __tablename__ = "alerts"

    alert_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())
    detection_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("detections.detection_id", ondelete="CASCADE"), nullable=False)
    channel: Mapped[AlertChannel] = mapped_column(
        SQLEnum(AlertChannel, name="alert_channel", create_type=False,
                values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    recipient: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[AlertStatus] = mapped_column(
        SQLEnum(AlertStatus, name="alert_status", create_type=False,
                values_callable=lambda e: [m.value for m in e]),
        nullable=False, default=AlertStatus.PENDING,
    )
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .detection import Detection
