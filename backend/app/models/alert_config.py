"""ORM model: alert_config table (Section 2.5). One row per admin (UNIQUE)."""
from datetime import datetime, time
from uuid import UUID
from sqlalchemy import String, Boolean, ForeignKey, DateTime, Time, func
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base
from .enums import AlertSeverityThreshold


class AlertConfig(Base):
    __tablename__ = "alert_config"

    config_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())
    admin_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("administrators.admin_id", ondelete="CASCADE"), nullable=False, unique=True)
    email_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    sms_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    email_recipient: Mapped[str | None] = mapped_column(String(255))
    sms_recipient: Mapped[str | None] = mapped_column(String(20))
    severity_threshold: Mapped[AlertSeverityThreshold] = mapped_column(
        SQLEnum(AlertSeverityThreshold, name="alert_severity_threshold", create_type=False,
                values_callable=lambda e: [m.value for m in e]),
        nullable=False, default=AlertSeverityThreshold.HIGH,
    )
    quiet_start: Mapped[time | None] = mapped_column(Time)
    quiet_end: Mapped[time | None] = mapped_column(Time)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    admin: Mapped["Administrator"] = relationship(back_populates="alert_config")
