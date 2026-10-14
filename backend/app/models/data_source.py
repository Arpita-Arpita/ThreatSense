"""ORM model: data_sources table (Section 2.2)."""
from datetime import datetime
from uuid import UUID
from sqlalchemy import (
    String, Integer, ForeignKey, DateTime, func, CheckConstraint, UniqueConstraint,
)
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import INET, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base
from .enums import SourceType, TransportType, SourceStatus


class DataSource(Base):
    __tablename__ = "data_sources"
    __table_args__ = (
        CheckConstraint("port BETWEEN 1 AND 65535", name="ck_data_sources_port"),
        # Names are how an admin tells collectors apart in the Log Sources
        # table (task 4.1) and in audit_logs, where only the name is recorded.
        # Two sources with the same name make both unreadable. Scoped per
        # admin, so separate admins can each have an "edge-firewall".
        UniqueConstraint("admin_id", "name", name="uq_data_sources_admin_name"),
    )

    source_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())
    admin_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("administrators.admin_id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    type: Mapped[SourceType] = mapped_column(
        SQLEnum(SourceType, name="source_type", create_type=False,
                values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    transport: Mapped[TransportType | None] = mapped_column(
        SQLEnum(TransportType, name="transport_type", create_type=False,
                values_callable=lambda e: [m.value for m in e]),
    )
    ip_address: Mapped[str | None] = mapped_column(INET)
    port: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[SourceStatus] = mapped_column(
        SQLEnum(SourceStatus, name="source_status", create_type=False,
                values_callable=lambda e: [m.value for m in e]),
        nullable=False, default=SourceStatus.ACTIVE,
    )
    last_received: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    admin: Mapped["Administrator"] = relationship(back_populates="data_sources")
    network_logs: Mapped[list["NetworkLog"]] = relationship(back_populates="source")
