"""ORM model: network_logs table (Section 2.2)."""
from datetime import datetime
from uuid import UUID
from sqlalchemy import BigInteger, Integer, String, Text, Boolean, ForeignKey, DateTime, func, CheckConstraint
from sqlalchemy.dialects.postgresql import INET, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base


class NetworkLog(Base):
    __tablename__ = "network_logs"
    __table_args__ = (
        CheckConstraint("src_port BETWEEN 0 AND 65535", name="ck_network_logs_src_port"),
        CheckConstraint("dst_port BETWEEN 0 AND 65535", name="ck_network_logs_dst_port"),
    )

    log_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("data_sources.source_id", ondelete="CASCADE"), nullable=False)
    batch_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    src_ip: Mapped[str] = mapped_column(INET, nullable=False)
    dst_ip: Mapped[str] = mapped_column(INET, nullable=False)
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False)
    packet_size: Mapped[int] = mapped_column(Integer, nullable=False)
    flags: Mapped[str | None] = mapped_column(String(20))
    connection_outcome: Mapped[str | None] = mapped_column(String(20))
    syslog_severity: Mapped[int | None] = mapped_column(Integer)
    raw_message: Mapped[str | None] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column("timestamp", DateTime(timezone=True), nullable=False)
    is_analysed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    source: Mapped["DataSource"] = relationship(back_populates="network_logs")
