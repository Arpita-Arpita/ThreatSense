"""ORM model: audit_logs table (Section 2.1)."""
from datetime import datetime
from uuid import UUID
from sqlalchemy import BigInteger, Text, ForeignKey, DateTime, func
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import INET, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base
from .enums import AuditAction


class AuditLog(Base):
    __tablename__ = "audit_logs"

    log_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    admin_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("administrators.admin_id"), nullable=False)
    action: Mapped[AuditAction] = mapped_column(
        SQLEnum(AuditAction, name="audit_action", create_type=False,
                values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    details: Mapped[str | None] = mapped_column(Text)
    ip_address: Mapped[str | None] = mapped_column(INET)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    admin: Mapped["Administrator"] = relationship(back_populates="audit_logs")
