"""ORM model: administrators table (Section 2.1)."""
from datetime import datetime
from uuid import UUID
from sqlalchemy import Boolean, String, Integer, DateTime, func
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base
from .enums import AdminRole


class Administrator(Base):
    __tablename__ = "administrators"

    admin_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())
    full_name: Mapped[str] = mapped_column(String(150), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[AdminRole] = mapped_column(
        SQLEnum(AdminRole, name="admin_role", create_type=False,
                values_callable=lambda e: [m.value for m in e]),
        nullable=False, default=AdminRole.ADMIN,
    )
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    # TRUE only for the account created by POST /api/auth/setup. A partial
    # unique index (db/migrations/002_single_initial_admin.sql) allows at most
    # one TRUE row, so a concurrent second setup request fails in the database
    # rather than relying on a count-then-insert check that two requests can
    # both pass. Not in the proposal's Table 2; declared as a deviation.
    is_initial_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="admin")
    data_sources: Mapped[list["DataSource"]] = relationship(back_populates="admin")
    alert_config: Mapped["AlertConfig | None"] = relationship(back_populates="admin", uselist=False)
