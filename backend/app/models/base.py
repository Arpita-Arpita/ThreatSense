"""Declarative base for all ThreatSense ORM models (SQLAlchemy 2.0)."""
from datetime import datetime
from sqlalchemy import DateTime, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def utcnow_col() -> Mapped[datetime]:
    """Helper: a NOT NULL TIMESTAMPTZ column defaulting to now()."""
    return mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
