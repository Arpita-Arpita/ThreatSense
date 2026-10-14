"""Process-local cache of alert_config rows (task 2.1, Section 2.5).

The proposal requires alert settings to be "loaded at application start-up and
refreshed after updates to reduce repeated database reads during detection
cycles". This module provides that cache.

Two processes use it and they behave differently:

  * The API process primes the cache at start-up (lifespan hook in main.py) and
    calls refresh() itself whenever an admin saves their settings, so it is
    always immediately correct.
  * The alert worker (task 2.3) runs as a SEPARATE process, so an in-memory
    refresh in the API cannot reach it. The worker therefore treats the cache as
    time-bounded: entries older than `alert_config_cache_ttl_seconds` are
    re-read from the database on next access. A settings change is picked up
    within that window without a per-detection query.

Not thread-safe by design intent, but the operations are simple dict
assignments, which are atomic under CPython, and a lost race only costs one
extra database read.
"""
from __future__ import annotations

import time as _time
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import settings
from ...models import AlertConfig

# admin_id -> (loaded_monotonic, AlertConfig)
_cache: dict[UUID, tuple[float, AlertConfig]] = {}
_primed_at: float | None = None


def _fresh(loaded_at: float) -> bool:
    return (_time.monotonic() - loaded_at) < settings.alert_config_cache_ttl_seconds


def _store(cfg: AlertConfig) -> AlertConfig:
    _cache[cfg.admin_id] = (_time.monotonic(), cfg)
    return cfg


def prime(session: Session) -> int:
    """Load every alert_config row. Called once at application start-up."""
    global _primed_at
    _cache.clear()
    rows = session.scalars(select(AlertConfig)).all()
    for row in rows:
        _store(row)
    _primed_at = _time.monotonic()
    return len(rows)


def refresh(session: Session, admin_id: UUID) -> AlertConfig | None:
    """Re-read one admin's config after an update. Returns None if deleted."""
    cfg = session.scalar(select(AlertConfig).where(AlertConfig.admin_id == admin_id))
    if cfg is None:
        _cache.pop(admin_id, None)
        return None
    return _store(cfg)


def get(session: Session, admin_id: UUID) -> AlertConfig | None:
    """Cached read for one admin, re-reading the row once the TTL has passed."""
    entry = _cache.get(admin_id)
    if entry is not None and _fresh(entry[0]):
        return entry[1]
    return refresh(session, admin_id)


def all_configs(session: Session) -> list[AlertConfig]:
    """Every config, used by the alert worker to fan a detection out to admins.

    Re-primes when the cache has never been loaded or has gone stale, so a
    long-running worker sees configuration changes without restarting.
    """
    stale = _primed_at is None or not _fresh(_primed_at)
    if stale:
        prime(session)
    return [cfg for _, cfg in _cache.values()]


def invalidate(admin_id: UUID | None = None) -> None:
    """Drop one entry, or the whole cache when admin_id is None."""
    global _primed_at
    if admin_id is None:
        _cache.clear()
        _primed_at = None
    else:
        _cache.pop(admin_id, None)


def size() -> int:
    return len(_cache)
