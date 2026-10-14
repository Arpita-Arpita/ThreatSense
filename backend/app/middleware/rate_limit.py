"""Sliding-window rate limiting -> 429. Tasks 1.4, 3.2 (NFR-05).

Proposal Section 3, Table 11, NFR-05 — Requirement (verbatim):
    "Rate limiting: five login attempts per IP within a 15-minute window; ten
    report generations per administrator per hour. Exceeding limits returns
    HTTP 429."

Proposal Section 3, Table 11, NFR-05 — Measurement / Metric (verbatim):
    "Test scripts (automated) to send requests in rapid succession and check
    for HTTP 429 response at specified thresholds."

Two independent limiters, one per clause of the requirement.

LOGIN (first clause) — five attempts per IP per 15 minutes, in-process sliding
window. Section 3.1 of the proposal states the implementation approach as
"sliding-window middleware counters", which is what LoginRateLimiter is.

    Why not derive the window from audit_logs, the way the report limiter
    derives its window from incident_reports? Because audit_logs.admin_id is
    NOT NULL with an FK to administrators, so services/auth/service.py cannot
    write an audit row when the submitted email matches no account. Attempts
    against non-existent emails would therefore be invisible to a table-backed
    counter — and enumeration spray is exactly the attack this clause exists
    to throttle. The counter has to live somewhere that sees every attempt.

    MVP LIMIT: the counters are per-process, so running uvicorn with
    --workers N gives each worker its own window and the effective limit
    becomes 5*N per IP. Run a single worker for the NFR-05 evidence capture.
    Restarting the API clears the counters.

REPORTS (second clause) — 10 successful reports per admin per rolling hour.
The window is derived from the incident_reports table itself: a report
"counts" iff its row exists. That gives three properties for free:

  * failed attempts (API error, timeout, validation) never consume quota,
    because generator.py only INSERTs on success — exactly the Section 2.6
    requirement;
  * the limit survives API restarts (no in-memory counters to lose);
  * it is per-admin by construction (generated_by).

The per-account failed_attempts lockout on administrators (423 LOCKED, see
services/auth/service.py) is retained and is NOT part of NFR-05. It defends a
different attack surface — one attacker spreading attempts for a single
account across many IPs, which a per-IP window cannot see — and is documented
as defence-in-depth beyond the requirement.
"""
from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import IncidentReport


@dataclass
class LoginRateLimitExceeded(Exception):
    """Raised when an IP is over the NFR-05 login window.

    retry_after_seconds feeds the Retry-After header on the 429.
    """

    limit: int
    window_minutes: int
    retry_after_seconds: int

    def __str__(self) -> str:  # pragma: no cover - message formatting
        return (f"Too many login attempts: {self.limit} per "
                f"{self.window_minutes} minutes. Try again in "
                f"{self.retry_after_seconds}s.")


def _monotonic() -> float:
    """Indirection so tests can advance the clock without sleeping 15 minutes."""
    return time.monotonic()


class LoginRateLimiter:
    """Sliding-window counter of login attempts, keyed by client IP.

    NFR-05 says "five login attempts per IP within a 15-minute window", so
    EVERY attempt is counted, not only the failures. A successful login does
    not clear or reduce the window — the requirement makes no such exemption,
    and reading one in would be a silent divergence from Table 11.

    Practical consequence for the demo: six sign-ins from one IP inside 15
    minutes will 429 on the sixth. Restart the API to clear the counters, or
    raise LOGIN_RATE_LIMIT in .env temporarily — but capture the NFR-05
    evidence at the default 5/15, since that is the number being certified.
    """

    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, key: str, now: float) -> deque[float]:
        hits = self._hits[key]
        cutoff = now - self.window_seconds
        while hits and hits[0] <= cutoff:
            hits.popleft()
        return hits

    def check_and_record(self, key: str) -> int:
        """Register one attempt from `key`. Returns attempts remaining after it.

        Raises LoginRateLimitExceeded (without recording) once the window is
        full, so a client hammering the endpoint cannot push its own reset
        time further out with every rejected request.
        """
        now = _monotonic()
        hits = self._prune(key, now)

        if len(hits) >= self.limit:
            # The window frees a slot when its OLDEST hit ages out.
            retry_after = max(1, math.ceil(hits[0] + self.window_seconds - now))
            raise LoginRateLimitExceeded(
                self.limit, self.window_seconds // 60, retry_after)

        hits.append(now)
        return self.limit - len(hits)

    def reset(self, key: str | None = None) -> None:
        """Clear one key, or all of them. Used by tests and by app start-up."""
        if key is None:
            self._hits.clear()
        else:
            self._hits.pop(key, None)


# Module-level singleton — the window must be shared across requests.
login_rate_limiter = LoginRateLimiter(
    limit=settings.login_rate_limit,
    window_seconds=settings.login_rate_window_minutes * 60,
)


def check_login_rate(client_key: str) -> int:
    """Gate one login attempt from this client. See LoginRateLimiter."""
    return login_rate_limiter.check_and_record(client_key)


@dataclass
class RateLimitExceeded(Exception):
    """Raised when the caller is over quota. retry_after feeds the 429 header."""

    limit: int
    window_minutes: int
    retry_after_seconds: int

    def __str__(self) -> str:  # pragma: no cover - message formatting
        return (f"Report limit reached: {self.limit} per "
                f"{self.window_minutes} minutes. Try again in "
                f"{self.retry_after_seconds}s.")


def check_report_rate(db: Session, admin_id) -> int:
    """Gate one report-generation attempt for this admin.

    Returns the remaining quota (after the attempt now being made) or raises
    RateLimitExceeded with an accurate Retry-After: the moment the oldest of
    the last `limit` reports slides out of the rolling window.
    """
    limit = settings.report_rate_limit
    window = timedelta(minutes=settings.report_rate_window_minutes)
    now = datetime.now(timezone.utc)
    since = now - window

    in_window = db.scalars(
        select(IncidentReport.created_at)
        .where(IncidentReport.generated_by == admin_id,
               IncidentReport.created_at > since)
        .order_by(IncidentReport.created_at.desc())
        .limit(limit)
    ).all()

    if len(in_window) >= limit:
        oldest = in_window[-1]
        if oldest.tzinfo is None:  # defensive; column is TIMESTAMPTZ
            oldest = oldest.replace(tzinfo=timezone.utc)
        retry_after = max(1, math.ceil((oldest + window - now).total_seconds()))
        raise RateLimitExceeded(limit, settings.report_rate_window_minutes, retry_after)

    return limit - len(in_window) - 1
