"""Effective source status (Use Case 4.2).

Use Case 4.2 requires a source to read ACTIVE while traffic is arriving and
INACTIVE once no valid message has been received for 60 seconds, returning to
ACTIVE on the next message.

The stored `data_sources.status` column records the last WRITE: the listener
sets it to ACTIVE on every flush that touched the source (see
services/ingestion/listener.py::IngestionService._write) and the upload path
does the same. Nothing ever set it back, so a source that had gone quiet still
read ACTIVE indefinitely.

This module supplies the missing half by deriving the status when it is READ,
from `last_received`, rather than by adding a background sweeper. Read-time
derivation was chosen deliberately:

  * it is deterministic — the answer depends only on last_received and the
    clock, not on when a sweeper last happened to run;
  * it cannot drift between screens, because Dashboard and Log Sources both
    call this one function;
  * it needs no new process, no scheduler and no extra failure mode, which
    matters two weeks from delivery.

ERROR is never overridden. An errored source is in a state an operator has to
resolve, and silently relabelling it INACTIVE because it also happens to be
quiet would hide the fault.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..config import settings
from ..models import SourceStatus


def effective_status(stored: SourceStatus, last_received: datetime | None,
                     now: datetime | None = None,
                     created_at: datetime | None = None) -> SourceStatus:
    """Return the status a caller should see for a source.

    Inputs:
        stored         the persisted data_sources.status value
        last_received  the persisted data_sources.last_received value, or None
                       when the source has never received a message
        now            injectable clock, for tests
        created_at     the persisted data_sources.created_at value, used as the
                       reference point before the first message arrives

    Output:
        SourceStatus — ERROR unchanged; INACTIVE when the source is not
        currently receiving; otherwise ACTIVE.
    """
    if stored == SourceStatus.ERROR:
        return SourceStatus.ERROR
    now = now or datetime.now(timezone.utc)
    if last_received is None:
        # Nothing received yet. Use Case 4.2 step 4 registers a source as
        # ACTIVE and step 5a turns it INACTIVE only after 60 seconds pass with
        # no messages, so a source that was just created must not read INACTIVE
        # the instant it appears in the table — the success screen shows a
        # green indicator. Counting from created_at gives exactly the
        # behaviour the use case describes, with the same 60-second rule.
        if created_at is None:
            return SourceStatus.INACTIVE
        last_received = created_at
    if last_received.tzinfo is None:                      # defensive: naive rows
        last_received = last_received.replace(tzinfo=timezone.utc)
    cutoff = timedelta(seconds=settings.source_inactive_after_seconds)
    # >= not >. Use Case 4.2 step 5a reads "if no messages arrive within 60
    # seconds", so sixty seconds of silence IS the transition, not the last
    # moment before it. 59.999s reads ACTIVE; 60.000s reads INACTIVE.
    if now - last_received >= cutoff:
        return SourceStatus.INACTIVE
    return SourceStatus.ACTIVE


def is_effectively_active(source, now: datetime | None = None) -> bool:
    """Convenience predicate for counting active sources."""
    return effective_status(
        source.status, source.last_received, now, source.created_at,
    ) == SourceStatus.ACTIVE
