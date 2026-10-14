"""Ingestion drop counters surfaced on /health (Phase 6 optional item).

    cd backend && source .venv/bin/activate
    pytest tests/test_ingestion_stats.py -v

WHY THIS EXISTS
---------------
The listener process counts two kinds of rejected traffic — messages from an
unregistered sender IP, and messages the parser cannot read — and logs both
once per flush cycle. Until now the only way to see them was to be watching
the listener's stdout at the moment it printed. A misconfigured sender IP
therefore produced silent, total data loss, which cost two complete NFR-01
runs during Phase 6.1 before anyone noticed.

This is NOT a Table 11 clause. It is operational telemetry: NFR-06 measures
availability from server access logs, and "the API answered 200" is a weaker
claim than "the API answered 200 and logs were actually arriving". The
counters let a reader tell those apart.

The listener and the API are separate processes, so the counters travel
through a file. The three states below are the ones a reader must be able to
distinguish, and conflating any two of them is the failure this file guards:

    unknown  no stats file at all — the listener has never run. Critically,
             this is NOT the same as a zero drop count.
    stale    file present but old — counters are last-known, not current.
    up       file fresh — counters are current.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app


@pytest.fixture()
def stats_file(tmp_path, monkeypatch):
    """Point the app at a throwaway stats path for the duration of a test."""
    path = tmp_path / "ingestion_stats.json"
    monkeypatch.setattr(settings, "ingestion_stats_path", str(path))
    return path


def _write(path, *, age_seconds: float = 0.0, **overrides):
    updated = datetime.now(timezone.utc) - timedelta(seconds=age_seconds)
    payload = {
        "listener_started_at": (updated - timedelta(minutes=5)).isoformat(),
        "updated_at": updated.isoformat(),
        "ingested_total": 1001,
        "dropped_total": 4,
        "dropped_unknown_source_total": 0,
        "dropped_unparseable_total": 4,
        "buffered_now": 0,
    }
    payload.update(overrides)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return payload


def _health(client):
    r = client.get("/health")
    assert r.status_code == 200, r.text
    return r.json()


# --- the endpoint still does what it did before -----------------------------

def test_health_still_reports_status_and_database(stats_file):
    """The pre-existing contract must not change; this block is additive."""
    with TestClient(app) as c:
        body = _health(c)
    assert body["status"] == "ok"
    assert body["database"] == "up"
    assert "env" in body


def test_health_is_200_when_no_stats_file_exists(stats_file):
    """Missing telemetry must never turn a healthy API into a failure."""
    assert not stats_file.exists()
    with TestClient(app) as c:
        body = _health(c)
    assert body["status"] == "ok"


# --- the three listener states ----------------------------------------------

def test_absent_stats_file_reports_unknown_not_zero(stats_file):
    """No file means "we do not know", which is not the same as "no drops".

    Reporting 0 here would be a lie that reads as good news — precisely the
    silent-loss failure this telemetry exists to prevent.
    """
    with TestClient(app) as c:
        ingestion = _health(c)["ingestion"]
    assert ingestion["listener"] == "unknown"
    assert "dropped_total" not in ingestion


def test_fresh_stats_file_reports_up_with_counters(stats_file):
    written = _write(stats_file, age_seconds=1.0)
    with TestClient(app) as c:
        ingestion = _health(c)["ingestion"]
    assert ingestion["listener"] == "up"
    assert ingestion["ingested_total"] == written["ingested_total"]
    assert ingestion["dropped_total"] == written["dropped_total"]
    assert ingestion["dropped_unparseable_total"] == 4
    assert ingestion["dropped_unknown_source_total"] == 0


def test_old_stats_file_reports_stale(stats_file):
    _write(stats_file, age_seconds=settings.ingestion_stats_stale_seconds + 30)
    with TestClient(app) as c:
        ingestion = _health(c)["ingestion"]
    assert ingestion["listener"] == "stale"
    # Counters are still returned — a last-known value is useful, provided
    # the caller can see that it is last-known.
    assert ingestion["ingested_total"] == 1001


def test_staleness_boundary_is_inclusive(stats_file):
    """A listener flushing exactly at the threshold must not read as stale."""
    _write(stats_file, age_seconds=settings.ingestion_stats_stale_seconds - 1)
    with TestClient(app) as c:
        assert _health(c)["ingestion"]["listener"] == "up"


def test_stale_threshold_exceeds_flush_interval(stats_file):
    """Guard the config relationship, not the code.

    The listener writes once per flush cycle. If the stale threshold were
    ever set below syslog_flush_seconds, a perfectly healthy listener would
    report stale on every read.
    """
    assert settings.ingestion_stats_stale_seconds > settings.syslog_flush_seconds


# --- malformed input --------------------------------------------------------

def test_unreadable_stats_file_reports_unknown_not_500(stats_file):
    stats_file.write_text("{ this is not json", encoding="utf-8")
    with TestClient(app) as c:
        body = _health(c)
    assert body["status"] == "ok"
    assert body["ingestion"]["listener"] == "unknown"


def test_stats_file_missing_timestamp_reports_unknown(stats_file):
    stats_file.write_text(json.dumps({"ingested_total": 5}), encoding="utf-8")
    with TestClient(app) as c:
        assert _health(c)["ingestion"]["listener"] == "unknown"


def test_naive_timestamp_is_treated_as_utc(stats_file):
    """Defensive: a hand-edited file without an offset must not crash."""
    naive = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    _write(stats_file, updated_at=naive)
    with TestClient(app) as c:
        assert _health(c)["ingestion"]["listener"] == "up"


# --- writer/reader round trip ------------------------------------------------

def test_listener_written_file_is_readable_by_health(stats_file, monkeypatch):
    """The listener writes it and /health reads it — assert they agree.

    Testing the two halves separately would pass even if the writer emitted
    "dropped" and the reader looked for "dropped_total". Only the round trip
    catches a key-name drift between two files that are edited months apart.
    """
    from app.services.ingestion.listener import IngestionService

    monkeypatch.setattr(settings, "ingestion_stats_path", str(stats_file))

    class _NullSession:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def scalars(self, *a, **k):
            class _R:
                def all(self_inner): return []
            return _R()

    service = IngestionService(lambda: _NullSession())
    service.total_ingested = 1001
    service.total_dropped_unparseable = 4
    service.total_dropped_unknown_source = 2
    service.write_stats()

    assert stats_file.exists()
    with TestClient(app) as c:
        ingestion = _health(c)["ingestion"]

    assert ingestion["listener"] == "up"
    assert ingestion["ingested_total"] == 1001
    assert ingestion["dropped_unparseable_total"] == 4
    assert ingestion["dropped_unknown_source_total"] == 2
    assert ingestion["dropped_total"] == 6      # summed by the writer


def test_write_stats_leaves_no_temp_file_behind(stats_file, monkeypatch):
    """The write is atomic via a .tmp rename; the temp must not survive."""
    from app.services.ingestion.listener import IngestionService

    monkeypatch.setattr(settings, "ingestion_stats_path", str(stats_file))

    class _NullSession:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def scalars(self, *a, **k):
            class _R:
                def all(self_inner): return []
            return _R()

    service = IngestionService(lambda: _NullSession())
    service.write_stats()

    leftovers = list(stats_file.parent.glob("*.tmp"))
    assert leftovers == [], f"temporary file not cleaned up: {leftovers}"
