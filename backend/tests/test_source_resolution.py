"""Syslog source-resolution integrity (Section 2.2, ingestion attribution).

    cd backend && source .venv/bin/activate
    pytest tests/test_source_resolution.py -v

Three defects in how a received packet was bound to an owning data source:

1. AMBIGUOUS ADDRESS. refresh_sources() built the sender-IP map with a dict
   comprehension, so when two administrators each registered 192.168.1.1 —
   which is not unique across networks — the later row silently overwrote the
   earlier one. One administrator's traffic was then filed under the other's
   source, decided by database row order.

2. UNRESTRICTED FALLBACK. When exactly one source existed, _single_source_id
   accepted traffic from ANY sender, so an unregistered host could write into
   that source.

3. STALE SOURCE. A record is bound to a source when it is buffered, but the
   source can be deleted in the seconds before the flush. The insert then
   violated the network_logs foreign key, and because a failed batch is
   correctly retained for retry, the same doomed batch was resubmitted every
   cycle forever — one deleted source wedged all ingestion behind it.

The first two groups are pure unit tests against a fake session factory and
need no database.
"""
from __future__ import annotations

import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

from app.models import SourceStatus, SourceType, TransportType
from app.services.ingestion.listener import IngestionService


class _FakeSource:
    def __init__(self, ip, source_id=None):
        self.ip_address = ip
        self.source_id = source_id or uuid.uuid4()


class _FakeScalars:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _FakeSession:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self, _stmt):
        return _FakeScalars(self._rows)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _service(rows):
    """An IngestionService whose source table is exactly `rows`."""
    @contextmanager
    def factory():
        yield _FakeSession(rows)

    return IngestionService(factory)


# --- 1. ambiguous sender addresses ------------------------------------------

def test_duplicate_address_is_not_attributed_to_either_source():
    """Two admins registering the same private IP: refuse, do not guess.

    Nothing in a syslog packet distinguishes the two, so any choice would put
    one administrator's network traffic into another administrator's account.
    Dropping is the only answer that cannot leak.
    """
    a, b = _FakeSource("192.168.1.1"), _FakeSource("192.168.1.1")
    svc = _service([a, b])
    assert svc.resolve_source("192.168.1.1") is None


def test_ambiguity_does_not_affect_unambiguous_addresses():
    """One contested address must not disable attribution for the others."""
    a, b = _FakeSource("192.168.1.1"), _FakeSource("192.168.1.1")
    c = _FakeSource("10.0.0.5")
    svc = _service([a, b, c])
    assert svc.resolve_source("192.168.1.1") is None
    assert svc.resolve_source("10.0.0.5") == c.source_id


def test_ambiguity_clears_when_the_duplicate_is_removed():
    """refresh_sources() is called every flush cycle, so fixing the
    configuration must take effect without restarting the listener."""
    a, b = _FakeSource("192.168.1.1"), _FakeSource("192.168.1.1")
    rows = [a, b]

    @contextmanager
    def factory():
        yield _FakeSession(rows)

    svc = IngestionService(factory)
    assert svc.resolve_source("192.168.1.1") is None
    rows.remove(b)
    svc.refresh_sources()
    assert svc.resolve_source("192.168.1.1") == a.source_id


# --- 2. single-source fallback scope -----------------------------------------

def test_single_source_without_an_address_still_accepts_traffic():
    """The fallback exists for the common single-collector setup where no
    address has been configured. Removing it entirely would break ingestion
    for every deployment relying on it, so it is narrowed rather than dropped.
    """
    only = _FakeSource(None)
    svc = _service([only])
    assert svc.resolve_source("203.0.113.9") == only.source_id


def test_single_source_with_an_address_rejects_an_unexpected_sender():
    """Once a source declares an address it is held to it: an unregistered
    host can no longer write into someone else's source."""
    only = _FakeSource("192.168.64.2")
    svc = _service([only])
    assert svc.resolve_source("192.168.64.2") == only.source_id
    assert svc.resolve_source("203.0.113.9") is None


def test_unknown_sender_is_counted_not_silently_discarded():
    only = _FakeSource("192.168.64.2")
    svc = _service([only])
    assert svc.offer(b"<134>1 - - - - - - x", "203.0.113.9") is False
    assert svc.dropped_unknown_source == 1
    assert svc.total_dropped_unknown_source == 1


# --- 3. stale source at the write boundary (needs PostgreSQL) ----------------

from sqlalchemy import select                       # noqa: E402
from sqlalchemy.orm import sessionmaker             # noqa: E402

from app.core.security import hash_password         # noqa: E402
from app.database import SessionLocal, engine       # noqa: E402
from app.models import (                            # noqa: E402
    AdminRole, Administrator, AuditLog, DataSource, NetworkLog,
)


@pytest.fixture()
def two_sources():
    """One admin, two sources — one of which is deleted mid-flight."""
    with SessionLocal() as db:
        admin = Administrator(
            full_name="Resolution Test",
            email=f"res-{uuid.uuid4().hex[:8]}@threatsense.local",
            password_hash=hash_password("TestPassw0rd!"), role=AdminRole.ADMIN)
        db.add(admin)
        db.flush()
        keep = DataSource(admin_id=admin.admin_id, name=f"keep-{uuid.uuid4().hex[:6]}",
                          type=SourceType.SYSLOG, status=SourceStatus.ACTIVE)
        doomed = DataSource(admin_id=admin.admin_id, name=f"gone-{uuid.uuid4().hex[:6]}",
                            type=SourceType.SYSLOG, status=SourceStatus.ACTIVE)
        db.add_all([keep, doomed])
        db.commit()
        ids = {"admin_id": admin.admin_id,
               "keep": keep.source_id, "doomed": doomed.source_id}
    yield ids
    with SessionLocal() as db:
        db.query(NetworkLog).filter(
            NetworkLog.source_id.in_([ids["keep"], ids["doomed"]])
        ).delete(synchronize_session=False)
        db.query(DataSource).filter(
            DataSource.admin_id == ids["admin_id"]).delete(synchronize_session=False)
        db.query(AuditLog).filter(AuditLog.admin_id == ids["admin_id"]).delete()
        db.query(Administrator).filter(
            Administrator.admin_id == ids["admin_id"]).delete()
        db.commit()


def _record(source_id):
    return {
        "source_id": source_id, "src_ip": "192.168.64.2", "dst_ip": "10.0.0.1",
        "src_port": 4444, "dst_port": 80, "protocol": "TCP", "packet_size": 60,
        "flags": "S", "connection_outcome": None, "syslog_severity": 6,
        "raw_message": "test", "event_time": datetime.now(timezone.utc),
    }


def test_deleted_source_does_not_block_the_rest_of_the_batch(two_sources):
    """The wedge: one record naming a deleted source used to fail the whole
    insert, and the retained batch was retried forever. Valid records sharing
    that batch must still commit."""
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    svc = IngestionService(factory)

    with SessionLocal() as db:
        db.query(DataSource).filter(
            DataSource.source_id == two_sources["doomed"]).delete()
        db.commit()

    batch = [_record(two_sources["keep"]), _record(two_sources["doomed"]),
             _record(two_sources["keep"])]
    batch_id = uuid.uuid4()
    svc._write(batch, batch_id, datetime.now(timezone.utc))

    with SessionLocal() as db:
        written = db.scalar(
            select(__import__("sqlalchemy").func.count())
            .select_from(NetworkLog)
            .where(NetworkLog.batch_id == batch_id)) or 0
    assert written == 2, "valid records must survive a stale sibling"
    assert svc.dropped_stale_source == 1
    assert svc.total_dropped_stale_source == 1


def test_batch_of_only_stale_records_commits_nothing_and_does_not_raise(two_sources):
    """A batch that is entirely stale must return cleanly so flush() can drop
    the prefix, rather than raising and being retried indefinitely."""
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    svc = IngestionService(factory)

    with SessionLocal() as db:
        db.query(DataSource).filter(
            DataSource.source_id == two_sources["doomed"]).delete()
        db.commit()

    batch_id = uuid.uuid4()
    svc._write([_record(two_sources["doomed"])], batch_id,
               datetime.now(timezone.utc))          # must not raise

    with SessionLocal() as db:
        written = db.scalar(
            select(__import__("sqlalchemy").func.count())
            .select_from(NetworkLog)
            .where(NetworkLog.batch_id == batch_id)) or 0
    assert written == 0
    assert svc.dropped_stale_source == 1


def test_reconfigured_source_no_longer_accepts_the_buffered_record(two_sources):
    """TOCTOU: resolution happens at buffer time, the write happens later.

    A record resolves to source A because A owns 192.168.1.10. Before the
    flush, the admin repoints A at a different address. A still EXISTS, so an
    existence check alone accepts the record — and it lands under a source
    that no longer claims the endpoint it came from.
    """
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    svc = IngestionService(factory)

    with SessionLocal() as db:
        src = db.get(DataSource, two_sources["keep"])
        src.ip_address = "192.168.1.10"
        db.commit()

    rec = _record(two_sources["keep"])
    rec["_sender_ip"] = "192.168.1.10"
    rec["_transport"] = TransportType.UDP
    rec["_listener_port"] = 1514

    with SessionLocal() as db:                       # admin edits the source
        db.get(DataSource, two_sources["keep"]).ip_address = "10.9.9.9"
        db.commit()

    batch_id = uuid.uuid4()
    svc._write([rec], batch_id, datetime.now(timezone.utc))

    with SessionLocal() as db:
        written = db.scalar(
            select(__import__("sqlalchemy").func.count())
            .select_from(NetworkLog)
            .where(NetworkLog.batch_id == batch_id)) or 0
    assert written == 0
    assert svc.dropped_endpoint_mismatch == 1


def test_transport_mismatch_is_rejected(two_sources):
    """A source configured for TLS must not absorb a UDP message."""
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    svc = IngestionService(factory)

    with SessionLocal() as db:
        src = db.get(DataSource, two_sources["keep"])
        src.transport = TransportType.TLS
        src.port = 6514
        db.commit()

    rec = _record(two_sources["keep"])
    rec["_sender_ip"] = "192.168.64.2"
    rec["_transport"] = TransportType.UDP
    rec["_listener_port"] = 1514

    svc._write([rec], uuid.uuid4(), datetime.now(timezone.utc))
    assert svc.dropped_endpoint_mismatch == 1


def test_matching_endpoint_is_accepted(two_sources):
    """The check must not reject traffic that genuinely still matches."""
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    svc = IngestionService(factory)

    with SessionLocal() as db:
        src = db.get(DataSource, two_sources["keep"])
        src.ip_address = "192.168.64.2"
        src.transport = TransportType.TLS
        src.port = 6514
        db.commit()

    rec = _record(two_sources["keep"])
    rec["_sender_ip"] = "192.168.64.2"
    rec["_transport"] = TransportType.TLS
    rec["_listener_port"] = 6514

    batch_id = uuid.uuid4()
    svc._write([rec], batch_id, datetime.now(timezone.utc))
    with SessionLocal() as db:
        written = db.scalar(
            select(__import__("sqlalchemy").func.count())
            .select_from(NetworkLog)
            .where(NetworkLog.batch_id == batch_id)) or 0
    assert written == 1
    assert svc.dropped_endpoint_mismatch == 0


def test_unconfigured_fields_are_not_enforced(two_sources):
    """A source that asserts no address/transport has nothing to contradict.

    This is the address-less single-collector deployment the fallback in
    resolve_source() exists for; enforcing absent fields would break it.
    """
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    svc = IngestionService(factory)

    rec = _record(two_sources["keep"])                # source has no ip/transport
    rec["_sender_ip"] = "203.0.113.99"
    rec["_transport"] = TransportType.UDP
    rec["_listener_port"] = 1514

    batch_id = uuid.uuid4()
    svc._write([rec], batch_id, datetime.now(timezone.utc))
    with SessionLocal() as db:
        written = db.scalar(
            select(__import__("sqlalchemy").func.count())
            .select_from(NetworkLog)
            .where(NetworkLog.batch_id == batch_id)) or 0
    assert written == 1
    assert svc.dropped_endpoint_mismatch == 0


def test_mismatched_record_does_not_block_valid_siblings(two_sources):
    """Same guarantee as the stale case: drop the record, keep the batch."""
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    svc = IngestionService(factory)

    with SessionLocal() as db:
        db.get(DataSource, two_sources["keep"]).ip_address = "192.168.64.2"
        db.commit()

    good = _record(two_sources["keep"])
    good.update(_sender_ip="192.168.64.2", _transport=TransportType.UDP,
                _listener_port=1514)
    bad = _record(two_sources["keep"])
    bad.update(_sender_ip="203.0.113.99", _transport=TransportType.UDP,
               _listener_port=1514)

    batch_id = uuid.uuid4()
    svc._write([good, bad, dict(good)], batch_id, datetime.now(timezone.utc))
    with SessionLocal() as db:
        written = db.scalar(
            select(__import__("sqlalchemy").func.count())
            .select_from(NetworkLog)
            .where(NetworkLog.batch_id == batch_id)) or 0
    assert written == 2
    assert svc.dropped_endpoint_mismatch == 1


def test_offer_records_the_resolution_evidence():
    """The write boundary can only revalidate what offer() carried forward."""
    only = _FakeSource("192.168.64.2")
    svc = _service([only])
    message = (b"<134>1 host app - - - src=10.0.0.7 dst=192.168.1.5 "
               b"sport=40007 dport=443 proto=TCP size=107 flags=SYN")
    accepted = svc.offer(message, "192.168.64.2", TransportType.TLS, 6514)
    assert accepted is False                      # buffered, batch not yet full
    assert svc.buffer, "record should have been buffered"
    rec = svc.buffer[0]
    assert rec["_sender_ip"] == "192.168.64.2"
    assert rec["_transport"] == TransportType.TLS
    assert rec["_listener_port"] == 6514


def test_live_source_write_still_updates_last_received(two_sources):
    """The fix must not disturb the existing behaviour it wraps."""
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    svc = IngestionService(factory)
    now = datetime.now(timezone.utc)
    svc._write([_record(two_sources["keep"])], uuid.uuid4(), now)

    with SessionLocal() as db:
        src = db.get(DataSource, two_sources["keep"])
        assert src.status == SourceStatus.ACTIVE
        assert src.last_received is not None
        assert abs(src.last_received - now) < timedelta(seconds=5)
