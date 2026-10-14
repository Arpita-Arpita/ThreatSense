"""Ingestion durability, validation and deduplication (Section 2.2, Algorithm 1).

    cd backend && source .venv/bin/activate
    pytest tests/test_ingestion_durability.py -v

WHY THIS EXISTS
---------------
An external audit found four confirmed defects in the ingestion path, all of
which contradict the proposal:

  1. flush() cleared the buffer BEFORE the database write and handed the only
     copy to an executor. Any failure in _write destroyed the whole batch
     silently, while /health still reported zero drops. NFR-01 requires
     ingestion "without data loss".

  2. There was no final flush at shutdown. Algorithm 1 ends with
     "IF buffer IS NOT empty THEN BULK INSERT buffer INTO network_logs";
     whatever was buffered when the listener stopped was discarded.

  3. make_record() fabricated required fields: a missing protocol became
     "UDP" and a missing packet size became len(raw) — the character length
     of the log line. Section 2.2 says such records are REJECTED. Fabricated
     values fed the feature extractor and therefore the model.

  4. No deduplication anywhere, though Section 2.2 requires it and
     Algorithm 1 checks for duplicates before buffering.

The tests below are deliberately failure-oriented. A happy-path test passes
against the broken implementation too — it was the failure paths that were
wrong.

THE CONCURRENCY TRAP
--------------------
Writing first and then calling buffer.clear() does NOT fix defect 1. offer()
appends while the write is awaited, so clear() discards records that were
never persisted; and every transport starts a flush task as soon as the batch
size is reached, so two flushes can snapshot the same records and store each
twice. The implementation therefore holds a lock across the whole operation
and removes a PREFIX of exactly the length written.

test_records_arriving_during_a_write_are_not_lost and
test_concurrent_flushes_do_not_double_write are the two that catch a naive
fix. Both pass against a correct implementation and fail against clear().
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.database import SessionLocal
from app.models import AdminRole, Administrator, DataSource, NetworkLog, SourceStatus
from app.services.ingestion import listener as listener_mod
from app.services.ingestion.listener import IngestionService
from app.services.ingestion.parsers import parse as parse_log
from app.services.ingestion.parsers.base import fingerprint

SENDER = "10.44.44.44"


class _NullTransport:
    """Closable stand-in — main() now closes transports before draining."""

    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


async def _no_transport(_service):
    """Stand-in for a transport starter in the shutdown test (binds nothing)."""
    return _NullTransport()


# --- fixtures -----------------------------------------------------------------

@pytest.fixture()
def source():
    """A real admin + source, so writes exercise the actual schema."""
    email = f"ingest-{uuid.uuid4().hex[:8]}@threatsense.local"
    with SessionLocal() as db:
        admin = Administrator(full_name="Ingest Test", email=email,
                              password_hash="x" * 60, role=AdminRole.ADMIN)
        db.add(admin)
        db.flush()
        src = DataSource(admin_id=admin.admin_id,
                         name=f"ingest-src-{uuid.uuid4().hex[:6]}", type="SYSLOG",
                         ip_address=SENDER, port=1514, transport="UDP",
                         status=SourceStatus.ACTIVE)
        db.add(src)
        db.commit()
        ids = {"admin_id": admin.admin_id, "source_id": src.source_id}
    yield ids
    with SessionLocal() as db:
        db.query(NetworkLog).filter(
            NetworkLog.source_id == ids["source_id"]).delete()
        db.query(DataSource).filter(
            DataSource.source_id == ids["source_id"]).delete()
        # The upload tests log in and upload, both of which write audit rows
        # (Section 2.1). Those hold an FK on administrators.
        from app.models import AuditLog
        db.query(AuditLog).filter(AuditLog.admin_id == ids["admin_id"]).delete()
        db.query(Administrator).filter(
            Administrator.admin_id == ids["admin_id"]).delete()
        db.commit()


@pytest.fixture()
def service(source):
    return IngestionService(SessionLocal)


def _msg(n: int, *, ts: str | None = None) -> bytes:
    """A parseable message. Distinct n keeps records non-identical."""
    stamp = f" {ts}" if ts else ""
    return (f"<134>1{stamp} host app - - - src=10.0.0.{n % 250 + 1} "
            f"dst=192.168.1.5 sport={40000 + n} dport=443 proto=TCP "
            f"size={100 + n} flags=SYN").encode()


def _stored(source_id) -> list[NetworkLog]:
    with SessionLocal() as db:
        return list(db.scalars(select(NetworkLog).where(
            NetworkLog.source_id == source_id)))


# --- 1. a failed write must not lose the batch --------------------------------

@pytest.mark.anyio
async def test_write_failure_retains_every_record(service, source):
    """The defect: the buffer was cleared before the write was known to work."""
    for i in range(5):
        service.offer(_msg(i), SENDER)
    assert len(service.buffer) == 5
    before = list(service.buffer)

    def _boom(batch, batch_id, now):
        raise RuntimeError("database is down")

    service._write = _boom
    await service.flush()

    assert service.buffer == before, "records were lost by a failed write"
    assert service.total_ingested == 0
    assert service.total_write_failures == 1


@pytest.mark.anyio
async def test_failed_batch_is_persisted_by_a_later_flush(service, source):
    """A transient outage must delay ingestion, not lose it."""
    for i in range(3):
        service.offer(_msg(i), SENDER)

    real_write = service._write
    calls = {"n": 0}

    def _flaky(batch, batch_id, now):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient")
        return real_write(batch, batch_id, now)

    service._write = _flaky
    await service.flush()          # fails
    assert len(service.buffer) == 3
    await service.flush()          # succeeds

    assert service.buffer == []
    rows = _stored(source["source_id"])
    assert len(rows) == 3, "records were dropped or stored twice across the retry"


@pytest.mark.anyio
async def test_successful_write_removes_exactly_the_persisted_records(service, source):
    for i in range(4):
        service.offer(_msg(i), SENDER)
    await service.flush()
    assert service.buffer == []
    assert service.total_ingested == 4
    assert len(_stored(source["source_id"])) == 4


# --- 2. concurrency: the two tests a naive fix fails --------------------------

@pytest.mark.anyio
async def test_records_arriving_during_a_write_are_not_lost(service, source):
    """Catches `await write(...)` followed by `buffer.clear()`.

    A message offered while the write is in flight belongs to no batch yet.
    Clearing the whole buffer afterwards discards it with no error anywhere.
    """
    for i in range(3):
        service.offer(_msg(i), SENDER)

    real_write = service._write
    gate = asyncio.Event()

    def _slow(batch, batch_id, now):
        # Runs in an executor thread; block until the test releases it.
        asyncio.run_coroutine_threadsafe(_noop(), loop).result()
        return real_write(batch, batch_id, now)

    async def _noop():
        await gate.wait()

    loop = asyncio.get_running_loop()
    service._write = _slow

    task = asyncio.create_task(service.flush())
    await asyncio.sleep(0.05)                 # let the write start
    service.offer(_msg(99), SENDER)           # arrives mid-write
    gate.set()
    await task

    assert len(service.buffer) == 1, "a record offered during the write was lost"
    assert len(_stored(source["source_id"])) == 3, "the late record was written early"

    await service.flush()
    assert len(_stored(source["source_id"])) == 4


@pytest.mark.anyio
async def test_concurrent_flushes_do_not_double_write(service, source):
    """Two overlapping flushes must not each persist the same records."""
    for i in range(6):
        service.offer(_msg(i), SENDER)

    await asyncio.gather(service.flush(), service.flush())

    rows = _stored(source["source_id"])
    assert len(rows) == 6, f"expected 6 rows, got {len(rows)} (double write?)"
    assert service.buffer == []
    assert service.total_ingested == 6


@pytest.mark.anyio
async def test_many_concurrent_flushes_stay_consistent(service, source):
    """Heavier version of the above — the batch-size path starts a flush task
    from every transport callback, so several can pile up under load."""
    for i in range(20):
        service.offer(_msg(i), SENDER)

    await asyncio.gather(*(service.flush() for _ in range(5)))

    assert len(_stored(source["source_id"])) == 20
    assert service.buffer == []


# --- 3. required fields are rejected, not fabricated --------------------------

def test_missing_protocol_is_rejected_not_defaulted_to_udp():
    """It used to become "UDP", which then fed tcp_ratio in the feature vector."""
    assert parse_log("src=1.1.1.1 dst=2.2.2.2 size=100") is None


def test_missing_packet_size_is_rejected_not_replaced_by_line_length():
    """It used to become len(raw) — a character count, not a packet size."""
    assert parse_log("src=1.1.1.1 dst=2.2.2.2 proto=TCP") is None


@pytest.mark.parametrize("line", [
    "src=999.999.999.999 dst=2.2.2.2 proto=TCP size=100",
    "src=1.1.1.1 dst=not-an-ip proto=TCP size=100",
    "src= dst=2.2.2.2 proto=TCP size=100",
])
def test_malformed_addresses_are_rejected(line):
    """Rejected HERE, before PostgreSQL's INET type sees them.

    One malformed address reaching the database aborts the whole INSERT — and
    with it every valid record batched alongside it.
    """
    assert parse_log(line) is None


def test_zero_and_negative_packet_sizes_are_rejected():
    assert parse_log("src=1.1.1.1 dst=2.2.2.2 proto=TCP size=0") is None
    assert parse_log("src=1.1.1.1 dst=2.2.2.2 proto=TCP size=-5") is None


def test_valid_ipv4_record_is_accepted():
    rec = parse_log("src=10.1.2.3 dst=10.4.5.6 proto=TCP size=120 sport=1 dport=2")
    assert rec is not None
    assert rec["src_ip"] == "10.1.2.3"
    assert rec["protocol"] == "TCP"
    assert rec["packet_size"] == 120


def test_valid_ipv6_record_is_accepted():
    """The source-creation schema accepts IPv6, so ingestion must agree."""
    rec = parse_log("src=2001:db8::1 dst=2001:db8::2 proto=TCP size=90")
    assert rec is not None
    assert rec["src_ip"] == "2001:db8::1"


@pytest.mark.anyio
async def test_a_rejected_record_cannot_poison_a_batch(service, source):
    """A malformed line must not take valid records down with it."""
    for i in range(3):
        service.offer(_msg(i), SENDER)
    service.offer(b"<134>1 host app - - - src=300.1.1.1 dst=2.2.2.2 proto=TCP size=5",
                  SENDER)
    assert len(service.buffer) == 3, "the malformed record was buffered"
    assert service.dropped_unparseable == 1

    await service.flush()
    assert len(_stored(source["source_id"])) == 3


# --- 4. UTC normalisation (Algorithm 1: CONVERT TO UTC) -----------------------

def test_offset_timestamp_is_converted_to_utc():
    rec = parse_log("<134>1 2026-08-24T14:30:00+10:00 h a - - - "
                    "src=1.1.1.1 dst=2.2.2.2 proto=TCP size=100")
    assert rec is not None
    ts = rec["event_time"]
    assert ts.utcoffset() == timedelta(0)
    assert ts.hour == 4 and ts.day == 24, "14:30+10:00 is 04:30 UTC"


def test_zulu_timestamp_stays_utc():
    rec = parse_log("<134>1 2026-08-24T04:30:00Z h a - - - "
                    "src=1.1.1.1 dst=2.2.2.2 proto=TCP size=100")
    assert rec["event_time"].utcoffset() == timedelta(0)
    assert rec["event_time"].hour == 4


# --- 5. deduplication ---------------------------------------------------------

@pytest.mark.anyio
async def test_identical_timestamped_message_is_stored_once(service, source):
    """Section 2.2: duplicates are removed within the batch."""
    msg = _msg(1, ts="2026-08-24T04:30:00Z")
    service.offer(msg, SENDER)
    service.offer(msg, SENDER)
    assert len(service.buffer) == 1
    assert service.dropped_duplicate == 1

    await service.flush()
    assert len(_stored(source["source_id"])) == 1


@pytest.mark.anyio
async def test_same_endpoints_different_timestamp_are_both_kept(service, source):
    """Near-duplicates are two events, not one repeated event."""
    service.offer(_msg(1, ts="2026-08-24T04:30:00Z"), SENDER)
    service.offer(_msg(1, ts="2026-08-24T04:30:01Z"), SENDER)
    assert len(service.buffer) == 2
    await service.flush()
    assert len(_stored(source["source_id"])) == 2


@pytest.mark.anyio
async def test_same_endpoints_different_size_are_both_kept(service, source):
    service.offer(_msg(1, ts="2026-08-24T04:30:00Z"), SENDER)
    service.offer(_msg(2, ts="2026-08-24T04:30:00Z"), SENDER)
    assert len(service.buffer) == 2


@pytest.mark.anyio
async def test_timestampless_identical_messages_are_all_kept(service, source):
    """The DDoS carve-out, stated as a test so it is not "fixed" later.

    A SYN flood is a burst of byte-identical packets. Where the source gives
    no timestamp, "identical" cannot distinguish a redelivered event from a
    second real packet — and collapsing them would erase packets_per_sec,
    which is exactly how Section 2.3's rule layer recognises DDOS. Dedup
    therefore applies only to records that carry an event time.
    """
    msg = _msg(7)                      # no timestamp
    for _ in range(4):
        service.offer(msg, SENDER)
    assert len(service.buffer) == 4
    assert service.dropped_duplicate == 0
    assert fingerprint(service.buffer[0]) is None


@pytest.mark.anyio
async def test_dedup_window_is_the_pending_batch_not_forever(service, source):
    """After a flush the same message may legitimately arrive again."""
    msg = _msg(3, ts="2026-08-24T04:30:00Z")
    service.offer(msg, SENDER)
    await service.flush()
    service.offer(msg, SENDER)
    assert len(service.buffer) == 1, "dedup outlived the batch it belongs to"


# --- 6. telemetry reflects what actually happened -----------------------------

@pytest.mark.anyio
async def test_write_failures_are_counted_for_health(service, source, tmp_path,
                                                     monkeypatch):
    """/health could report zero drops after a write failure lost the batch."""
    from app.config import settings as app_settings
    monkeypatch.setattr(app_settings, "ingestion_stats_path",
                        str(tmp_path / "stats.json"))
    service.offer(_msg(1), SENDER)

    def _boom(batch, batch_id, now):
        raise RuntimeError("down")

    service._write = _boom
    await service.flush()
    service.write_stats()

    import json
    data = json.loads((tmp_path / "stats.json").read_text())
    assert data["write_failures_total"] == 1
    assert data["buffered_now"] == 1, "the retained record should be visible"
    assert data["ingested_total"] == 0


# --- 7. shutdown flush (Algorithm 1's final step) ----------------------------

@pytest.mark.anyio
async def test_shutdown_flushes_a_partial_batch(service, source, monkeypatch,
                                                tmp_path):
    """Algorithm 1 ends with a final flush; there was no such path.

    A partial batch — fewer than syslog_flush_batch records, still waiting on
    the 5-second timer — was discarded whenever the listener stopped. This
    drives main()'s loop-and-finally directly: the stop event fires while
    records sit buffered, and they must still reach the database.
    """
    from app.config import settings as app_settings
    monkeypatch.setattr(app_settings, "ingestion_stats_path",
                        str(tmp_path / "stats.json"))
    monkeypatch.setattr(app_settings, "syslog_flush_seconds", 60)  # never fires
    # No sockets: TLS needs a certificate, and binding UDP would clash with a
    # real listener if one happens to be running.
    monkeypatch.setattr(app_settings, "syslog_tls_enabled", False)
    monkeypatch.setattr(app_settings, "syslog_tcp_enabled", False)
    monkeypatch.setattr(listener_mod, "start_udp", _no_transport)

    # main() builds its own service; hand it ours so we can pre-load the buffer.
    monkeypatch.setattr(listener_mod, "IngestionService", lambda *a, **k: service)
    for i in range(3):
        service.offer(_msg(i), SENDER)
    assert len(service.buffer) == 3

    task = asyncio.create_task(listener_mod.main())
    await asyncio.sleep(0.1)                       # let main() reach its loop
    task.cancel()                                  # stand-in for SIGINT/SIGTERM
    try:
        await task
    except asyncio.CancelledError:
        pass

    # Cancellation unwinds through the finally, which performs the final flush.
    assert len(_stored(source["source_id"])) == 3, \
        "buffered records were discarded at shutdown"


@pytest.mark.anyio
async def test_shutdown_reports_records_it_could_not_persist(service, source, caplog):
    """If the final flush also fails, say so — do not exit quietly.

    Losing data at shutdown is bad; losing it silently is worse, because
    nothing in the logs would ever indicate the gap.
    """
    import logging
    service.offer(_msg(1), SENDER)

    def _boom(batch, batch_id, now):
        raise RuntimeError("database gone")

    service._write = _boom
    caplog.set_level(logging.ERROR)
    await service.flush()

    assert len(service.buffer) == 1
    assert any("retained for retry" in r.getMessage() for r in caplog.records)


# =============================================================================
# Fix 4b — defects found by adversarial review of the first durability patch.
#
# All three were reproduced against the shipped code before being fixed here.
# They share a shape: flush() is correct in isolation, so a test suite that
# only exercises flush() directly passes while the lifecycle AROUND it is
# broken.
# =============================================================================

# --- Finding 1: unbounded flush tasks ----------------------------------------

@pytest.mark.anyio
async def test_size_triggered_flush_does_not_spawn_a_task_per_message(service, source):
    """The durable flush keeps records buffered until the write succeeds, so
    offer() reports "full" for EVERY message arriving during that write. With
    create_task(flush()) in the transport callback, one slow write at NFR-01's
    1,000 msg/s produced ~1,000 tasks queued on the lock.

    The lock stopped them double-writing; nothing stopped them existing.
    NFR-01 requires ingestion "without data loss or queue overflow", and that
    was a queue overflow of our own making.
    """
    from app.config import settings as app_settings
    monkeypatch_batch = 3
    real_write = service._write
    gate = asyncio.Event()
    loop = asyncio.get_running_loop()

    async def _wait():
        await gate.wait()

    def _slow(batch, batch_id, now):
        asyncio.run_coroutine_threadsafe(_wait(), loop).result()
        return real_write(batch, batch_id, now)

    service._write = _slow

    import unittest.mock as mock
    with mock.patch.object(app_settings, "syslog_flush_batch", monkeypatch_batch):
        # Drive the REAL protocol callback, not flush() directly — that is
        # where the task was created.
        proto = listener_mod.SyslogProtocol(service)
        for i in range(25):
            proto.datagram_received(_msg(i), (SENDER, 5000))
            await asyncio.sleep(0)          # let the loop schedule anything queued

        # Count every pending task belonging to the ingestion service —
        # BOTH the single-flight worker and any bare flush() task, since the
        # defect being guarded was create_task(flush()) per message. Matching
        # only the worker name would let the old behaviour pass unnoticed.
        pending = [t for t in asyncio.all_tasks()
                   if not t.done()
                   and any(name in repr(t.get_coro())
                           for name in ("_drain_full_batches",
                                        "IngestionService.flush"))]
        assert len(pending) <= 1, (
            f"{len(pending)} pending flush workers for 25 messages — "
            "one task per message is back")

        gate.set()
        await asyncio.sleep(0.2)
        await service.wait_for_pending_flush()

    await service.flush()
    assert len(_stored(source["source_id"])) == 25, "messages were lost"


@pytest.mark.anyio
async def test_worker_drains_a_batch_that_arrives_during_its_write(service, source):
    """Records must pile up DURING the write — the earlier version of this
    test put everything in the buffer first, so it never reproduced its own
    stated behaviour and passed against the defect below.

    THE DEFECT. _drain_full_batches() decided whether to keep going by
    comparing buffer lengths:

        before = len(self.buffer)
        await self.flush()
        if len(self.buffer) >= before: return    # "the write failed"

    That inference is wrong, because offer() keeps appending during the
    awaited write. One full batch written successfully plus one full batch
    arriving meanwhile leaves the buffer exactly the same size — which read
    as failure, so the worker exited and abandoned a complete batch.

    flush() now returns success explicitly and the worker uses that.
    """
    from app.config import settings as app_settings
    import unittest.mock as mock

    batch = 3
    real_write = service._write
    gate = asyncio.Event()
    loop = asyncio.get_running_loop()
    writes: list[int] = []

    async def _wait():
        await gate.wait()

    def _blocking(b, batch_id, now):
        writes.append(len(b))
        if len(writes) == 1:                     # block only the first write
            asyncio.run_coroutine_threadsafe(_wait(), loop).result()
        return real_write(b, batch_id, now)

    service._write = _blocking

    with mock.patch.object(app_settings, "syslog_flush_batch", batch):
        for i in range(batch):                   # one full batch
            service.offer(_msg(i), SENDER)
        service.request_flush()
        await asyncio.sleep(0.05)                # the write is now blocked

        for i in range(batch, batch * 2):        # a SECOND full batch arrives
            service.offer(_msg(i), SENDER)
        assert len(service.buffer) == batch * 2

        gate.set()
        # Await ONLY the single-flight worker — no manual flush() afterwards,
        # which is what masked the defect previously.
        await service.wait_for_pending_flush()

        assert len(service.buffer) < batch, (
            f"{len(service.buffer)} record(s) left; the worker abandoned a "
            "full batch that arrived during its write")

    assert len(_stored(source["source_id"])) == batch * 2
    assert len(writes) >= 2, "the second batch was never written"


@pytest.mark.anyio
async def test_flush_reports_success_and_failure_explicitly(service, source):
    """The drain loop depends on this contract, so pin it directly."""
    for i in range(3):
        service.offer(_msg(i), SENDER)
    assert await service.flush() is True
    assert await service.flush() is True          # nothing to do is success

    accepted = service.offer(_msg(9), SENDER)
    assert len(service.buffer) == 1, (
        f"record not buffered (offer -> {accepted}, "
        f"unknown_source={service.dropped_unknown_source}, "
        f"unparseable={service.dropped_unparseable})")

    def _boom(b, batch_id, now):
        raise RuntimeError("down")

    service._write = _boom
    assert await service.flush() is False


@pytest.mark.anyio
async def test_request_flush_is_idempotent_while_a_worker_runs(service, source):
    for i in range(3):
        service.offer(_msg(i), SENDER)
    service.request_flush()
    first = service._flush_task
    service.request_flush()
    service.request_flush()
    assert service._flush_task is first, "a second worker was scheduled"
    await service.wait_for_pending_flush()


# --- Finding 2: shutdown must stop traffic BEFORE draining -------------------

@pytest.mark.anyio
async def test_listeners_are_closed_before_the_final_drain(source, monkeypatch,
                                                           tmp_path):
    """Reproduces the reviewed defect exactly.

    Shutdown drained while the sockets were still open, so a record arriving
    during the final write was correctly RETAINED by the prefix algorithm and
    then thrown away when the process exited. The fix is ordering: close the
    transports, wait for them, then drain.

    The fake transport below injects a message the moment the drain begins,
    and asserts both that the transport was closed first and that nothing is
    left buffered.
    """
    from app.config import settings as app_settings
    monkeypatch.setattr(app_settings, "ingestion_stats_path",
                        str(tmp_path / "stats.json"))
    monkeypatch.setattr(app_settings, "syslog_flush_seconds", 60)
    monkeypatch.setattr(app_settings, "syslog_tls_enabled", False)
    monkeypatch.setattr(app_settings, "syslog_tcp_enabled", False)

    svc = IngestionService(SessionLocal)
    monkeypatch.setattr(listener_mod, "IngestionService", lambda *a, **k: svc)

    state = {"closed": False, "injected_after_close": False}

    class _FakeTransport:
        def close(self):
            state["closed"] = True

    async def _fake_udp(_service):
        return _FakeTransport()

    monkeypatch.setattr(listener_mod, "start_udp", _fake_udp)

    # A record already buffered before shutdown.
    svc.offer(_msg(1), SENDER)

    # Inject a late arrival at the moment the final flush runs.
    real_flush = svc.flush
    injected = {"done": False}

    async def _flush_with_injection():
        if not injected["done"] and state["closed"]:
            injected["done"] = True
            state["injected_after_close"] = True
            # Traffic still arriving during the drain. It must be REFUSED:
            # a record accepted now would be buffered behind the final write
            # and lost on exit. offer() returns False once accepting is off.
            state["late_accepted"] = svc.offer(_msg(2), SENDER)
        await real_flush()

    svc.flush = _flush_with_injection

    task = asyncio.create_task(listener_mod.main())
    await asyncio.sleep(0.1)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert state["closed"], "the transport was never closed at shutdown"
    assert state["injected_after_close"], "test did not exercise the drain"
    assert state.get("late_accepted") is False, (
        "a record was accepted during the shutdown drain — it would sit "
        "behind the final write and be lost on exit")
    assert not svc.accepting, "the accepting gate was never closed"
    # Nothing may be left buffered when main() returns.
    assert svc.buffer == [], (
        f"{len(svc.buffer)} record(s) left buffered after shutdown")
    # Exactly the record buffered BEFORE shutdown is persisted.
    assert len(_stored(source["source_id"])) == 1


# --- Finding 3: values the database will refuse must never enter a batch -----

@pytest.mark.parametrize("line,why", [
    ("src=1.1.1.1 dst=2.2.2.2 proto=TCP size=100 sport=70000",
     "src_port above the CHECK (0..65535)"),
    ("src=1.1.1.1 dst=2.2.2.2 proto=TCP size=100 dport=99999",
     "dst_port above the CHECK"),
    ("src=1.1.1.1 dst=2.2.2.2 proto=TCP size=100 sport=-1",
     "negative port — must be rejected, not silently nulled"),
    ("src=1.1.1.1 dst=2.2.2.2 proto=TCP size=999999999999999999999",
     "packet_size overflows PostgreSQL INTEGER"),
    ("src=1.1.1.1 dst=2.2.2.2 proto=TCP size=100 sev=999999999999999999999",
     "syslog_severity overflows INTEGER"),
    ("src=1.1.1.1 dst=2.2.2.2 proto=TCP size=100 sev=9",
     "syslog severity is 0..7"),
    ("src=1.1.1.1 dst=2.2.2.2 proto=NOT_A_REAL_PROTOCOL size=100",
     "protocol longer than VARCHAR(10) was silently truncated"),
])
def test_values_the_database_would_refuse_are_rejected(line, why):
    """Now that a failed write RETAINS its batch for retry, a single value the
    schema refuses is worse than before: it is retried forever and blocks
    every record queued behind it. Durability turned "lose 500 rows" into
    "wedge ingestion", so validation has to be complete rather than mostly.
    """
    assert parse_log(line) is None, f"accepted a record that {why}"


def test_absent_optional_fields_are_still_accepted():
    """Rejecting out-of-range values must not reject absent ones — Section 2.2
    marks ports and severity NULLABLE."""
    rec = parse_log("src=1.1.1.1 dst=2.2.2.2 proto=TCP size=100")
    assert rec is not None
    assert rec["src_port"] is None and rec["dst_port"] is None
    assert rec["syslog_severity"] is None


def test_in_range_values_survive():
    rec = parse_log("src=1.1.1.1 dst=2.2.2.2 proto=TCP size=1500 "
                    "sport=65535 dport=0 sev=7")
    assert rec["src_port"] == 65535 and rec["dst_port"] == 0
    assert rec["syslog_severity"] == 7


@pytest.mark.anyio
async def test_a_poison_record_cannot_wedge_the_pipeline(service, source):
    """End to end: the whole point of Finding 3.

    A batch containing an out-of-range port used to commit-fail, be retained,
    and fail again on every retry — permanently blocking ingestion behind it.
    """
    for i in range(5):
        service.offer(_msg(i), SENDER)
    service.offer(b"src=1.1.1.1 dst=2.2.2.2 proto=TCP size=100 sport=70000", SENDER)
    assert len(service.buffer) == 5, "the poison record entered the batch"

    await service.flush()
    assert service.buffer == [], "ingestion is wedged"
    assert len(_stored(source["source_id"])) == 5


# --- Finding 6: duplicate-only cycles must be reported -----------------------

def test_duplicate_only_cycle_is_logged_and_reset(service, caplog):
    """log_drops() returned early unless an unknown-source or unparseable drop
    had also occurred, so duplicate counts silently accumulated across cycles
    until some unrelated bad message happened to flush them."""
    import logging
    msg = _msg(1, ts="2026-08-24T04:30:00Z")
    service.offer(msg, SENDER)
    service.offer(msg, SENDER)
    assert service.dropped_duplicate == 1

    caplog.set_level(logging.INFO)
    service.log_drops()

    assert service.dropped_duplicate == 0, "the per-cycle counter was not reset"
    assert any("duplicate" in r.getMessage() for r in caplog.records)


# --- Finding 7: the failure log must not render the database exception -------

@pytest.mark.anyio
async def test_write_failure_log_excludes_the_raw_exception(service, caplog):
    """A SQLAlchemy error renders the statement and its bound parameters —
    which are network_logs rows, including raw_message, which is
    attacker-controlled Syslog content. Same principle as the password-reset
    hardening: never render a third-party error string wholesale.
    """
    import logging
    secret = "SENSITIVE-PAYLOAD-cafebabe"
    service.offer(f"src=1.1.1.1 dst=2.2.2.2 proto=TCP size=100 note={secret}"
                  .encode(), SENDER)

    def _boom(batch, batch_id, now):
        raise RuntimeError(f"INSERT failed for row containing {secret}")

    service._write = _boom
    caplog.set_level(logging.DEBUG)
    await service.flush()

    haystack = "\n".join([r.getMessage() for r in caplog.records] + [caplog.text])
    assert secret not in haystack, "the database exception text was logged verbatim"
    assert "RuntimeError" in haystack, "the exception type should still be logged"
    assert "retained for retry" in haystack


# --- Finding 5: the upload path's dedup had no endpoint test -----------------

def test_upload_endpoint_deduplicates_identical_timestamped_lines(source):
    """Section 2.2 puts dedup under "Preprocessing (all formats)".

    The upload path shares the listener's fingerprint, but nothing proved it
    end to end — and the upload code differs in ways that matter: it sets
    source_id before fingerprinting, counts duplicates as skipped, and
    commits through its own path.

    NOTE the timestamps: only records carrying an event time are
    deduplicable, so a duplicate iptables line WITHOUT one is stored twice by
    design (see test_timestampless_identical_messages_are_all_kept).
    """
    from app.core.security import hash_password
    from fastapi.testclient import TestClient
    from app.main import app
    from app.models import AdminRole

    password = "UploadDedup1!"
    with SessionLocal() as db:
        admin = db.get(Administrator, source["admin_id"])
        admin.password_hash = hash_password(password)
        admin.role = AdminRole.ADMIN
        email = admin.email
        db.commit()

    line = ("<134>1 2026-08-24T04:30:00Z host app - - - src=10.5.5.5 "
            "dst=10.6.6.6 sport=1111 dport=2222 proto=TCP size=250 flags=SYN")
    body = "\n".join([line, line, line])          # same line three times

    with TestClient(app) as c:
        assert c.post("/api/auth/login",
                      json={"email": email, "password": password}).status_code == 200
        r = c.post(f"/api/sources/{source['source_id']}/upload",
                   files={"file": ("logs.txt", body.encode(), "text/plain")})
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["parsed"] == 1, "duplicate lines were stored"
    assert payload["skipped"] == 2, "duplicates should be reported as skipped"

    rows = [r_ for r_ in _stored(source["source_id"])
            if str(r_.src_ip) == "10.5.5.5"]
    assert len(rows) == 1


def test_upload_keeps_lines_that_differ(source):
    """Dedup must not swallow genuinely different events in one file."""
    from app.core.security import hash_password
    from fastapi.testclient import TestClient
    from app.main import app
    from app.models import AdminRole

    password = "UploadDedup2!"
    with SessionLocal() as db:
        admin = db.get(Administrator, source["admin_id"])
        admin.password_hash = hash_password(password)
        admin.role = AdminRole.ADMIN
        email = admin.email
        db.commit()

    base = ("<134>1 2026-08-24T04:31:0{i}Z host app - - - src=10.7.7.7 "
            "dst=10.8.8.8 sport=3333 dport=4444 proto=TCP size=300 flags=SYN")
    body = "\n".join(base.format(i=i) for i in range(3))

    with TestClient(app) as c:
        c.post("/api/auth/login", json={"email": email, "password": password})
        r = c.post(f"/api/sources/{source['source_id']}/upload",
                   files={"file": ("logs.txt", body.encode(), "text/plain")})
    assert r.json()["parsed"] == 3, "distinct timestamps were collapsed"


# --- Fix 4c: an ALREADY-CONNECTED stream client must be cut off --------------

@pytest.mark.anyio
async def test_live_tcp_connection_cannot_feed_the_buffer_during_shutdown(source):
    """Closing the listening server is not enough.

    asyncio.Server.close() stops NEW connections being accepted. A client that
    connected before shutdown keeps its own transport and can go on sending —
    so records could still enter the buffer while it was being drained, and
    wait_closed() can itself block on those live connections.

    This uses a real TCP server and a real client socket, not a stub, because
    the previous shutdown test substituted a fake transport and therefore
    could not have caught this.
    """
    service = IngestionService(SessionLocal)
    # The client connects from 127.0.0.1; source resolution is not what this
    # test is about, so map any sender to the fixture's source.
    service.resolve_source = lambda _ip: source["source_id"]

    loop = asyncio.get_running_loop()
    real_server = await loop.create_server(
        lambda: listener_mod.SyslogStreamProtocol(service, "TCP"),
        "127.0.0.1", 0)
    port = real_server.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    frame = _msg(1)
    writer.write(str(len(frame)).encode() + b" " + frame)   # RFC 6587 framing
    await writer.drain()
    await asyncio.sleep(0.1)
    assert len(service.buffer) == 1, "the live connection never delivered"
    assert service._stream_transports, "the connection was not registered"

    # Shutdown: refuse new records and close live connections.
    service.stop_accepting()
    real_server.close()
    await asyncio.wait_for(real_server.wait_closed(), timeout=5)

    # The client keeps writing after shutdown began.
    try:
        writer.write(str(len(frame)).encode() + b" " + frame)
        await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass                                   # the server hung up: also fine
    await asyncio.sleep(0.1)

    assert len(service.buffer) == 1, (
        "a live stream connection added records after shutdown began")
    assert not service.accepting

    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionResetError, BrokenPipeError):
        pass


@pytest.mark.anyio
async def test_stream_transports_are_unregistered_when_a_client_disconnects(source):
    """The registry must not grow without bound over a long run."""
    service = IngestionService(SessionLocal)
    service.resolve_source = lambda _ip: source["source_id"]
    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        lambda: listener_mod.SyslogStreamProtocol(service, "TCP"),
        "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    for _ in range(3):
        _r, w = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.02)
        w.close()
        await w.wait_closed()
    await asyncio.sleep(0.1)

    assert service._stream_transports == set(), (
        f"{len(service._stream_transports)} transport(s) still registered "
        "after the clients disconnected")

    server.close()
    await server.wait_closed()


# --- Fix 4d: cancellation must not duplicate or strand a batch ---------------
#
# run_in_executor hands _write to a thread. Cancelling the coroutine that
# awaits it does NOT stop that thread: it runs to completion and may commit.
# Awaiting the future directly therefore allowed:
#
#   flush() cancelled -> exits before removing the prefix
#   thread commits anyway
#   -> records in PostgreSQL AND still in the buffer
#   -> next flush writes them a second time
#
# The fix shields the future so cancellation reaches flush() without
# cancelling the write, waits for the thread's real outcome, reconciles the
# buffer, and only then propagates CancelledError.

@pytest.mark.anyio
async def test_cancelled_flush_reconciles_a_successful_executor_write(service, source):
    """Cancelled mid-write, write COMMITS: stored once, buffer cleared."""
    service.offer(_msg(1), SENDER)
    assert len(service.buffer) == 1

    real_write = service._write
    started = asyncio.Event()
    release = asyncio.Event()
    loop = asyncio.get_running_loop()

    async def _wait():
        await release.wait()

    def _blocking(batch, batch_id, now):
        loop.call_soon_threadsafe(started.set)
        asyncio.run_coroutine_threadsafe(_wait(), loop).result()
        return real_write(batch, batch_id, now)      # actually commits

    service._write = _blocking

    task = asyncio.create_task(service.flush())
    await started.wait()                 # the thread is inside _write
    task.cancel()                        # cancel while it writes
    await asyncio.sleep(0.05)
    release.set()                        # let the commit complete

    with pytest.raises(asyncio.CancelledError):
        await task                       # cancellation must still propagate

    assert service.buffer == [], (
        "the committed prefix was left in the buffer — the next flush would "
        "store it a second time")
    assert len(_stored(source["source_id"])) == 1, "record was written twice"
    assert service.total_write_failures == 0

    # And a subsequent flush must not resurrect it.
    await service.flush()
    assert len(_stored(source["source_id"])) == 1


@pytest.mark.anyio
async def test_cancelled_flush_retains_a_failed_executor_write(service, source):
    """Cancelled mid-write, write FAILS: nothing stored, batch retained."""
    service.offer(_msg(2), SENDER)

    started = asyncio.Event()
    release = asyncio.Event()
    loop = asyncio.get_running_loop()

    async def _wait():
        await release.wait()

    def _failing(batch, batch_id, now):
        loop.call_soon_threadsafe(started.set)
        asyncio.run_coroutine_threadsafe(_wait(), loop).result()
        raise RuntimeError("commit failed")

    service._write = _failing

    task = asyncio.create_task(service.flush())
    await started.wait()
    task.cancel()
    await asyncio.sleep(0.05)
    release.set()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert len(service.buffer) == 1, "a failed write lost the batch"
    assert service.total_write_failures == 1
    assert len(_stored(source["source_id"])) == 0


@pytest.mark.anyio
async def test_cancellation_does_not_leave_the_flush_lock_held(service, source):
    """A cancelled flush must release the lock, or ingestion deadlocks."""
    service.offer(_msg(3), SENDER)

    real_write = service._write
    started = asyncio.Event()
    release = asyncio.Event()
    loop = asyncio.get_running_loop()

    async def _wait():
        await release.wait()

    def _blocking(batch, batch_id, now):
        loop.call_soon_threadsafe(started.set)
        asyncio.run_coroutine_threadsafe(_wait(), loop).result()
        return real_write(batch, batch_id, now)

    service._write = _blocking
    task = asyncio.create_task(service.flush())
    await started.wait()
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert not service._flush_lock.locked(), "the flush lock was left held"
    service.offer(_msg(4), SENDER)
    assert await asyncio.wait_for(service.flush(), timeout=5) is True


# --- Fix 4e: reconciliation must survive REPEATED cancellation ---------------
#
# Fix 4d caught one cancellation, but the `await future` inside that handler
# was itself cancellable, and CancelledError is not an Exception subclass —
# so a second cancel escaped, the executor thread committed anyway, and the
# prefix stayed buffered to be written a second time. Reconciliation is now a
# loop, so the number of cancellations is irrelevant.

async def _cancel_repeatedly(task, times: int) -> None:
    """Cancel the same task several times while it is mid-write."""
    for _ in range(times):
        task.cancel()
        await asyncio.sleep(0)          # let the cancellation be delivered


@pytest.mark.anyio
async def test_repeated_cancellation_reconciles_a_successful_write(service, source):
    """Three cancellations, write COMMITS: stored once, buffer cleared."""
    service.offer(_msg(11), SENDER)

    real_write = service._write
    started = asyncio.Event()
    release = asyncio.Event()
    loop = asyncio.get_running_loop()

    async def _wait():
        await release.wait()

    def _blocking(batch, batch_id, now):
        loop.call_soon_threadsafe(started.set)
        asyncio.run_coroutine_threadsafe(_wait(), loop).result()
        return real_write(batch, batch_id, now)

    service._write = _blocking
    task = asyncio.create_task(service.flush())
    await started.wait()

    await _cancel_repeatedly(task, 3)    # three, not one
    release.set()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert service.buffer == [], (
        "repeated cancellation abandoned a committed prefix — the next flush "
        "would store it again")
    assert len(_stored(source["source_id"])) == 1
    assert service.total_write_failures == 0

    await service.flush()
    assert len(_stored(source["source_id"])) == 1, "duplicate on the next flush"


@pytest.mark.anyio
async def test_repeated_cancellation_retains_a_failed_write(service, source):
    """Three cancellations, write FAILS: nothing stored, batch retained."""
    service.offer(_msg(12), SENDER)

    started = asyncio.Event()
    release = asyncio.Event()
    loop = asyncio.get_running_loop()

    async def _wait():
        await release.wait()

    def _failing(batch, batch_id, now):
        loop.call_soon_threadsafe(started.set)
        asyncio.run_coroutine_threadsafe(_wait(), loop).result()
        raise RuntimeError("commit failed")

    service._write = _failing
    task = asyncio.create_task(service.flush())
    await started.wait()

    await _cancel_repeatedly(task, 3)
    release.set()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert len(service.buffer) == 1, "a failed write lost the batch"
    assert service.total_write_failures == 1
    assert len(_stored(source["source_id"])) == 0
    assert not service._flush_lock.locked()
