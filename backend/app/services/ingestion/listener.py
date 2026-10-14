"""
Syslog ingestion worker (tasks 1.6, 6.2) — runs as a SEPARATE process from the API.

Listens on three transports, all feeding one shared buffer and flush path:

  TLS  / TCP 6514  (task 6.2, NFR-04)  — RFC 5425 Syslog over TLS. The
                                          encrypted path the requirement wants.
  UDP  / 1514      (task 1.6)          — testing only, per NFR-04's "may be
                                          used only within the isolated
                                          testing environment".
  TCP  / 1601      (off by default)    — plaintext RFC 6587, for isolating
                                          whether a fault is TLS-related.

An asyncio listener that receives syslog messages, buffers parsed records
in memory, and flushes them into network_logs in batches per Algorithm 1:
flush when the buffer reaches SYSLOG_FLUSH_BATCH records OR every
SYSLOG_FLUSH_SECONDS, whichever comes first. Each flush is tagged with one
batch_id and rows land with is_analysed = FALSE for the detection engine.

Design notes:
  • Datagrams are buffered synchronously inside the event-loop callback (no
    per-packet task, no lock) so the socket drains fast and we don't drop under
    burst. The blocking DB write is offloaded to a thread executor so receiving
    never stalls behind a flush.
  • The UDP receive buffer (SO_RCVBUF) is enlarged to absorb bursts.

Run it (from backend/, venv active, DB up):
    python -m app.services.ingestion.listener

NOTE: parsing is intentionally minimal (key=value body). Task 1.7 formalises
this into pluggable parser adapters; 1.6 is about the buffer/flush machinery.
"""
from __future__ import annotations

import asyncio
import json
import logging
import signal
import socket
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.models import DataSource, NetworkLog, SourceStatus, TransportType
from app.services.ingestion.framing import FrameDecoder, FrameError
from app.services.ingestion.parsers import parse as parse_log
from app.services.ingestion.parsers.base import fingerprint
from app.services.ingestion.tls import TLSConfigError, build_server_context, describe

logging.basicConfig(level=logging.INFO, format="%(asctime)s ingest %(levelname)s %(message)s")
logger = logging.getLogger("threatsense.ingest")

engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

RCVBUF_BYTES = 4 * 1024 * 1024  # 4 MiB UDP receive buffer



class IngestionService:
    def __init__(self, session_factory) -> None:
        self.session_factory = session_factory
        self.buffer: list[dict] = []
        self._by_ip: dict[str, uuid.UUID] = {}
        self._single_source_id: uuid.UUID | None = None
        # Addresses registered by more than one source. Traffic from these is
        # dropped rather than guessed at — see refresh_sources().
        self._ambiguous_ips: set[str] = set()
        # Drops are counted BY CAUSE and logged each flush cycle. Before 6.2
        # this was a single counter that was never logged or exposed, so a
        # misconfigured sender IP produced 100% silent data loss — that cost
        # two complete NFR-01 runs during 6.1 before the cause was found.
        # An operator must be able to see rejected traffic.
        self.dropped_unknown_source = 0
        self.dropped_unparseable = 0
        self.dropped_duplicate = 0
        # Records whose source row disappeared between buffering and the write.
        # Counted separately because the cause and the fix differ from an
        # unregistered sender: the admin deleted the source mid-flight.
        self.dropped_stale_source = 0
        # Records whose source was RECONFIGURED between buffering and the
        # write so that it no longer matches the endpoint the message arrived
        # on. Distinct from a stale source (which was deleted) and from an
        # unknown sender (which never resolved at all).
        self.dropped_endpoint_mismatch = 0
        self._unknown_senders: set[str] = set()
        # Process-lifetime totals. The counters above are reset every flush
        # cycle by log_drops(), so they cannot answer "how much has been lost
        # since this listener started" — which is the question /health needs
        # to answer. These are never reset.
        self.total_dropped_unknown_source = 0
        self.total_dropped_unparseable = 0
        self.total_dropped_duplicate = 0
        self.total_dropped_stale_source = 0
        self.total_dropped_endpoint_mismatch = 0
        self.total_write_failures = 0
        self.total_ingested = 0
        # Only one flush may touch the buffer at a time. The listener starts a
        # flush task from every transport callback as soon as the batch size is
        # reached (see offer), so without this two flushes can overlap: both
        # snapshot the same records and both write them, storing each row
        # twice.
        self._flush_lock = asyncio.Lock()
        # Single-flight scheduler for size-triggered flushes. Each transport
        # callback used to do asyncio.create_task(flush()) whenever offer()
        # reported a full buffer — and because the durable flush keeps records
        # in the buffer until the write succeeds, offer() keeps reporting
        # "full" for every message that arrives during the write. One slow
        # write at NFR-01's 1,000 msg/s therefore created ~1,000 tasks, all
        # queued on the lock, doing nothing but consuming memory. NFR-01 asks
        # for ingestion "without data loss or queue overflow"; that was a
        # queue overflow of our own making.
        self._flush_task: asyncio.Task | None = None
        # Shutdown gate. Closing the listening asyncio.Server stops NEW
        # connections; it does not stop an ALREADY-CONNECTED syslog client
        # from continuing to send. Without this, records could still enter
        # the buffer during the final drain and be lost on exit.
        self.accepting = True
        # Live TCP/TLS connection transports, so shutdown can close the
        # connections themselves rather than only the listener.
        self._stream_transports: set = set()
        # Fingerprint -> count for the records currently buffered, so the
        # duplicate check Section 2.2 requires is O(1) rather than a scan of
        # the buffer on every message. Kept in step with the buffer on both
        # append and prefix removal.
        self._pending: Counter = Counter()
        self.started_at = datetime.now(timezone.utc)
        self.refresh_sources()

    def register_stream_transport(self, transport) -> None:
        self._stream_transports.add(transport)

    def unregister_stream_transport(self, transport) -> None:
        self._stream_transports.discard(transport)

    def stop_accepting(self) -> None:
        """Refuse new records and close every live stream connection.

        Called at the start of shutdown, before the final drain, so the
        buffer cannot grow while it is being emptied.
        """
        self.accepting = False
        for transport in list(self._stream_transports):
            try:
                transport.close()
            except Exception:                     # pragma: no cover
                pass
        self._stream_transports.clear()

    @property
    def dropped(self) -> int:
        """Total drops across both causes (kept for existing callers)."""
        return self.dropped_unknown_source + self.dropped_unparseable

    def log_drops(self) -> None:
        """Emit and reset the drop counters. Called once per flush cycle."""
        if not (self.dropped or self.dropped_duplicate
                or self.dropped_stale_source or self.dropped_endpoint_mismatch):
            return
        if self.dropped_unknown_source:
            senders = ", ".join(sorted(self._unknown_senders)) or "unknown"
            logger.warning(
                "DROPPED %d message(s) from unregistered sender(s): %s — add the "
                "address to data_sources.ip_address or these are discarded",
                self.dropped_unknown_source, senders)
        if self.dropped_unparseable:
            logger.warning("DROPPED %d unparseable message(s)", self.dropped_unparseable)
        if self.dropped_duplicate:
            logger.info("suppressed %d duplicate message(s) within the pending batch",
                        self.dropped_duplicate)
        self.dropped_unknown_source = 0
        self.dropped_unparseable = 0
        self.dropped_duplicate = 0
        self.dropped_stale_source = 0
        self.dropped_endpoint_mismatch = 0
        self._unknown_senders.clear()

    def write_stats(self) -> None:
        """Publish ingestion telemetry for the API process to read.

        The listener and the API are separate processes with no shared memory,
        so /health cannot reach these counters directly. Written once per
        flush cycle, after log_drops() has emitted and reset the per-cycle
        counters — the totals below are lifetime figures and are unaffected
        by that reset.

        Written to a temporary file and moved into place, so a reader can
        never observe a half-written file. Failure is logged and swallowed:
        telemetry must not be able to stop ingestion.
        """
        path = Path(settings.ingestion_stats_path)
        payload = {
            "listener_started_at": self.started_at.isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "ingested_total": self.total_ingested,
            "dropped_total": (self.total_dropped_unknown_source
                              + self.total_dropped_unparseable),
            "dropped_unknown_source_total": self.total_dropped_unknown_source,
            "dropped_unparseable_total": self.total_dropped_unparseable,
            "dropped_duplicate_total": self.total_dropped_duplicate,
            "dropped_stale_source_total": self.total_dropped_stale_source,
            "dropped_endpoint_mismatch_total": self.total_dropped_endpoint_mismatch,
            # A failed database write no longer loses the batch, but it does
            # mean records are sitting unpersisted. /health previously showed
            # zero drops after a write failure had discarded data outright.
            "write_failures_total": self.total_write_failures,
            "buffered_now": len(self.buffer),
        }
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            tmp.replace(path)                    # atomic on POSIX
        except OSError as exc:
            logger.warning("could not write ingestion stats to %s: %s", path, exc)

    def refresh_sources(self) -> None:
        """Rebuild the sender-IP -> source map.

        Two attribution defects were fixed here, both at the point where a
        packet is bound to an owner:

        AMBIGUITY. The map was a plain dict comprehension, so when two
        administrators registered the same private address (192.168.1.1 is not
        unique across networks) the later row silently overwrote the earlier
        one and one admin's traffic was filed under the other's source — a
        cross-tenant data leak produced by dict ordering. Addresses claimed by
        more than one source are now excluded from the map entirely and logged.
        Refusing to attribute is the only safe answer: nothing in a syslog
        packet distinguishes the two, so any choice would be a guess, and the
        brief is explicit that a record must never be silently reassigned to
        another administrator.

        FALLBACK SCOPE. `_single_source_id` accepted traffic from ANY sender
        whenever exactly one source existed, so an unregistered host could
        write into that source. The fallback now applies only when the single
        source has no ip_address configured — i.e. when there is genuinely
        nothing to match against. A source that declares an address is held to
        it.
        """
        with self.session_factory() as s:
            sources = s.scalars(select(DataSource)).all()

        by_ip: dict[str, uuid.UUID] = {}
        claims: Counter = Counter()
        for src in sources:
            if not src.ip_address:
                continue
            ip = str(src.ip_address)
            claims[ip] += 1
            by_ip[ip] = src.source_id

        self._ambiguous_ips = {ip for ip, n in claims.items() if n > 1}
        for ip in self._ambiguous_ips:
            by_ip.pop(ip, None)
        if self._ambiguous_ips:
            logger.warning(
                "%d sender address(es) are registered by more than one source "
                "(%s) — traffic from them cannot be attributed and is dropped. "
                "Give each source a distinct ip_address.",
                len(self._ambiguous_ips), ", ".join(sorted(self._ambiguous_ips)))

        self._by_ip = by_ip
        # Fallback ONLY for a lone source with no address to check against.
        self._single_source_id = (
            sources[0].source_id
            if len(sources) == 1 and not sources[0].ip_address
            else None
        )

    def resolve_source(self, sender_ip: str) -> uuid.UUID | None:
        """Sender address -> owning source, or None when it cannot be decided.

        None means the message is dropped and counted. That is deliberate for
        the ambiguous case: attributing it to either candidate would put one
        administrator's network traffic in another administrator's account.
        """
        if sender_ip in self._ambiguous_ips:
            return None
        return self._by_ip.get(sender_ip) or self._single_source_id

    def offer(self, data: bytes, sender_ip: str,
              transport: TransportType | None = None,
              listener_port: int | None = None) -> bool:
        """Buffer one message (runs on the event loop). Returns True if full.

        Shared by all three transports — UDP datagrams and TLS/TCP frames are
        identical once framing has been stripped, so buffering, batching and
        the flush path are common to all of them.

        The sender address, the transport it arrived on and the listener port
        that received it are carried ON the buffered record. Without them the
        write boundary can only ask "does this source id still exist", which
        is not the same question as "does this record still belong to that
        source" — see _write().
        """
        if not self.accepting:
            # Shutting down: the buffer is being drained and must not grow.
            # Dropping here is deliberate and preferable to accepting a
            # record that would never be persisted.
            return False
        source_id = self.resolve_source(sender_ip)
        if source_id is None:
            self.dropped_unknown_source += 1
            self.total_dropped_unknown_source += 1
            self._unknown_senders.add(sender_ip)
            return False
        rec = parse_log(data.decode(errors="replace"))
        if rec is None:
            self.dropped_unparseable += 1
            self.total_dropped_unparseable += 1
            return False
        rec["source_id"] = source_id
        # Resolution evidence, revalidated at the write boundary. Not columns
        # in network_logs — these exist only for the lifetime of the buffer.
        rec["_sender_ip"] = sender_ip
        rec["_transport"] = transport
        rec["_listener_port"] = listener_port

        # Section 2.2: "Deduplication is performed inside each batch for
        # identical records." Identity is the whole normalised record (see
        # parsers.base.fingerprint), not src+dst — a flood is legitimately
        # many packets between the same pair, and deduplicating on the pair
        # alone would delete the very traffic the detector needs.
        fp = fingerprint(rec)
        if fp is not None and self._pending[fp]:
            self.dropped_duplicate += 1
            self.total_dropped_duplicate += 1
            return len(self.buffer) >= settings.syslog_flush_batch
        if fp is not None:
            self._pending[fp] += 1
        self.buffer.append(rec)
        return len(self.buffer) >= settings.syslog_flush_batch

    def request_flush(self) -> None:
        """Ask for a size-triggered flush; at most one worker is ever pending.

        Called from the transport callbacks instead of create_task(flush()).
        If a worker is already running, this is a no-op: that worker re-checks
        the buffer when its write completes and drains any batch that piled up
        meanwhile, so no message goes unflushed and no second task is created.
        """
        if self._flush_task is not None and not self._flush_task.done():
            return
        self._flush_task = asyncio.create_task(self._drain_full_batches())

    async def _drain_full_batches(self) -> None:
        """Flush while full batches remain, then stop.

        Bounded by design: each pass either persists a batch (shrinking the
        buffer) or fails (in which case flush() has retained the records and
        we stop, leaving the retry to the periodic cycle rather than spinning
        on a database that is down).
        """
        while len(self.buffer) >= settings.syslog_flush_batch:
            if not await self.flush():
                # The write failed and flush() retained the records. Stop
                # rather than spin against a database that is down; the
                # periodic cycle retries.
                return
            # Loop again: another full batch may have accumulated WHILE that
            # write was in flight. Comparing buffer lengths to detect this
            # was the bug — a successful write plus three new arrivals leaves
            # the buffer the same size, which read as failure and abandoned a
            # full batch.

    async def wait_for_pending_flush(self) -> None:
        """Await the scheduled worker, if any. Used by the shutdown drain."""
        task = self._flush_task
        if task is not None and not task.done():
            try:
                await task
            except asyncio.CancelledError:
                raise
            except Exception:            # pragma: no cover - logged in flush()
                pass

    async def flush(self) -> bool:
        """Persist buffered records, then remove exactly what was persisted.

        Returns True when the write succeeded (or there was nothing to do),
        False when it failed and the records were retained. The caller must
        NOT infer success from the buffer shrinking: messages keep arriving
        during the awaited write, so a successful flush can leave the buffer
        the same size or larger. _drain_full_batches() made exactly that
        mistake and stopped draining after a successful write.

        DURABILITY. The previous implementation cleared the buffer BEFORE the
        database write and handed the only copy to an executor. Any failure in
        _write — a malformed value, a dropped connection, the database being
        restarted — destroyed the whole batch with no record that it had
        happened. Up to syslog_flush_batch records could vanish while /health
        still reported zero drops, directly contradicting NFR-01's "without
        data loss".

        CONCURRENCY. Writing first and then clearing is not sufficient on its
        own, and is the trap this method is shaped to avoid:

          * offer() appends while the write is awaited, so buffer.clear()
            after a write discards records that were never persisted;
          * every transport can start a flush task the moment the batch size
            is reached, so two flushes can snapshot the same records and store
            each of them twice.

        Both are solved by holding a lock for the whole operation and removing
        a PREFIX of exactly the length that was written. Anything appended
        during the write sits after that prefix and survives untouched.
        """
        async with self._flush_lock:
            if not self.buffer:
                return True
            batch = list(self.buffer)          # snapshot a prefix
            batch_len = len(batch)
            batch_id = uuid.uuid4()
            now = datetime.now(timezone.utc)
            # CANCELLATION SAFETY. run_in_executor hands the write to a
            # thread, and cancelling the awaiting coroutine does NOT stop that
            # thread — it will run to completion and may commit. Awaiting the
            # future directly meant a cancelled flush could exit before
            # removing the prefix while the thread committed it anyway,
            # leaving the records both in PostgreSQL and in the buffer, to be
            # written a second time by the next flush.
            #
            # shield() lets the cancellation reach us without cancelling the
            # future, so we can wait for the thread's actual outcome, act on
            # it, and only then propagate the cancellation. The invariant is:
            # once _write has started, we never exit uncertain whether the
            # prefix committed.
            future = asyncio.get_running_loop().run_in_executor(
                None, self._write, batch, batch_id, now)
            cancelled = False

            # Wait for a DEFINITE outcome, however many times we are
            # cancelled. A single try/except handled one cancellation, but
            # the `await future` inside that handler was itself cancellable
            # and CancelledError is not an Exception subclass — so a second
            # cancel escaped, the thread committed anyway, and the prefix
            # stayed buffered to be written twice. The loop makes the number
            # of cancellations irrelevant.
            while not future.done():
                try:
                    await asyncio.shield(future)
                except asyncio.CancelledError:
                    cancelled = True
                    continue                 # keep waiting for the thread
                except Exception:
                    break                    # outcome is known; read it below

            try:
                future.result()
            except Exception as exc:
                # Keep the records. A later flush retries them, so a transient
                # database outage delays ingestion instead of losing it.
                self._note_write_failure(batch_len, batch_id, exc)
                if cancelled:
                    raise asyncio.CancelledError from None
                return False

            # Remove ONLY the persisted prefix, and drop its fingerprints so
            # an identical message arriving later is stored again — the
            # dedup window is the pending batch, per Section 2.2, not forever.
            for rec in batch:
                fp = fingerprint(rec)
                if fp is None:
                    continue
                self._pending[fp] -= 1
                if self._pending[fp] <= 0:
                    del self._pending[fp]
            del self.buffer[:batch_len]

            self.total_ingested += batch_len
            logger.info("flushed %d records (batch %s)", batch_len, batch_id)
            if cancelled:
                # The write committed and the buffer is consistent with the
                # database; only now is it safe to honour the cancellation.
                raise asyncio.CancelledError
            return True

    def _note_write_failure(self, batch_len: int, batch_id: uuid.UUID,
                            exc: BaseException) -> None:
        """Record a failed batch write without logging the exception text.

        Type and SQLSTATE only — never str(exc). A SQLAlchemy error renders
        the failing statement and its bound parameters, and those parameters
        are network_logs rows including raw_message, which is
        attacker-controlled Syslog content. Same principle already applied to
        password-reset delivery.
        """
        self.total_write_failures += 1
        sqlstate = getattr(getattr(exc, "orig", None), "sqlstate", None)
        logger.error(
            "flush failed, %d records retained for retry "
            "(batch %s, error %s, sqlstate %s)",
            batch_len, batch_id, type(exc).__name__, sqlstate or "n/a")

    def _still_matches(self, src: DataSource, rec: dict) -> bool:
        """Does this buffered record still belong to this source?

        Resolution happens when a message is buffered; the write happens up to
        five seconds later. In between, an administrator can EDIT the source —
        point it at a different address, or change its transport — and the
        source id remains perfectly valid. Checking only that the id still
        exists therefore answers the wrong question, and the record lands under
        a source that no longer claims the endpoint it came from.

        Each configured field is checked; each unconfigured field is skipped.
        A source with no ip_address has not asserted an address, so there is
        nothing to contradict — that is the address-less single-source
        deployment the fallback in resolve_source() exists for, and it must
        keep working.

        Returns False to DROP the record. It is never reassigned to whichever
        source now owns the address: that would move one administrator's
        traffic into another's account, the same failure the ambiguous-address
        handling exists to prevent.
        """
        sender_ip = rec.get("_sender_ip")
        if src.ip_address and sender_ip and str(src.ip_address) != sender_ip:
            return False

        transport = rec.get("_transport")
        if src.transport and transport is not None and src.transport != transport:
            return False

        listener_port = rec.get("_listener_port")
        if src.port and listener_port is not None and src.port != listener_port:
            return False

        return True

    def _write(self, batch: list[dict], batch_id: uuid.UUID, now: datetime) -> None:
        """Persist one batch, revalidating each record's source first.

        STALE SOURCE. A record is bound to a source when it is buffered, but
        the admin can delete that source during the five seconds before the
        flush. The insert then violates network_logs.source_id's foreign key,
        and because flush() correctly RETAINS a failed batch for retry, the
        same doomed row was re-submitted every cycle forever: one deleted
        source wedged all ingestion, including every valid record queued behind
        it. NFR-01 asks for ingestion without data loss, and an ingestion path
        that has stopped moving loses everything that arrives after it.

        The fix is local and runs inside the same session as the insert, so
        there is no window between the check and the write: source ids still
        present are selected, records naming anything else are dropped and
        counted, and the remainder commits. One bad record can no longer block
        the batch it happens to share.
        """
        touched = {r["source_id"] for r in batch}
        with self.session_factory() as s:
            sources = {src.source_id: src for src in s.scalars(
                select(DataSource).where(DataSource.source_id.in_(touched))
            )}

            kept, stale, mismatched = [], set(), set()
            for rec in batch:
                src = sources.get(rec["source_id"])
                if src is None:
                    stale.add(rec["source_id"])
                    continue
                if not self._still_matches(src, rec):
                    mismatched.add(rec["source_id"])
                    continue
                kept.append(rec)

            if stale:
                dropped = sum(1 for r in batch if r["source_id"] in stale)
                self.dropped_stale_source += dropped
                self.total_dropped_stale_source += dropped
                logger.warning(
                    "DROPPED %d buffered record(s): their data source was "
                    "deleted before the flush (source id(s): %s)",
                    dropped, ", ".join(str(x) for x in sorted(stale, key=str)))
            if mismatched:
                dropped = len(batch) - len(kept) - sum(
                    1 for r in batch if r["source_id"] in stale)
                self.dropped_endpoint_mismatch += dropped
                self.total_dropped_endpoint_mismatch += dropped
                logger.warning(
                    "DROPPED %d buffered record(s): their data source was "
                    "reconfigured before the flush and no longer matches the "
                    "endpoint the message arrived on (source id(s): %s)",
                    dropped, ", ".join(str(x) for x in sorted(mismatched, key=str)))

            batch = kept
            touched = {r["source_id"] for r in batch}
            if not batch:
                return

            rows = [
                NetworkLog(
                    source_id=r["source_id"], batch_id=batch_id,
                    src_ip=r["src_ip"], dst_ip=r["dst_ip"],
                    src_port=r["src_port"], dst_port=r["dst_port"],
                    protocol=r["protocol"], packet_size=r["packet_size"],
                    flags=r["flags"], connection_outcome=r["connection_outcome"],
                    syslog_severity=r["syslog_severity"], raw_message=r["raw_message"],
                    timestamp=r.get("event_time") or now, is_analysed=False,
                )
                for r in batch
            ]
            s.add_all(rows)
            for src in s.scalars(select(DataSource).where(DataSource.source_id.in_(touched))):
                src.last_received = now
                src.status = SourceStatus.ACTIVE
            s.commit()


class SyslogProtocol(asyncio.DatagramProtocol):
    """UDP transport (task 1.6). One datagram = one message; no framing needed."""

    def __init__(self, service: IngestionService) -> None:
        self.service = service

    def datagram_received(self, data: bytes, addr) -> None:
        if self.service.offer(data, addr[0], TransportType.UDP,
                              settings.syslog_port):
            self.service.request_flush()


class SyslogStreamProtocol(asyncio.Protocol):
    """TCP transport, with or without TLS (task 6.2).

    TCP is a byte stream, so message boundaries come from RFC 6587 framing —
    see framing.py. One FrameDecoder per connection, because the partial
    remainder between reads is per-peer state.

    When TLS is active, asyncio completes the handshake before calling
    connection_made, so peercert and cipher are already available here.
    """

    # Which configured endpoint this listener represents, so a buffered record
    # can be revalidated against data_sources.transport / .port at the write
    # boundary (see IngestionService._still_matches).
    _ENDPOINT = {
        "TLS": (TransportType.TLS, "syslog_tls_port"),
        "TCP": (TransportType.TCP, "syslog_tcp_port"),
    }

    def __init__(self, service: IngestionService, transport_label: str) -> None:
        self.service = service
        self.transport_label = transport_label
        kind, port_setting = self._ENDPOINT[transport_label]
        self.transport_kind = kind
        self.listener_port = getattr(settings, port_setting)
        self.decoder = FrameDecoder(max_frame_bytes=settings.syslog_max_frame_bytes)
        self.peer = "?"
        self._transport: asyncio.Transport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport                      # type: ignore[assignment]
        # Registered so shutdown can close live connections. Closing the
        # asyncio.Server only stops new ones being accepted.
        self.service.register_stream_transport(transport)
        peername = transport.get_extra_info("peername")
        self.peer = peername[0] if peername else "?"

        cipher = transport.get_extra_info("cipher")
        if cipher:
            # Logged per connection: this line is the NFR-04 evidence that a
            # real handshake happened and at which version.
            name, version, _bits = cipher
            logger.info("%s connection from %s (%s, %s)",
                        self.transport_label, self.peer, version, name)
        else:
            logger.info("%s connection from %s (plaintext)",
                        self.transport_label, self.peer)

    def data_received(self, data: bytes) -> None:
        try:
            messages = self.decoder.feed(data)
        except FrameError as exc:
            # A corrupt stream cannot be resynchronised — there is no way to
            # find the next boundary. Close rather than risk writing fragments
            # into network_logs as though they were whole records.
            logger.warning("%s framing error from %s: %s — closing connection",
                           self.transport_label, self.peer, exc)
            if self._transport is not None:
                self._transport.close()
            return

        full = False
        for message in messages:
            if self.service.offer(message, self.peer, self.transport_kind,
                                  self.listener_port):
                full = True
        if full:
            self.service.request_flush()

    def connection_lost(self, exc: Exception | None) -> None:
        if self._transport is not None:
            self.service.unregister_stream_transport(self._transport)
        if self.decoder.pending_bytes:
            # A truncated final message is worth surfacing: it usually means
            # the sender was killed mid-write, and the bytes are discarded.
            logger.warning("%s connection from %s closed with %d unframed byte(s) "
                           "discarded", self.transport_label, self.peer,
                           self.decoder.pending_bytes)
        if exc is not None and not isinstance(exc, ConnectionResetError):
            # ECONNRESET is what a sender that closes without a TLS shutdown
            # produces, which is routine and not worth a warning. Anything
            # else means the connection failed for a reason worth seeing.
            logger.warning("%s connection from %s lost: %s",
                           self.transport_label, self.peer, exc)


async def start_udp(service: IngestionService) -> asyncio.DatagramTransport:
    """UDP 1514 — testing transport (task 1.6).

    Returns the transport so main() can CLOSE it before the shutdown drain.
    It previously discarded the handle, which meant traffic kept arriving
    during the final flush and any late record was left buffered and lost.
    """
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: SyslogProtocol(service),
        local_addr=(settings.syslog_host, settings.syslog_port),
    )
    sock = transport.get_extra_info("socket")
    if sock is not None:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF_BYTES)
        except OSError:
            pass
    logger.info("  UDP  %s:%-5d  testing only (NFR-04 permits 514/1514 in the "
                "isolated test environment)", settings.syslog_host, settings.syslog_port)
    return transport


async def start_tls(service: IngestionService) -> asyncio.Server:
    """TLS on TCP 6514 — RFC 5425 (task 6.2, NFR-04)."""
    context = build_server_context(
        certfile=settings.syslog_tls_certfile,
        keyfile=settings.syslog_tls_keyfile,
        min_version=settings.syslog_tls_min_version,
        ca_file=settings.syslog_tls_ca_file or None,
        require_client_cert=settings.syslog_tls_require_client_cert,
    )
    server = await asyncio.get_running_loop().create_server(
        lambda: SyslogStreamProtocol(service, "TLS"),
        host=settings.syslog_host, port=settings.syslog_tls_port,
        ssl=context,
    )
    logger.info("  TLS  %s:%-5d  RFC 5425 syslog-over-TLS (%s)",
                settings.syslog_host, settings.syslog_tls_port, describe(context))
    return server


async def start_tcp(service: IngestionService) -> asyncio.Server:
    """Plaintext TCP — RFC 6587, diagnostics only."""
    server = await asyncio.get_running_loop().create_server(
        lambda: SyslogStreamProtocol(service, "TCP"),
        host=settings.syslog_host, port=settings.syslog_tcp_port,
    )
    logger.warning("  TCP  %s:%-5d  PLAINTEXT — diagnostics only, not an NFR-04 "
                   "transport", settings.syslog_host, settings.syslog_tcp_port)
    return server


async def main() -> None:
    service = IngestionService(SessionLocal)
    logger.info("Syslog listener starting (flush: %ds / %d records)",
                settings.syslog_flush_seconds, settings.syslog_flush_batch)

    udp_transport = await start_udp(service)
    tls_server: asyncio.Server | None = None
    tcp_server: asyncio.Server | None = None

    if settings.syslog_tls_enabled:
        try:
            tls_server = await start_tls(service)
        except TLSConfigError as exc:
            # Fatal by design. Falling back to plaintext when the certificate
            # is missing would quietly void the NFR-04 evidence, so refuse to
            # start instead — but say exactly what is wrong and how to fix it.
            logger.error("TLS listener could not start:\n%s", exc)
            logger.error("Set SYSLOG_TLS_ENABLED=false to run without it.")
            raise SystemExit(1)
    else:
        logger.warning("  TLS  disabled (SYSLOG_TLS_ENABLED=false) — NFR-04's "
                       "encrypted transport is NOT active")

    if settings.syslog_tcp_enabled:
        tcp_server = await start_tcp(service)

    # Algorithm 1 ends with a final flush after the loop stops:
    #     IF buffer IS NOT empty THEN BULK INSERT buffer INTO network_logs
    # There was no such path. Whatever sat in the buffer at shutdown — up to
    # syslog_flush_batch records, or a partial batch waiting on the 5-second
    # timer — was simply lost. SIGTERM matters as much as SIGINT here: that is
    # what Docker and systemd send, so covering only Ctrl-C would lose the
    # buffer on every ordinary container stop.
    stopping = asyncio.Event()

    def _request_stop(signame: str) -> None:
        logger.info("%s received — draining the ingestion buffer", signame)
        stopping.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _request_stop, sig.name)
        except (NotImplementedError, RuntimeError):  # pragma: no cover
            # Platforms without signal handlers (or a non-main thread) fall
            # back to the KeyboardInterrupt path below.
            pass

    try:
        while not stopping.is_set():
            try:
                await asyncio.wait_for(stopping.wait(),
                                       timeout=settings.syslog_flush_seconds)
            except asyncio.TimeoutError:
                pass                      # normal cycle: the interval elapsed
            await service.flush()
            service.log_drops()          # surface rejected traffic (see log_drops)
            service.write_stats()        # publish counters for /health to read
            service.refresh_sources()
    finally:
        # Runs on graceful stop AND on an unexpected exception, because a
        # crash should not be the one path that discards buffered records.
        #
        # ORDER MATTERS. Draining while the sockets are still open does not
        # terminate: offer() keeps appending during the awaited write, so a
        # record arriving mid-drain is correctly retained by the prefix
        # algorithm and then discarded when the process exits. Stop accepting
        # traffic FIRST, then drain what is left.
        # 1. Refuse new records and close live TCP/TLS connections. Closing
        #    only the listening server leaves already-connected clients free
        #    to keep sending into the buffer while it is being drained — and
        #    wait_closed() can itself block on those connections.
        service.stop_accepting()
        udp_transport.close()

        # 2. Stop accepting new connections, then wait — bounded, because the
        #    live connections were closed above.
        for server in (tls_server, tcp_server):
            if server is not None:
                server.close()
                try:
                    await asyncio.wait_for(server.wait_closed(), timeout=5)
                except Exception:                            # pragma: no cover
                    logger.warning("listener did not close cleanly; continuing "
                                   "to the final drain")

        # Let any in-flight size-triggered worker finish before the final
        # flush, so the two do not contend for the lock.
        await service.wait_for_pending_flush()

        pending = len(service.buffer)
        if pending:
            logger.info("final flush: %d buffered record(s)", pending)
        await service.flush()
        service.log_drops()
        service.write_stats()
        if service.buffer:
            # Only reachable if the write itself failed — nothing can be
            # arriving now, the listeners are closed.
            logger.error(
                "listener stopping with %d record(s) still unpersisted — the "
                "final database write failed", len(service.buffer))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("listener stopped")
