"""Parser-adapter interface + shared helpers (task 1.7).

Each adapter implements try_parse(raw) -> normalized dict | None. It returns a
dict of network_logs fields when it recognises and can parse the line (with at
least src_ip + dst_ip), or None to let the next adapter try. The registry in
__init__.py dispatches to the first adapter that returns a record.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

_ISO_RE = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b"
)


def to_int(value) -> int | None:
    s = "" if value is None else str(value)
    return int(s) if s.isdigit() else None


def kv_pairs(text: str) -> dict[str, str]:
    """Extract key=value tokens, keys lower-cased (for src=/dst= style)."""
    out: dict[str, str] = {}
    for tok in text.split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            if v != "":
                out[k.lower()] = v
    return out


def parse_iso(text: str) -> datetime | None:
    m = _ISO_RE.search(text)
    if not m:
        return None
    raw = m.group(1).replace(" ", "T")
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def to_utc(dt: datetime | None) -> datetime | None:
    """Normalise an event timestamp to UTC (Algorithm 1: CONVERT TO UTC).

    An aware datetime is converted. A NAIVE datetime is ASSUMED to be UTC and
    stamped as such — the forwarding device did not tell us its offset, and
    guessing the collector's local zone would silently shift events by hours
    whenever the two differ. Section 2.2 keeps the original text in
    raw_message, so the un-normalised value remains available for audit.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def make_record(*, src_ip, dst_ip, raw, src_port=None, dst_port=None,
                protocol=None, packet_size=None, flags=None,
                connection_outcome=None, syslog_severity=None,
                event_time=None) -> dict | None:
    """Build a normalized network_logs record, or None if it must be rejected.

    Section 2.2, verbatim:

        "Records are rejected from the scoring pipeline if required
         network-event fields are missing or malformed, including source IP,
         destination IP, protocol, and packet size"

    Two fallbacks used to violate that directly: a missing protocol became
    "UDP" and a missing packet size became len(raw) — the byte length of the
    log line, which is not a packet size at all. Both fabricated values fed
    the feature extractor and therefore the model, so a malformed source could
    quietly shift protocol ratios and packet-size statistics. They are gone.

    IP addresses are parsed here rather than left to PostgreSQL's INET type.
    A malformed address that reaches the database aborts the whole INSERT, and
    with it every valid record batched alongside it — one bad line could take
    out 499 good ones.

    Returning None (rather than raising) keeps the contract adapters already
    use: None means "not usable", and the caller counts it as unparseable.
    """
    if not _valid_ip(src_ip) or not _valid_ip(dst_ip):
        return None

    # Protocol: reject rather than truncate. str(protocol)[:10] silently
    # turned "NOT_A_REAL_PROTOCOL" into "NOT_A_REAL" and stored it as fact,
    # which then feeds tcp_ratio in the feature vector. Section 2.2 says
    # malformed required fields are rejected, and quietly mangling a value is
    # not rejecting it.
    if protocol is None:
        return None
    proto = str(protocol).strip()
    if not proto or len(proto) > _PROTOCOL_MAX_LEN:
        return None

    # Numeric bounds are the DATABASE's bounds, checked here. Anything the
    # schema will refuse must never reach a batch: since a failed write now
    # RETAINS its records for retry, one out-of-range value would be retried
    # forever and block every record queued behind it. Durability turned a
    # "lose 500 rows" bug into a "wedge ingestion permanently" bug, so the
    # validation has to be complete.
    size = _bounded_int(packet_size, 1, _PG_INT_MAX)
    if size is None:
        return None
    src_port = _optional_bounded(src_port, 0, 65535)
    if src_port is _INVALID:
        return None
    dst_port = _optional_bounded(dst_port, 0, 65535)
    if dst_port is _INVALID:
        return None
    syslog_severity = _optional_bounded(syslog_severity, 0, 7)
    if syslog_severity is _INVALID:
        return None

    return {
        "src_ip": str(src_ip),
        "dst_ip": str(dst_ip),
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "packet_size": size,
        "flags": flags[:20] if flags else None,
        "connection_outcome": connection_outcome[:20] if connection_outcome else None,
        "syslog_severity": syslog_severity,
        "raw_message": raw[:4000],
        "event_time": to_utc(event_time),
    }


# schema.sql: protocol VARCHAR(10); packet_size / ports / severity INTEGER
# with CHECK (src_port BETWEEN 0 AND 65535).
_PROTOCOL_MAX_LEN = 10
_PG_INT_MAX = 2_147_483_647
_INVALID = object()          # sentinel: "supplied but out of range"


def _bounded_int(value, low: int, high: int):
    """Parse an integer and require low <= n <= high, else None."""
    n = to_int(value)
    if n is None or n < low or n > high:
        return None
    return n


def _optional_bounded(value, low: int, high: int):
    """None stays None; a supplied value must be in range or _INVALID.

    The distinction matters: an absent port is legitimate (Section 2.2 marks
    ports NULLABLE), but a port of 70000 is a malformed record, not an
    absent one, and must not be silently dropped to NULL.
    """
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    n = _bounded_int(value, low, high)
    return _INVALID if n is None else n


def _valid_ip(value) -> bool:
    """True when value parses as an IPv4 or IPv6 address.

    IPv6 is accepted: the source-creation schema already accepts it, so
    rejecting it here would make the two disagree about what a valid address
    is.
    """
    if value is None:
        return False
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


# Fields that make two records "identical" for the in-batch deduplication
# Section 2.2 requires. Deliberately the whole normalised record: deduplicating
# on src+dst alone would delete legitimate repeated packets between the same
# pair, which is exactly what a flood looks like.
_FINGERPRINT_FIELDS = (
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packet_size",
    "flags", "connection_outcome", "syslog_severity", "raw_message",
    "event_time",
)


def fingerprint(rec: dict) -> tuple | None:
    """Deterministic identity of a normalised record, or None if undecidable.

    Shared by the live listener and the file-upload path so the two cannot
    drift — Section 2.2 puts deduplication under "Preprocessing (all
    formats)", not under the listener alone.

    DELIBERATE NARROWING, and why it is not just spec-dodging.

    Section 2.2 says "Deduplication is performed inside each batch for
    identical records". Applied literally to a record with no event
    timestamp, that deletes real traffic: a SYN flood is by nature a burst of
    byte-identical packets, and packets_per_sec is precisely how the rule
    layer recognises DDOS (Section 2.3). Collapsing them would erase the
    signal the detector exists to find — the system would grow blind to an
    attack in proportion to how hard it was being hit.

    What deduplication is actually for is redelivery: the same event arriving
    twice, which happens with syslog retransmission and with a log file
    uploaded twice. When the forwarding device supplies a timestamp, those
    two cases are distinguishable — a redelivered event repeats its
    timestamp, whereas two genuine packets are two moments.

    So dedup applies only to records that carry an event_time. Returning None
    means "cannot be judged a duplicate", and the caller stores the record.
    Timestamp-less sources are the ones our own Kali iptables feed produces,
    so this is the common path, not an edge case.
    """
    if rec.get("event_time") is None:
        return None
    return tuple(rec.get(f) for f in _FINGERPRINT_FIELDS) + (rec.get("source_id"),)


class LogParser:
    """Base adapter. Subclasses set `name` and implement try_parse()."""

    name = "base"

    def try_parse(self, raw: str) -> dict | None:
        raise NotImplementedError
