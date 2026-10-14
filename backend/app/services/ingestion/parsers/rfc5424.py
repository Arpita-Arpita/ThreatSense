"""RFC 5424 syslog adapter (task 1.7).

Parses the <PRI> header to derive syslog severity (PRI % 8) and an ISO-8601
event timestamp, then extracts flow fields from a key=value message body.
"""
from __future__ import annotations

import re

# Raw values are passed to make_record: it owns validation and bounds, so
# converting here would turn a malformed port into a silent NULL.
from .base import LogParser, kv_pairs, make_record, parse_iso, to_int

_PRI = re.compile(r"^<(\d{1,3})>")


class Rfc5424Parser(LogParser):
    name = "rfc5424"

    def try_parse(self, raw: str) -> dict | None:
        m = _PRI.match(raw)
        if not m:
            return None
        pri = int(m.group(1))
        if pri > 191:          # valid PRI is 0..191
            return None
        f = kv_pairs(raw)
        if not f.get("src") or not f.get("dst"):
            return None
        return make_record(
            src_ip=f.get("src"), dst_ip=f.get("dst"),
            src_port=f.get("sport"), dst_port=f.get("dport"),
            protocol=f.get("proto"), packet_size=to_int(f.get("size")),
            flags=f.get("flags"), connection_outcome=f.get("outcome"),
            syslog_severity=pri % 8, event_time=parse_iso(raw), raw=raw,
        )
