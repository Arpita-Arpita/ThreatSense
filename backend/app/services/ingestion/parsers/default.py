"""Default adapter: generic key=value body (task 1.7)."""
from __future__ import annotations

# Raw values are passed to make_record: it owns validation and bounds, so
# converting here would turn a malformed port into a silent NULL.
from .base import LogParser, kv_pairs, make_record, to_int


class KeyValueParser(LogParser):
    name = "keyvalue"

    def try_parse(self, raw: str) -> dict | None:
        f = kv_pairs(raw)
        if not f.get("src") or not f.get("dst"):
            return None
        return make_record(
            src_ip=f.get("src"), dst_ip=f.get("dst"),
            src_port=f.get("sport"), dst_port=f.get("dport"),
            protocol=f.get("proto"), packet_size=to_int(f.get("size")),
            flags=f.get("flags"), connection_outcome=f.get("outcome"),
            syslog_severity=f.get("sev"), raw=raw,
        )
