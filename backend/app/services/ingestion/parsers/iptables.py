"""iptables / netfilter kernel-log adapter (task 1.7).

Recognised by uppercase SRC=/DST= keys. Handles bare iptables lines and
iptables-over-syslog (leading <PRI> contributes severity if present).
"""
from __future__ import annotations

import re

# Raw values are passed to make_record: it owns validation and bounds, so
# converting here would turn a malformed port into a silent NULL.
from .base import LogParser, make_record, to_int

_PRI = re.compile(r"^<(\d{1,3})>")
_TCP_FLAGS = {"SYN", "ACK", "FIN", "RST", "PSH", "URG"}


class IptablesParser(LogParser):
    name = "iptables"

    def try_parse(self, raw: str) -> dict | None:
        if "SRC=" not in raw or "DST=" not in raw:   # case-sensitive: uppercase = iptables
            return None
        f: dict[str, str] = {}
        for tok in raw.split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                if v != "":
                    f[k] = v                          # preserve UPPER case
        src, dst = f.get("SRC"), f.get("DST")
        if not src or not dst:
            return None
        flags = [t for t in raw.split() if t in _TCP_FLAGS]
        sev = None
        m = _PRI.match(raw)
        if m and int(m.group(1)) <= 191:
            sev = int(m.group(1)) % 8
        return make_record(
            src_ip=src, dst_ip=dst,
            src_port=f.get("SPT"), dst_port=f.get("DPT"),
            protocol=f.get("PROTO"), packet_size=to_int(f.get("LEN")),
            flags=" ".join(flags) or None, syslog_severity=sev, raw=raw,
        )
