"""Parser registry (task 1.7).

Adapters are tried in priority order; the first to return a record wins.
Order matters: iptables (uppercase SRC=) before rfc5424 (<PRI> + lowercase
src=) before the generic key=value default.
"""
from __future__ import annotations

from .default import KeyValueParser
from .iptables import IptablesParser
from .rfc5424 import Rfc5424Parser

PARSERS = [IptablesParser(), Rfc5424Parser(), KeyValueParser()]


def parse(raw: str) -> dict | None:
    """Parse one log line. Returns a normalized record (with 'parser' set) or None."""
    for p in PARSERS:
        rec = p.try_parse(raw)
        if rec is not None:
            rec["parser"] = p.name
            return rec
    return None


def parse_lines(text: str) -> tuple[list[dict], int]:
    """Parse multi-line content (e.g. an uploaded log file).

    Returns (records, skipped). Used by the live listener's batch path and,
    in task 1.8, the syslog/pcap file-upload endpoint.
    """
    records: list[dict] = []
    skipped = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        rec = parse(line)
        if rec is None:
            skipped += 1
        else:
            records.append(rec)
    return records, skipped
