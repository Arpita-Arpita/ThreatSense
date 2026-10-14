#!/usr/bin/env python3
"""
NFR-01 ingestion throughput — COUNTER half. Runs ON THE MAC.

Partner to nfr01_send.py, which runs on the Kali VM. See that script's
docstring for why the harness is split.

Proposal Section 3, Table 11, NFR-01 — Requirement (verbatim):
    "The data ingestion pipeline must process a minimum of 1,000 Syslog
    entries per second under normal operating conditions without data loss or
    queue overflow. A stretch target of 5,000 entries per second will be
    evaluated during load testing."

WHAT IT COUNTS
--------------
Rows in network_logs whose ingested_at falls at or after the sender's start
timestamp. ingested_at carries a server_default of now() and is written when
the listener FLUSHES a batch, so it records when the pipeline actually
accepted the record — unlike the `timestamp` column, which holds the time
parsed out of the syslog message itself.

UDP does not acknowledge, so the gap between sent and delivered IS the "data
loss or queue overflow" the requirement asks about.

USAGE
-----
Copy the command nfr01_send.py prints when it finishes:

    python scripts/nfr01_count_rows.py \\
        --since '2026-08-23T02:34:14.227000+00:00' --expect 85001 \\
        --per-rate '[[500, 5000], [1000, 10000], [2000, 20001], [5000, 50000]]'

--per-rate is optional; without it you get a single aggregate figure rather
than a per-rate breakdown.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.models import DataSource, NetworkLog


def main() -> None:
    ap = argparse.ArgumentParser(description="NFR-01 counter (run on the Mac)")
    ap.add_argument("--since", required=True,
                    help="ISO timestamp printed by nfr01_send.py.")
    ap.add_argument("--expect", type=int, required=True,
                    help="Total datagrams the sender reported.")
    ap.add_argument("--per-rate", default=None,
                    help="JSON [[rate, sent], ...] for a per-rate breakdown.")
    ap.add_argument("--tolerance", type=float, default=1.0,
                    help="Loss %% still counted as a pass (default 1.0).")
    args = ap.parse_args()

    since = datetime.fromisoformat(args.since)
    if since.tzinfo is None:
        since = since.replace(tzinfo=timezone.utc)

    engine = create_engine(settings.database_url, pool_pre_ping=True)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    with SessionLocal() as db:
        delivered = db.scalar(
            select(func.count()).select_from(NetworkLog)
            .where(NetworkLog.ingested_at >= since)) or 0

        # Which source absorbed them — confirms resolve_source() matched the
        # sender rather than falling through to a different registered host.
        by_source = db.execute(
            select(DataSource.name, DataSource.ip_address, func.count(NetworkLog.log_id))
            .join(NetworkLog, NetworkLog.source_id == DataSource.source_id)
            .where(NetworkLog.ingested_at >= since)
            .group_by(DataSource.name, DataSource.ip_address)).all()

    loss = args.expect - delivered
    loss_pct = (loss / args.expect * 100) if args.expect else 0.0

    print("NFR-01 ingestion throughput — DELIVERY")
    print(f"  counting rows with ingested_at >= {since.isoformat()}")
    print(f"  baseline    : 1,000 msgs/sec without loss")
    print(f"  stretch     : 5,000 msgs/sec\n")

    print("=" * 66)
    print(f"  sent (from Kali) : {args.expect}")
    print(f"  delivered        : {delivered}")
    print(f"  loss             : {loss}  ({loss_pct:.2f}%)")
    print("=" * 66)

    if by_source:
        print("\n  Resolved to:")
        for name, ip, count in by_source:
            print(f"    {name:<24} {str(ip):<16} {count:>8} rows")
    else:
        print("\n  ! No rows landed at all. The listener resolves the sending host")
        print("    against data_sources.ip_address and silently discards anything")
        print("    it cannot match — check the sender IP is registered, and that")
        print("    the listener was RESTARTED after any change (refresh_sources()")
        print("    only runs at start-up).")

    if args.per_rate:
        print("\n  Per-rate sent (delivery is measured in aggregate — the rates run")
        print("  back to back, so ingested_at cannot attribute a row to one rate):")
        print(f"\n{'Target':>8} {'Sent':>8}")
        print("-" * 20)
        for rate, sent in json.loads(args.per_rate):
            print(f"{rate:>8} {sent:>8}")

    ok = loss_pct <= args.tolerance
    print(f"\nNFR-01 BASELINE (1,000/sec, no loss): {'PASS' if ok else 'FAIL'}")
    print(f"  aggregate loss {loss_pct:.2f}% against a {args.tolerance:.1f}% tolerance")

    if not ok:
        print("\n  Loss above tolerance. Before recording this as a ceiling, re-run")
        print("  the rates INDIVIDUALLY to find which one degrades:")
        print("    python3 nfr01_send.py --rates 1000 --duration 20      # on Kali")
        print("  A single-rate run attributes loss unambiguously; a combined run")
        print("  cannot tell you whether 1,000/sec or 5,000/sec dropped the packets.")

    print("\nScreenshot this block for the NFR-01 evidence.")


if __name__ == "__main__":
    main()
