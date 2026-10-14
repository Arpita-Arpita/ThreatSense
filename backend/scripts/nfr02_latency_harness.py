#!/usr/bin/env python3
"""
NFR-02 detection latency harness.

Proposal Section 3, Table 11, NFR-02 — Requirement (verbatim):
    "The Isolation Forest detection engine must complete analysis of each
    one-minute feature vector batch within 10 seconds, ensuring near-real-time
    detection capability."

Proposal Section 3, Table 11, NFR-02 — Measurement / Metric (verbatim):
    "Server-side timing of detection cycle starts and completion timestamps;
    the 95th percentile across 100 consecutive test cycles must be ≤ 10
    seconds."

WHAT COUNTS AS A CYCLE
----------------------
run_cycle() in app/services/detection/engine.py: read unanalysed rows, group
into one-minute windows, extract the 10 features, score each window through
IF_v1.0, write detections, mark rows analysed, commit. This times that whole
call, which is what "cycle starts and completion timestamps" means.

Cycles that find no unanalysed logs return immediately and are NOT counted —
timing an empty cycle would flatter the percentile with near-zero samples.
The script seeds fresh logs before each cycle so all 100 do real work.

The requirement says "one-minute feature vector batch", so by default each
cycle is given one minute's worth of traffic. --logs-per-cycle sets how dense
that minute is; 600 (10/sec) is a reasonable steady-state figure. Raise it to
see how the percentile behaves under heavier load, and say which value you
used when you report the number.

USAGE
-----
    cd backend && source .venv/bin/activate
    python scripts/nfr02_latency_harness.py

    # heavier minute
    python scripts/nfr02_latency_harness.py --logs-per-cycle 3000

The seeded logs are deleted afterwards unless you pass --keep.
"""
from __future__ import annotations

import argparse
import random
import statistics
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import create_engine, delete, func, select
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.models import DataSource, Detection, NetworkLog
from app.services.detection.engine import run_cycle

PROTOCOLS = ["TCP", "TCP", "TCP", "UDP", "ICMP"]
FLAGS = ["SYN", "SYN ACK", "ACK", "PSH ACK", "FIN ACK", "RST"]


def seed_one_minute(db, source_id, batch_id, count: int, when: datetime,
                    hosts: int = 25) -> None:
    """Insert `count` logs spread across a single one-minute window.

    `hosts` controls how many distinct source IPs the traffic comes from, and
    it matters more than it looks. engine.run_cycle() groups by
    (source_id, src_ip, minute), so the window count — and therefore the
    number of feature extractions and model scorings — is driven by the number
    of distinct source IPs, NOT by the log count.

    Giving every log its own src_ip would produce one single-record window per
    log: degenerate feature vectors that score as anomalous almost every time,
    inflating both the timing and the detections table with junk. 25 hosts
    emitting into one minute is closer to a real edge firewall.
    """
    rows = []
    for i in range(count):
        rows.append(NetworkLog(
            source_id=source_id,
            batch_id=batch_id,
            timestamp=when + timedelta(seconds=(i / count) * 59),
            src_ip=f"10.0.0.{(i % hosts) + 1}",
            dst_ip=f"192.168.1.{(i % 20) + 1}",
            src_port=random.randint(1024, 65535),
            dst_port=random.choice([22, 80, 443, 3389, 8080]),
            protocol=random.choice(PROTOCOLS),
            packet_size=random.randint(40, 1500),
            flags=random.choice(FLAGS),
            is_analysed=False,
        ))
    db.add_all(rows)
    db.commit()


def main() -> None:
    ap = argparse.ArgumentParser(description="NFR-02 detection latency harness")
    ap.add_argument("--cycles", type=int, default=100,
                    help="Table 11 specifies 100 consecutive cycles.")
    ap.add_argument("--logs-per-cycle", type=int, default=600,
                    help="Logs in each one-minute window (default 600 = 10/sec).")
    ap.add_argument("--hosts", type=int, default=25,
                    help="Distinct source IPs per window. Drives the window count, "
                         "which is what actually determines cycle cost.")
    ap.add_argument("--keep", action="store_true",
                    help="Leave the seeded logs and detections in place afterwards.")
    args = ap.parse_args()

    engine = create_engine(settings.database_url, pool_pre_ping=True)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    with SessionLocal() as db:
        source = db.scalar(select(DataSource))
        if source is None:
            sys.exit("No data_sources row. Run db/seed.py first.")
        source_id = source.source_id

    with SessionLocal() as db:
        backlog = db.scalar(select(func.count()).select_from(NetworkLog)
                            .where(NetworkLog.is_analysed.is_(False))) or 0

    batch_id = uuid.uuid4()
    print("NFR-02 detection latency")
    print(f"  cycles          : {args.cycles}")
    print(f"  logs per cycle  : {args.logs_per_cycle} (one-minute window)")
    print(f"  distinct hosts  : {args.hosts}  -> {args.hosts} windows scored per cycle")
    print(f"  threshold       : 95th percentile <= 10.0 s")
    print(f"  model           : loaded per cycle by run_cycle()")
    if backlog:
        drain = -(-backlog // 5000)   # ceil; run_cycle takes 5000 rows max
        print(f"\n  ! {backlog:,} unanalysed logs already in network_logs.")
        print(f"    run_cycle() takes the OLDEST rows first, so roughly the next")
        print(f"    {drain} cycles will drain that backlog rather than measure the")
        print(f"    synthetic window. Those cycles are detected and excluded.")
    print()

    durations: list[float] = []
    detections_made = 0
    created_detection_ids: list = []
    skipped_backlog = 0
    base_time = datetime.now(timezone.utc) - timedelta(minutes=args.cycles + 5)

    for n in range(1, args.cycles + 1):
        with SessionLocal() as db:
            seed_one_minute(db, source_id, batch_id, args.logs_per_cycle,
                            base_time + timedelta(minutes=n), hosts=args.hosts)

        with SessionLocal() as db:
            before = datetime.now(timezone.utc)
            start = time.perf_counter()
            processed, created, _ = run_cycle(db)
            elapsed = time.perf_counter() - start
            # Capture what this cycle wrote, so cleanup can target it exactly.
            if created:
                created_detection_ids.extend(db.scalars(
                    select(Detection.detection_id)
                    .where(Detection.created_at >= before)).all())

        if processed == 0:
            print(f"  cycle {n:>3}: no unanalysed logs — skipped (not counted)")
            continue

        # A cycle that consumed materially more rows than we seeded was working
        # through a PRE-EXISTING backlog of unanalysed logs, not our synthetic
        # window. Timing it would blend two unrelated workloads into one
        # percentile — so drain it, but do not count it.
        if processed > args.logs_per_cycle * 1.5:
            skipped_backlog += 1
            if skipped_backlog == 1:
                print(f"  cycle {n:>3}: {processed} logs — pre-existing backlog, "
                      f"draining (not counted)")
            elif skipped_backlog % 10 == 0:
                print(f"  cycle {n:>3}: still draining backlog "
                      f"({skipped_backlog} cycles so far, not counted)")
            continue

        durations.append(elapsed)
        detections_made += created

        if n % 10 == 0 or n == 1:
            print(f"  cycle {n:>3}: {elapsed:6.3f}s  ({processed} logs, {created} detections)")

    if not durations:
        sys.exit("No cycles produced timings — nothing to report.")

    durations_sorted = sorted(durations)
    # Nearest-rank p95: the smallest value with at least 95% of samples at or
    # below it. Stated explicitly because percentile methods differ and the
    # examiner may recompute from the raw list.
    rank = max(1, int(len(durations_sorted) * 0.95 + 0.9999))
    p95 = durations_sorted[rank - 1]

    print("\n" + "=" * 60)
    if skipped_backlog:
        print(f"  backlog cycles   : {skipped_backlog} drained, NOT counted")
    print(f"  cycles timed     : {len(durations)}")
    print(f"  logs per cycle   : {args.logs_per_cycle}")
    print(f"  windows/cycle    : {args.hosts}")
    print(f"  detections made  : {detections_made}")
    print(f"  min              : {min(durations):.3f}s")
    print(f"  median           : {statistics.median(durations):.3f}s")
    print(f"  mean             : {statistics.fmean(durations):.3f}s")
    print(f"  95th percentile  : {p95:.3f}s   <-- the NFR-02 number")
    print(f"  max              : {max(durations):.3f}s")
    print("=" * 60)
    print(f"\nNFR-02: {'PASS' if p95 <= 10.0 else 'FAIL'} (p95 {p95:.3f}s vs 10.0s threshold)")

    if len(durations) < args.cycles:
        print(f"\nNOTE: only {len(durations)} of {args.cycles} cycles were counted. "
              f"Table 11 specifies 100 consecutive cycles, so re-run now that the\n"
              f"      backlog is drained to get a full set for the evidence.")

    if not args.keep:
        with SessionLocal() as db:
            # Delete ONLY the detections this run produced, identified by their
            # own primary keys, collected cycle by cycle.
            #
            # An earlier version matched on (source_id, timestamp older than N
            # minutes) and would happily delete pre-existing detections for the
            # same source — including real Phase 5 validation results. Never
            # scope a destructive cleanup by anything but the identity of what
            # you created.
            if created_detection_ids:
                db.execute(delete(Detection).where(
                    Detection.detection_id.in_(created_detection_ids)))
            db.execute(delete(NetworkLog).where(NetworkLog.batch_id == batch_id))
            db.commit()
        print(f"\nRemoved {len(created_detection_ids)} seeded detections and this "
              f"run's logs. Pass --keep to retain them.")

    print("\nScreenshot the summary block for the NFR-02 evidence.")


if __name__ == "__main__":
    main()
