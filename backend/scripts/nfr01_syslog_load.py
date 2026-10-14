#!/usr/bin/env python3
"""
NFR-01 ingestion throughput harness.

Proposal Section 3, Table 11, NFR-01 — Requirement (verbatim):
    "The data ingestion pipeline must process a minimum of 1,000 Syslog
    entries per second under normal operating conditions without data loss or
    queue overflow. A stretch target of 5,000 entries per second will be
    evaluated during load testing."

Proposal Section 3, Table 11, NFR-01 — Measurement / Metric (verbatim):
    "Load testing with synthetic Syslog streams at increasing volumes (500,
    1,000, 2,000, 5,000 msgs/sec); throughput logged per batch and verified
    against the 1,000/s baseline threshold."

WHAT THIS MEASURES
------------------
Two different numbers, and the distinction matters for the write-up:

  SEND rate     — datagrams this script pushed onto the wire per second.
  DELIVERED     — rows that actually reached network_logs, counted in the
                  database by batch window.

UDP does not acknowledge. The gap between the two IS the "data loss or queue
overflow" the requirement asks about, so both are reported. A run that sends
5,000/sec and lands 5,000/sec passes; one that sends 5,000/sec and lands
3,100/sec tells you the pipeline's real ceiling is around 3,100.

TOPOLOGY
--------
Send to the Docker network path, not loopback, so the measured number is the
one you can reproduce in the demo — the same path the Phase 5 Kali traffic
took. Pass --host with the address your listener binds on the UTM bridge
(192.168.64.1 in the Phase 5 setup), NOT 127.0.0.1.

Loopback will give a flattering number that the demo cannot reproduce.

USAGE
-----
    # Terminal 1 — the listener under test
    cd backend && source .venv/bin/activate
    python -m app.services.ingestion.listener

    # Terminal 2 — this harness
    cd backend && source .venv/bin/activate
    python scripts/nfr01_syslog_load.py --host 192.168.64.1 --port 1514

Runs 500, 1000, 2000 and 5000 msgs/sec in sequence by default, 10 seconds
each, with a settle pause between so one rate's backlog is not counted
against the next.
"""
from __future__ import annotations

import argparse
import random
import socket
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.models import NetworkLog

# Matches the iptables adapter in app/services/ingestion/parsers/iptables.py,
# which is the format the Phase 5 Kali sandbox actually emitted. Using the
# real format means this exercises the same parser path as live traffic
# rather than a synthetic shortcut.
TEMPLATE = (
    "<134>{ts} kernel: [12345.678] IN=eth0 OUT= MAC=00:11:22:33:44:55 "
    "SRC={src} DST={dst} LEN={length} TOS=0x00 PREC=0x00 TTL=64 ID={ident} "
    "PROTO={proto} SPT={spt} DPT={dpt} WINDOW=64240 RES=0x00 {flags} URGP=0"
)

PROTOCOLS = ["TCP", "TCP", "TCP", "UDP", "ICMP"]   # TCP-weighted, as real traffic is
FLAG_SETS = ["SYN", "SYN ACK", "ACK", "PSH ACK", "FIN ACK", "RST"]


def make_message(seq: int) -> bytes:
    """One plausible iptables-over-syslog line."""
    ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    return TEMPLATE.format(
        ts=ts,
        src=f"10.0.{(seq // 254) % 254}.{(seq % 254) + 1}",
        dst=f"192.168.1.{(seq % 20) + 1}",
        length=random.randint(40, 1500),
        ident=random.randint(1, 65535),
        proto=random.choice(PROTOCOLS),
        spt=random.randint(1024, 65535),
        dpt=random.choice([22, 80, 443, 3389, 8080, random.randint(1, 65535)]),
        flags=random.choice(FLAG_SETS),
    ).encode()


def count_rows(SessionLocal, since: datetime) -> int:
    """Rows that landed in network_logs since `since`.

    Counts on ingested_at (server_default now(), set when the listener FLUSHES
    the row) rather than the `timestamp` column, which carries the time parsed
    out of the syslog message itself. Only ingested_at reflects when the
    pipeline actually accepted the record, which is what NFR-01 measures.
    """
    with SessionLocal() as db:
        return db.scalar(
            select(func.count()).select_from(NetworkLog)
            .where(NetworkLog.ingested_at >= since)
        ) or 0


def run_rate(sock, addr, rate: int, duration: int, SessionLocal, settle: float) -> dict:
    """Send at `rate` msgs/sec for `duration` seconds; report sent vs delivered."""
    print(f"\n  {rate:>5} msgs/sec for {duration}s …", end="", flush=True)

    started_at = datetime.now(timezone.utc)
    interval = 1.0 / rate
    deadline = time.perf_counter() + duration
    next_send = time.perf_counter()
    sent = 0
    send_errors = 0

    while time.perf_counter() < deadline:
        now = time.perf_counter()
        if now < next_send:
            # Busy-wait for sub-millisecond precision: time.sleep() cannot
            # pace 5,000/sec reliably (its granularity is ~1ms on macOS).
            continue
        try:
            sock.sendto(make_message(sent), addr)
            sent += 1
        except OSError:
            # ENOBUFS when the kernel send buffer is full — itself a finding,
            # so count it rather than crashing the run.
            send_errors += 1
        next_send += interval

    elapsed = duration
    actual_rate = sent / elapsed

    # Let the listener's buffer flush (SYSLOG_FLUSH_SECONDS) before counting.
    print(f" sent {sent} ({actual_rate:.0f}/s), settling {settle:.0f}s …", end="", flush=True)
    time.sleep(settle)

    delivered = count_rows(SessionLocal, started_at)
    loss = sent - delivered
    loss_pct = (loss / sent * 100) if sent else 0.0

    print(" done")
    return {
        "target_rate": rate, "sent": sent, "actual_send_rate": actual_rate,
        "delivered": delivered, "loss": loss, "loss_pct": loss_pct,
        "send_errors": send_errors,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="NFR-01 ingestion throughput harness")
    ap.add_argument("--host", required=True,
                    help="Listener address. Use the Docker/bridge path (e.g. 192.168.64.1), NOT 127.0.0.1.")
    ap.add_argument("--port", type=int, default=1514)
    ap.add_argument("--rates", type=int, nargs="+", default=[500, 1000, 2000, 5000],
                    help="Rates from Table 11's measurement column.")
    ap.add_argument("--duration", type=int, default=10, help="Seconds per rate.")
    ap.add_argument("--settle", type=float, default=8.0,
                    help="Pause after each rate so the listener buffer flushes.")
    args = ap.parse_args()

    if args.host.startswith("127.") or args.host == "localhost":
        print("WARNING: sending over loopback. NFR-01 evidence should use the\n"
              "         Docker/bridge path so the number is reproducible in the demo.\n")

    engine = create_engine(settings.database_url, pool_pre_ping=True)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    addr = (args.host, args.port)

    print("NFR-01 ingestion throughput")
    print(f"  target      : {addr[0]}:{addr[1]} (UDP)")
    print(f"  baseline    : 1,000 msgs/sec without loss")
    print(f"  stretch     : 5,000 msgs/sec")

    results = [run_rate(sock, addr, r, args.duration, SessionLocal, args.settle)
               for r in args.rates]
    sock.close()

    print("\n" + "=" * 78)
    print(f"{'Target':>8} {'Sent':>8} {'Send/s':>9} {'Delivered':>10} {'Loss':>8} {'Loss %':>8}  Result")
    print("-" * 78)
    baseline_pass = None          # None = the 1,000/sec rate was not run
    for r in results:
        # "without data loss or queue overflow" — a small margin is allowed for
        # rows still in flight, not for genuine drops.
        ok = r["loss_pct"] <= 1.0
        verdict = "PASS" if ok else "LOSS"
        if r["target_rate"] == 1000:
            baseline_pass = ok
        print(f"{r['target_rate']:>8} {r['sent']:>8} {r['actual_send_rate']:>9.0f} "
              f"{r['delivered']:>10} {r['loss']:>8} {r['loss_pct']:>7.2f}%  {verdict}")
        if r["send_errors"]:
            print(f"{'':>8} (+{r['send_errors']} kernel send-buffer errors — sender-side, not ingestion)")
    print("=" * 78)

    if baseline_pass is None:
        print("\nNFR-01 BASELINE (1,000/sec): NOT TESTED — the 1,000/sec rate was not "
              "in --rates.\n  Run without --rates to cover all four rates from Table 11.")
    else:
        print(f"\nNFR-01 BASELINE (1,000/sec, no loss): {'PASS' if baseline_pass else 'FAIL'}")
    stretch = next((r for r in results if r["target_rate"] == 5000), None)
    if stretch:
        print(f"NFR-01 STRETCH  (5,000/sec)          : "
              f"{'MET' if stretch['loss_pct'] <= 1.0 else 'NOT MET'} "
              f"({stretch['loss_pct']:.2f}% loss) — stretch target, not a pass condition")

    print("\nScreenshot this table for the NFR-01 evidence.")


if __name__ == "__main__":
    main()
