#!/usr/bin/env python3
"""
NFR-01 ingestion throughput — SENDER half. Runs ON THE KALI VM.

Proposal Section 3, Table 11, NFR-01 — Requirement (verbatim):
    "The data ingestion pipeline must process a minimum of 1,000 Syslog
    entries per second under normal operating conditions without data loss or
    queue overflow. A stretch target of 5,000 entries per second will be
    evaluated during load testing."

Proposal Section 3, Table 11, NFR-01 — Measurement / Metric (verbatim):
    "Load testing with synthetic Syslog streams at increasing volumes (500,
    1,000, 2,000, 5,000 msgs/sec); throughput logged per batch and verified
    against the 1,000/s baseline threshold."

WHY THIS IS SPLIT IN TWO
------------------------
The combined harness could not work from Kali: it counted delivered rows by
querying Postgres, which is bound to the Mac and unreachable from the guest.
Running it on the Mac instead meant the Mac sent to its own bridge address,
and the kernel picked the Wi-Fi interface as the source — so the listener saw
an unregistered sender IP and silently dropped every datagram.

Sending from Kali is also simply the better measurement: guest VM -> UTM
bridge -> Mac listener is the real deployment path and the same one Phase 5's
attack traffic took, rather than the Mac talking to itself.

So: this script SENDS only, and has no dependencies beyond the standard
library. Its partner, nfr01_count_rows.py, runs on the Mac and counts what
arrived.

USAGE
-----
On the Mac, start the listener and note the time:

    cd backend && source .venv/bin/activate
    python -m app.services.ingestion.listener

On Kali:

    python3 nfr01_send.py --host 192.168.64.1 --port 1514

It prints a UTC start timestamp. Give that to the counter on the Mac:

    python scripts/nfr01_count_rows.py --since '<timestamp>' --expect 85001

IMPORTANT
---------
The listener resolves the sending host against data_sources.ip_address. Kali
at 192.168.64.2 is already registered as 'kali-sandbox', so datagrams from
here resolve correctly. Sending from any unregistered address results in 100%
silent loss — the listener increments an internal counter that is never
logged or exposed.
"""
from __future__ import annotations

import argparse
import json
import random
import socket
import time
from datetime import datetime, timezone

# Matches app/services/ingestion/parsers/iptables.py, the adapter that handled
# the Phase 5 attack traffic, so this exercises the same parser path.
TEMPLATE = (
    "<134>{ts} kernel: [12345.678] IN=eth0 OUT= MAC=00:11:22:33:44:55 "
    "SRC={src} DST={dst} LEN={length} TOS=0x00 PREC=0x00 TTL=64 ID={ident} "
    "PROTO={proto} SPT={spt} DPT={dpt} WINDOW=64240 RES=0x00 {flags} URGP=0"
)

PROTOCOLS = ["TCP", "TCP", "TCP", "UDP", "ICMP"]
FLAG_SETS = ["SYN", "SYN ACK", "ACK", "PSH ACK", "FIN ACK", "RST"]


def make_message(seq: int) -> bytes:
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


def run_rate(sock, addr, rate: int, duration: int) -> dict:
    print(f"  {rate:>5} msgs/sec for {duration}s …", end="", flush=True)

    interval = 1.0 / rate
    started = time.perf_counter()
    deadline = started + duration
    next_send = started
    sent = 0
    send_errors = 0

    while time.perf_counter() < deadline:
        if time.perf_counter() < next_send:
            continue          # busy-wait; sleep() granularity cannot pace 5000/s
        try:
            sock.sendto(make_message(sent), addr)
            sent += 1
        except OSError:
            send_errors += 1  # ENOBUFS — sender-side, not an ingestion failure
        next_send += interval

    elapsed = time.perf_counter() - started
    actual = sent / elapsed if elapsed else 0.0
    print(f" sent {sent} ({actual:.0f}/s)")
    return {"target_rate": rate, "sent": sent, "actual_send_rate": actual,
            "send_errors": send_errors}


def main() -> None:
    ap = argparse.ArgumentParser(description="NFR-01 sender (run on Kali)")
    ap.add_argument("--host", default="192.168.64.1",
                    help="Mac listener address on the UTM bridge.")
    ap.add_argument("--port", type=int, default=1514)
    ap.add_argument("--rates", type=int, nargs="+", default=[500, 1000, 2000, 5000],
                    help="Rates from Table 11's measurement column.")
    ap.add_argument("--duration", type=int, default=10, help="Seconds per rate.")
    ap.add_argument("--gap", type=float, default=8.0,
                    help="Pause between rates so the listener buffer flushes.")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    addr = (args.host, args.port)

    # Report the source address the LISTENER will see, since that is what it
    # resolves against data_sources. Getting this wrong is silent 100% loss.
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.connect(addr)
    sender_ip = probe.getsockname()[0]
    probe.close()

    started_at = datetime.now(timezone.utc)

    print("NFR-01 ingestion throughput — SENDER")
    print(f"  target      : {addr[0]}:{addr[1]} (UDP)")
    print(f"  sender IP   : {sender_ip}   <- must exist in data_sources.ip_address")
    print(f"  baseline    : 1,000 msgs/sec without loss")
    print(f"  stretch     : 5,000 msgs/sec")
    print(f"  started at  : {started_at.isoformat()}\n")

    results = []
    for i, rate in enumerate(args.rates):
        results.append(run_rate(sock, addr, rate, args.duration))
        if i < len(args.rates) - 1:
            time.sleep(args.gap)
    sock.close()

    print(f"\n  waiting {args.gap:.0f}s for the final flush …")
    time.sleep(args.gap)

    total_sent = sum(r["sent"] for r in results)
    total_errors = sum(r["send_errors"] for r in results)

    print("\n" + "=" * 62)
    print(f"{'Target':>8} {'Sent':>8} {'Send/s':>9}   Errors")
    print("-" * 62)
    for r in results:
        print(f"{r['target_rate']:>8} {r['sent']:>8} {r['actual_send_rate']:>9.0f}   "
              f"{r['send_errors']}")
    print("-" * 62)
    print(f"{'TOTAL':>8} {total_sent:>8}")
    print("=" * 62)

    if total_errors:
        print(f"\n{total_errors} kernel send-buffer errors (sender-side, not ingestion).")

    print("\nNow run this ON THE MAC to count what arrived:\n")
    print(f"  python scripts/nfr01_count_rows.py \\")
    print(f"      --since '{started_at.isoformat()}' --expect {total_sent} \\")
    print(f"      --per-rate '{json.dumps([[r['target_rate'], r['sent']] for r in results])}'")


if __name__ == "__main__":
    main()
