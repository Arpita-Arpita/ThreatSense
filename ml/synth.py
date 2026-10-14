"""
Synthetic flow generator (MVP training/eval data) — task 1.9 decision.

We train the Isolation Forest on PIPELINE-SHAPED normal traffic so the model
learns from the exact 10 features the detection engine computes at inference.
Attack windows here are used only for EVALUATION (precision/recall/F1) and for
Nmap/hping3-style validation later — NOT for training (Isolation Forest is
unsupervised and learns "normal" only).

Future improvement: derive these same 10 features from CICIDS2017 raw PCAPs for
a hybrid baseline. CICIDS2017's CICFlowMeter CSV features do not map 1:1 to our
Syslog-derived window features, which is why they are reference/eval only here.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone


def _window(src_ip, dst_ips, ports, protocols, n, syn_p, rst_p, size_lo, size_hi, base):
    recs = []
    for _ in range(n):
        recs.append({
            "source_id": "synthetic",
            "src_ip": src_ip,
            "dst_ip": random.choice(dst_ips),
            "dst_port": random.choice(ports),
            "protocol": random.choices(*zip(*protocols))[0],
            "packet_size": random.randint(size_lo, size_hi),
            "flags": "SYN" if random.random() < syn_p else ("RST" if random.random() < rst_p else "ACK"),
            "timestamp": base + timedelta(seconds=random.uniform(0, 59)),
        })
    return recs


def normal_window(rng_seed=None) -> list[dict]:
    """Benign client: few dst IPs/ports, moderate sizes, mostly ACK."""
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    src = f"10.0.{random.randint(0,3)}.{random.randint(2,254)}"
    dst_ips = [f"192.168.1.{random.randint(2,30)}" for _ in range(random.randint(1, 3))]
    ports = random.sample([80, 443, 53, 22, 123, 3306], random.randint(1, 4))
    return _window(src, dst_ips, ports, [("TCP", 0.7), ("UDP", 0.3)],
                   n=random.randint(8, 40), syn_p=0.08, rst_p=0.02,
                   size_lo=200, size_hi=1200, base=base)


def attack_window(kind: str) -> list[dict]:
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    src = f"10.0.9.{random.randint(2,254)}"
    if kind == "port_scan":
        dst = [f"192.168.1.{random.randint(2,30)}"]
        ports = random.sample(range(1, 65000), random.randint(60, 200))
        return _window(src, dst, ports, [("TCP", 1.0)],
                       n=len(ports), syn_p=0.95, rst_p=0.0, size_lo=40, size_hi=64, base=base)
    if kind == "ddos":
        dst = [f"192.168.1.{random.randint(2,5)}"]
        return _window(src, dst, [80], [("TCP", 1.0)],
                       n=random.randint(400, 900), syn_p=0.9, rst_p=0.0,
                       size_lo=40, size_hi=80, base=base)
    # sweep: one src -> many dst IPs
    dst = [f"192.168.{random.randint(1,5)}.{i}" for i in random.sample(range(2, 254), random.randint(40, 120))]
    return _window(src, dst, [445], [("TCP", 1.0)],
                   n=len(dst), syn_p=0.95, rst_p=0.0, size_lo=40, size_hi=64, base=base)


def normal_dataset(n_windows: int) -> list[list[dict]]:
    return [normal_window() for _ in range(n_windows)]


def attack_dataset(n_each: int) -> list[tuple[str, list[dict]]]:
    out = []
    for kind in ("port_scan", "ddos", "sweep"):
        out += [(kind, attack_window(kind)) for _ in range(n_each)]
    return out
