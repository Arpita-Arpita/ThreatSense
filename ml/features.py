"""
Canonical 10 flow-window features (task 1.11) — the SINGLE SOURCE OF TRUTH.

Imported by BOTH ml/train.py (offline training) and the backend detection
engine (live inference), so features can never drift between the two. Each
"window" is the set of network_logs for one (source_id, src_ip) inside one
1-minute bucket; extract_features() turns a window into the 10-feature vector.

Records are plain dicts with keys:
    timestamp (datetime), src_ip, dst_ip, dst_port (int|None),
    protocol (str), packet_size (int), flags (str|None), source_id
"""
from __future__ import annotations

import math
import statistics
from collections import Counter

WINDOW_SECONDS = 60

FEATURE_NAMES = [
    "packets_per_sec",
    "bytes_per_sec",
    "unique_dst_ports",
    "unique_dst_ips",
    "avg_packet_size",
    "std_packet_size",
    "tcp_ratio",
    "syn_ratio",
    "rst_ratio",
    "dst_ip_entropy",
]


def extract_features(window: list[dict]) -> dict:
    """Compute the 10 features for one window of log records."""
    n = len(window)
    if n == 0:
        return {k: 0.0 for k in FEATURE_NAMES}

    times = [r["timestamp"] for r in window]
    duration = max((max(times) - min(times)).total_seconds(), 1.0)

    sizes = [int(r["packet_size"]) for r in window]
    total_bytes = sum(sizes)
    dst_ports = {r["dst_port"] for r in window if r.get("dst_port") is not None}
    dst_ips = [r["dst_ip"] for r in window]
    protocols = [str(r.get("protocol") or "").upper() for r in window]
    flags = [str(r.get("flags") or "").upper() for r in window]

    tcp = sum(1 for p in protocols if p == "TCP")
    syn = sum(1 for f in flags if "SYN" in f)
    rst = sum(1 for f in flags if "RST" in f)

    counts = Counter(dst_ips)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())

    return {
        "packets_per_sec": n / duration,
        "bytes_per_sec": total_bytes / duration,
        "unique_dst_ports": float(len(dst_ports)),
        "unique_dst_ips": float(len(set(dst_ips))),
        "avg_packet_size": total_bytes / n,
        "std_packet_size": statistics.pstdev(sizes) if n > 1 else 0.0,
        "tcp_ratio": tcp / n,
        "syn_ratio": syn / n,
        "rst_ratio": rst / n,
        "dst_ip_entropy": entropy,
    }


def to_vector(features: dict) -> list[float]:
    """Ordered feature vector for the model (order == FEATURE_NAMES)."""
    return [float(features[k]) for k in FEATURE_NAMES]


def group_windows(records: list[dict]) -> dict:
    """Bucket records into windows keyed by (source_id, src_ip, minute)."""
    windows: dict[tuple, list[dict]] = {}
    for r in records:
        bucket = r["timestamp"].replace(second=0, microsecond=0)
        key = (r.get("source_id"), r["src_ip"], bucket)
        windows.setdefault(key, []).append(r)
    return windows
