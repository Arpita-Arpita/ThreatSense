"""
Rule-based threat categorisation (task 1.13) — the hybrid ML+rules layer.

The Isolation Forest decides WHETHER a window is anomalous; these rules decide
WHAT KIND of threat it is, by inspecting the same 10 window features (plus the
dominant destination port). Runs only on windows already flagged anomalous, so
each rule answers "given this is anomalous, which category fits?".

Thresholds are documented heuristics, tuned for the MVP and easily adjustable.
Order matters: more specific signatures are checked first.
"""
from __future__ import annotations

from collections import Counter

from app.models import ThreatType

# Services commonly targeted by credential brute-forcing.
AUTH_PORTS = {21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900}


def _dominant_dst_port(window: list[dict]) -> int | None:
    ports = [r.get("dst_port") for r in window if r.get("dst_port") is not None]
    return Counter(ports).most_common(1)[0][0] if ports else None


def classify_threat(features: dict, window: list[dict]) -> ThreatType:
    ports = features["unique_dst_ports"]
    ips = features["unique_dst_ips"]
    syn = features["syn_ratio"]
    pps = features["packets_per_sec"]
    std_size = features["std_packet_size"]
    dom_port = _dominant_dst_port(window)
    n = len(window)

    # PORT_SCAN / network sweep: SYN-heavy fan-out across many ports or many hosts.
    if (ports >= 15 or ips >= 15) and syn >= 0.30:
        return ThreatType.PORT_SCAN

    # BRUTE_FORCE: many attempts against a single auth service on few hosts.
    if ports <= 2 and ips <= 3 and n >= 10 and dom_port in AUTH_PORTS:
        return ThreatType.BRUTE_FORCE

    # DDOS: volumetric flood concentrated on one/few targets and ports.
    if pps >= 2.0 and ips <= 2 and ports <= 3:
        return ThreatType.DDOS

    # C2 beacon (best-effort): single host:port, low and very regular volume on a
    # non-standard port. Cross-window periodicity is a future enhancement.
    if ips == 1 and ports == 1 and pps < 2.0 and std_size <= 50 and dom_port not in AUTH_PORTS:
        return ThreatType.C2

    return ThreatType.UNKNOWN_ANOMALY
