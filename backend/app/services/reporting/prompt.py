"""Minimum-metadata prompt builder (task 3.2, Algorithm 5, Section 2.6).

Only the fields Algorithm 5 names are sent to the LLM: threat category,
normalised anomaly score, severity, source/destination IP, a protocol-level
summary of the related traffic, and a feature-vector summary. Raw log lines
(network_logs.raw_message) and anything person-identifying never leave the
database — the related-log query below selects aggregates only, so a payload
or hostname in a raw syslog line cannot leak into the prompt by accident.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from numbers import Number

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...models import Detection, NetworkLog
from .llm_client import REPORT_SECTIONS

# How far back from the detection timestamp the related-traffic summary looks.
# Matches the detection engine's batch horizon: the logs that produced the
# detection are inside this window.
# Algorithm 2 groups network_logs into ONE-MINUTE CALENDAR BUCKETS —
# ml/features.py::group_windows keys on timestamp.replace(second=0,
# microsecond=0) — and Detection.timestamp is the LAST log timestamp inside
# that bucket, not the bucket boundary.
#
# That distinction matters. A rolling "detection.timestamp minus one minute"
# window is NOT the detection's window: for a detection at 12:30:20 it spans
# 12:29:20-12:30:20, so forty seconds of the PREVIOUS bucket — traffic the
# model never scored, belonging to a different detection — is summarised into
# this incident's report. Narrowing fifteen minutes to a rolling one minute
# reduced that error without eliminating it.
#
# The scope is therefore derived from the bucket itself (see
# detection_window_start), and this constant only describes the bucket's
# width for the prompt text and the TrafficSummary schema.
RELATED_LOG_WINDOW_MINUTES = 1

_THREAT_LABELS = {
    "PORT_SCAN": "Port scan",
    "DDOS": "DDoS activity",
    "C2": "Command-and-control traffic",
    "BRUTE_FORCE": "Brute-force attempt",
    "UNKNOWN_ANOMALY": "Unknown anomaly",
}

SYSTEM_PROMPT = (
    "You are the incident-report writer inside ThreatSense, a network threat "
    "detection system. You write concise, professional reports for a "
    "non-technical audience (managers, auditors). You are given only summary "
    "metadata about one detection — never raw logs. Do not invent hosts, "
    "usernames, applications or events that are not in the metadata. Do not "
    "include code, tables or links.\n\n"
    "Respond with exactly these four markdown sections, in this order, each "
    "as a level-2 heading followed by one or two short paragraphs:\n"
    + "\n".join(f"## {s}" for s in REPORT_SECTIONS)
)


def detection_window_start(detection: Detection) -> datetime:
    """Start of the calendar minute the detection was scored in.

    Mirrors ml/features.py::group_windows, which buckets records with
    timestamp.replace(second=0, microsecond=0). Keeping the derivation here in
    one place means the report summary, the View Traffic panel and the feature
    extractor all describe the same minute.
    """
    return detection.timestamp.replace(second=0, microsecond=0)


def summarise_related_logs(db: Session, detection: Detection) -> dict:
    """Aggregate the traffic behind a detection. Aggregates only — no rows.

    Scope: same data source, same source IP, inside the detection's own
    one-minute bucket, from the start of that minute up to and including the
    detection timestamp. Traffic from the preceding bucket is excluded because
    it belongs to a different detection; traffic AFTER the detection timestamp
    is excluded because the model never saw it. Returns {} when nothing matches
    (e.g. injected test detections), and the prompt simply omits the traffic
    summary.
    """
    since = detection_window_start(detection)
    scope = (
        (NetworkLog.source_id == detection.source_id)
        & (NetworkLog.src_ip == detection.source_ip)
        & (NetworkLog.timestamp >= since)
        & (NetworkLog.timestamp <= detection.timestamp)
    )

    totals = db.execute(
        select(
            func.count(),
            func.count(func.distinct(NetworkLog.dst_port)),
            func.count(func.distinct(NetworkLog.dst_ip)),
            func.min(NetworkLog.packet_size),
            func.avg(NetworkLog.packet_size),
            func.max(NetworkLog.packet_size),
        ).where(scope)
    ).one()
    total = totals[0] or 0
    if total == 0:
        return {}

    protocols = {
        proto: n
        for proto, n in db.execute(
            select(NetworkLog.protocol, func.count()).where(scope)
            .group_by(NetworkLog.protocol).order_by(func.count().desc())
        )
    }
    top_ports = [
        int(port)
        for (port,) in db.execute(
            select(NetworkLog.dst_port).where(scope & NetworkLog.dst_port.isnot(None))
            .group_by(NetworkLog.dst_port).order_by(func.count().desc()).limit(5)
        )
    ]
    return {
        "events": total,
        "protocols": protocols,
        "distinct_dst_ports": totals[1] or 0,
        "distinct_dst_ips": totals[2] or 0,
        "top_dst_ports": top_ports,
        "packet_size_bytes": {
            "min": int(totals[3]), "avg": round(float(totals[4]), 1), "max": int(totals[5]),
        },
        "window_minutes": RELATED_LOG_WINDOW_MINUTES,
    }


def _feature_summary(feature_vector: dict) -> list[str]:
    """Engineered feature names + rounded values. Skips anything non-numeric
    defensively, so a future feature carrying text can never enter the prompt."""
    lines = []
    for key in sorted(feature_vector):
        value = feature_vector[key]
        if isinstance(value, bool) or not isinstance(value, Number):
            continue
        lines.append(f"  - {key}: {round(float(value), 4)}")
    return lines


def build_user_prompt(detection: Detection, log_summary: dict) -> str:
    """Assemble the metadata block Algorithm 5 allows — nothing else."""
    threat = detection.threat_type.value
    lines = [
        "Write the incident report for this detection.",
        "",
        "Detection metadata:",
        f"- Threat category: {_THREAT_LABELS.get(threat, threat)} ({threat})",
        f"- Normalised anomaly score: {detection.anomaly_score:.2f} (scale 0.00-1.00)",
        f"- Severity: {detection.severity.value}",
        f"- Source IP: {detection.source_ip}",
        f"- Destination IP: {detection.destination_ip}",
        f"- Detected at: {detection.timestamp.isoformat()}",
        f"- Detection model: {detection.model_type} {detection.model_version}",
    ]
    if log_summary:
        proto = ", ".join(f"{p}: {n}" for p, n in log_summary["protocols"].items())
        pkt = log_summary["packet_size_bytes"]
        lines += [
            "",
            # The scope is the detection's calendar-minute bucket up to the
            # detection timestamp (see detection_window_start), NOT a rolling
            # window ending there. For a detection at 12:30:20 the data covers
            # 12:30:00-12:30:20. The model is told what it is actually being
            # given, so it cannot describe the summary as "the last minute of
            # traffic" in a report an administrator will read.
            "Related traffic summary (same source IP, detection minute up to "
            "detection time):",
            f"- Events observed: {log_summary['events']}",
            f"- Protocol distribution: {proto}",
            f"- Distinct destination ports: {log_summary['distinct_dst_ports']}"
            f" (most contacted: {', '.join(map(str, log_summary['top_dst_ports'])) or 'n/a'})",
            f"- Distinct destination IPs: {log_summary['distinct_dst_ips']}",
            f"- Packet size bytes (min/avg/max): {pkt['min']}/{pkt['avg']}/{pkt['max']}",
        ]
    features = _feature_summary(detection.feature_vector or {})
    if features:
        lines += ["", "Model feature summary (normalised inputs):", *features]
    return "\n".join(lines)
