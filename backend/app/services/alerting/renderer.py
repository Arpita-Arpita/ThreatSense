"""Render the alert email from a detection (task 2.3, Section 2.5).

Kept separate from the worker so the template can be exercised on its own, and
so the "Send Test Alert" control on the Alert Configuration screen (Figure 6)
can reuse exactly the same layout an operator will receive in production.
"""
from __future__ import annotations

from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from ...config import settings
from ...models import Detection, SeverityLevel

_TEMPLATE = Path(__file__).parent / "templates" / "alert_email.html"

# Matches the dashboard severity palette (Section 7).
_COLOURS = {
    SeverityLevel.LOW: "#0ea5e9",
    SeverityLevel.MEDIUM: "#d97706",
    SeverityLevel.HIGH: "#ea580c",
    SeverityLevel.CRITICAL: "#dc2626",
}

_THREAT_LABELS = {
    "PORT_SCAN": "Port scan",
    "DDOS": "DDoS activity",
    "C2": "Command-and-control traffic",
    "BRUTE_FORCE": "Brute-force attempt",
    "UNKNOWN_ANOMALY": "Unclassified anomaly",
}


@lru_cache(maxsize=1)
def _template() -> str:
    return _TEMPLATE.read_text(encoding="utf-8")


def _value(enum_or_str) -> str:
    return getattr(enum_or_str, "value", str(enum_or_str))


def threat_label(threat_type) -> str:
    key = _value(threat_type)
    return _THREAT_LABELS.get(key, key.replace("_", " ").title())


def subject_for(detection: Detection) -> str:
    return (
        f"[ThreatSense] {_value(detection.severity)}: "
        f"{threat_label(detection.threat_type)} from {detection.source_ip}"
    )


def _fill(template: str, values: dict[str, str]) -> str:
    """Substitute {token} placeholders literally.

    Deliberately not str.format: HTML and CSS are full of braces (media
    queries, <style> blocks), and any stray brace would raise KeyError or
    silently mangle the markup. Plain replacement is brace-safe, so the
    template can be edited freely without breaking rendering.
    """
    for key, value in values.items():
        template = template.replace("{" + key + "}", str(value))
    return template


def render(detection: Detection) -> str:
    """Return the HTML body for one detection."""
    severity = detection.severity
    if not isinstance(severity, SeverityLevel):
        severity = SeverityLevel(_value(severity))

    detected = detection.timestamp or detection.created_at or datetime.now(timezone.utc)
    if detected.tzinfo is None:
        detected = detected.replace(tzinfo=timezone.utc)

    return _fill(_template(), {
        "severity": _value(severity),
        "severity_colour": _COLOURS.get(severity, "#475569"),
        "threat_label": threat_label(detection.threat_type),
        "anomaly_score": f"{float(detection.anomaly_score):.2f}",
        "source_ip": detection.source_ip,
        "destination_ip": detection.destination_ip,
        "detected_at": detected.strftime("%d %b %Y, %H:%M:%S %Z").strip(),
        "model_version": detection.model_version,
        "dashboard_url": settings.dashboard_url.rstrip("/") + "/dashboard",
    })
