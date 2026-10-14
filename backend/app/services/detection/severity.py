"""Severity bands for the normalized anomaly score (task 1.12).

Bands: Low 0.50-0.69, Medium 0.70-0.84, High 0.85-0.94, Critical 0.95-1.0.
(Detections are only created when score >= the sensitivity threshold.)
"""
from __future__ import annotations

from app.models import SeverityLevel


def severity_for(score: float) -> SeverityLevel:
    if score >= 0.95:
        return SeverityLevel.CRITICAL
    if score >= 0.85:
        return SeverityLevel.HIGH
    if score >= 0.70:
        return SeverityLevel.MEDIUM
    return SeverityLevel.LOW
