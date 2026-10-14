"""Map IsolationForest.score_samples() -> normalized 0..1 anomaly score (task 1.10).

score_samples returns a value where LOWER = more anomalous. Using the score
range observed on the (normal) training set, we map to 0..1 where 1 = most
anomalous, clipped to the unit interval.
"""
from __future__ import annotations


def normalize_score(raw_score: float, score_min: float, score_max: float) -> float:
    if score_max <= score_min:
        return 0.0
    a = (score_max - raw_score) / (score_max - score_min)
    return max(0.0, min(1.0, a))
