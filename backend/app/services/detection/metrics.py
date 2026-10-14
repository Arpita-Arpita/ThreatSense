"""Reads the evaluation artefact written by ml/evaluate.py --json (task 4.2).

The Detection Settings screen shows precision / recall / F1 for the active
model at the configured sensitivity. Those numbers come from task 1.10's
evaluation against held-out synthetic windows — they are NOT recomputed here.

Two rules this module exists to enforce:

  * If the artefact is missing, say so. A security tool that displays invented
    accuracy figures is worse than one that displays none, because the invented
    ones will be believed and quoted.
  * If the artefact is old, report its age. A model retrained after the last
    evaluation would otherwise be described by stale numbers.

The artefact carries a full 0.50-0.99 sweep, so moving the slider re-reads a
precomputed row instead of running inference on every request.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

_ML_DIR = Path(__file__).resolve().parents[3].parent / "ml"
METRICS_DIR = _ML_DIR / "metrics"
MODELS_DIR = _ML_DIR / "models"

GENERATE_HINT = ("Run `cd ml && python evaluate.py --json` to generate it. "
                 "The evaluation needs the trained model in ml/models/.")


def available_versions() -> list[str]:
    """Model versions present on disk, newest name last."""
    if not MODELS_DIR.is_dir():
        return []
    return sorted(p.stem for p in MODELS_DIR.glob("*.joblib"))


def has_metrics(version: str) -> bool:
    return (METRICS_DIR / f"{version}.metrics.json").is_file()


def _load(version: str) -> dict | None:
    path = METRICS_DIR / f"{version}.metrics.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _cache_key(version: str) -> tuple[str, float]:
    """Include mtime so a regenerated artefact invalidates the cache."""
    path = METRICS_DIR / f"{version}.metrics.json"
    return version, path.stat().st_mtime if path.is_file() else 0.0


@lru_cache(maxsize=8)
def _cached(key: tuple[str, float]) -> dict | None:
    return _load(key[0])


def metrics_for(version: str, threshold: float) -> dict:
    """Metrics payload for one model at one threshold. Never raises."""
    data = _cached(_cache_key(version))
    if data is None:
        return {
            "available": False,
            "model_version": version,
            "message": f"No evaluation artefact for {version}. {GENERATE_HINT}",
        }

    sweep = data.get("sweep", [])
    if not sweep:
        return {"available": False, "model_version": version,
                "message": f"The artefact for {version} contains no threshold sweep. "
                           f"{GENERATE_HINT}"}

    # Nearest swept threshold — the sweep is in 0.01 steps and the slider
    # matches, but never assume the two grids line up exactly.
    point = min(sweep, key=lambda row: abs(float(row["threshold"]) - threshold))

    generated_at = None
    stale_days = None
    raw_generated = data.get("generated_at")
    if raw_generated:
        try:
            generated_at = datetime.fromisoformat(raw_generated)
            if generated_at.tzinfo is None:
                generated_at = generated_at.replace(tzinfo=timezone.utc)
            stale_days = (datetime.now(timezone.utc) - generated_at).days
        except ValueError:
            generated_at = None

    key = f"{point['threshold']:.2f}"
    by_kind = {
        kind: curve.get(key)
        for kind, curve in (data.get("recall_by_attack_kind") or {}).items()
        if curve.get(key) is not None
    }

    return {
        "available": True,
        "model_version": data.get("model_version", version),
        "generated_at": generated_at,
        "stale_days": stale_days,
        "threshold": float(point["threshold"]),
        "at_threshold": point,
        "sweep": sweep,
        "recall_by_attack_kind": by_kind,
        "dataset": data.get("dataset", {}),
    }
