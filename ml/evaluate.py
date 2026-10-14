"""
Evaluate IF_v1.0 on held-out normal + synthetic attack windows (task 1.10).

Reports precision / recall / F1 at the configured sensitivity threshold —
the numbers that feed the Detection Settings screen. Attack windows
(port_scan / ddos / sweep) are the positives.

    python evaluate.py [threshold]              # print a report
    python evaluate.py --json                   # ALSO write the metrics artefact

The --json form sweeps every threshold from 0.50 to 0.99 and writes
ml/metrics/<version>.metrics.json. The Detection Settings screen (task 4.2)
reads that file, so precision/recall/F1 update live as the sensitivity slider
moves instead of being recomputed per request. Scores are computed once and
re-thresholded, so the sweep costs barely more than a single evaluation.

Re-run it whenever the model is retrained — the API reports the artefact's
age so a stale one is visible rather than silently trusted.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features import extract_features, to_vector  # noqa: E402
from normalize import normalize_score  # noqa: E402
import synth  # noqa: E402

MODELS_DIR = Path(__file__).resolve().parent / "models"
METRICS_DIR = Path(__file__).resolve().parent / "metrics"
VERSION = "IF_v1.0"


def anomaly_scores(bundle, windows) -> np.ndarray:
    X = np.array([to_vector(extract_features(w)) for w in windows], dtype=float)
    raw = bundle["model"].score_samples(X)
    return np.array([normalize_score(s, bundle["score_min"], bundle["score_max"]) for s in raw])


def confusion(s_atk, s_norm, threshold: float) -> dict:
    tp = int((s_atk >= threshold).sum())
    fn = int((s_atk < threshold).sum())
    fp = int((s_norm >= threshold).sum())
    tn = int((s_norm < threshold).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"threshold": round(threshold, 2), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4)}


def write_artefact(s_atk, s_norm, attacks, n_normal: int) -> Path:
    """Sweep 0.50-0.99 and persist, so the UI can read any threshold instantly."""
    sweep = [confusion(s_atk, s_norm, t / 100) for t in range(50, 100)]

    by_kind: dict[str, list] = {}
    for (kind, _w), score in zip(attacks, s_atk):
        by_kind.setdefault(kind, []).append(float(score))
    recall_by_kind = {
        kind: {str(round(t / 100, 2)): round(sum(s >= t / 100 for s in scores) / len(scores), 4)
               for t in range(50, 100)}
        for kind, scores in by_kind.items()
    }

    METRICS_DIR.mkdir(exist_ok=True)
    out = METRICS_DIR / f"{VERSION}.metrics.json"
    out.write_text(json.dumps({
        "model_version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {"normal_windows": n_normal, "attack_windows": len(attacks),
                    "source": "ml/synth.py held-out synthetic windows"},
        "sweep": sweep,
        "recall_by_attack_kind": recall_by_kind,
    }, indent=2) + "\n", encoding="utf-8")
    return out


def main() -> None:
    args = [a for a in sys.argv[1:] if a != "--json"]
    want_json = "--json" in sys.argv
    threshold = float(args[0]) if args else 0.75
    bundle = joblib.load(MODELS_DIR / f"{VERSION}.joblib")

    normal = synth.normal_dataset(600)
    attacks = synth.attack_dataset(200)            # 200 each of 3 kinds = 600 positives
    attack_windows = [w for _, w in attacks]

    s_norm = anomaly_scores(bundle, normal)
    s_atk = anomaly_scores(bundle, attack_windows)

    tp = int((s_atk >= threshold).sum())
    fn = int((s_atk < threshold).sum())
    fp = int((s_norm >= threshold).sum())
    tn = int((s_norm < threshold).sum())

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    print(f"Threshold: {threshold}")
    print(f"  normal  windows: {len(normal)}  (mean score {s_norm.mean():.3f})")
    print(f"  attack  windows: {len(attack_windows)}  (mean score {s_atk.mean():.3f})")
    print(f"  TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"  precision={precision:.3f}  recall={recall:.3f}  f1={f1:.3f}")
    # per-attack-kind recall
    from collections import defaultdict
    by_kind = defaultdict(list)
    for (kind, w), s in zip(attacks, s_atk):
        by_kind[kind].append(s >= threshold)
    for kind, hits in by_kind.items():
        print(f"  recall[{kind}] = {sum(hits)/len(hits):.3f}")

    if want_json:
        path = write_artefact(s_atk, s_norm, attacks, len(normal))
        print(f"\nWrote {path} (thresholds 0.50-0.99).")
        print("The Detection Settings screen reads this file.")


if __name__ == "__main__":
    main()
