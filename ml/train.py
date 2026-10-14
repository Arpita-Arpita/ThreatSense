"""
Train the Isolation Forest on synthetic NORMAL traffic, save as IF_v1.0 (task 1.10).

    python train.py                 # trains, evaluates, writes ml/models/IF_v1.0.joblib
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features import FEATURE_NAMES, extract_features, to_vector  # noqa: E402
import synth  # noqa: E402

MODEL_VERSION = "IF_v1.0"
N_TRAIN_WINDOWS = 4000
N_TREES = 200
MODELS_DIR = Path(__file__).resolve().parent / "models"


def build_matrix(windows: list[list[dict]]) -> np.ndarray:
    return np.array([to_vector(extract_features(w)) for w in windows], dtype=float)


def main() -> None:
    print(f"Generating {N_TRAIN_WINDOWS} synthetic normal windows...")
    X = build_matrix(synth.normal_dataset(N_TRAIN_WINDOWS))
    print(f"Feature matrix: {X.shape}  (features: {', '.join(FEATURE_NAMES)})")

    model = IsolationForest(n_estimators=N_TREES, contamination="auto", random_state=42)
    model.fit(X)

    scores = model.score_samples(X)              # lower = more anomalous
    score_min, score_max = float(scores.min()), float(scores.max())

    bundle = {
        "version": MODEL_VERSION,
        "model": model,
        "model_type": "ISOLATION_FOREST",
        "feature_names": FEATURE_NAMES,
        "score_min": score_min,
        "score_max": score_max,
        "n_estimators": N_TREES,
        "n_train_windows": N_TRAIN_WINDOWS,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "training_source": "synthetic pipeline-shaped normal traffic (MVP)",
    }
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    out = MODELS_DIR / f"{MODEL_VERSION}.joblib"
    joblib.dump(bundle, out)
    print(f"Saved {out}  (score range [{score_min:.3f}, {score_max:.3f}])")


if __name__ == "__main__":
    main()
