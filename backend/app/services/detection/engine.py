"""
Detection engine (task 1.12) — scheduled worker, runs as a SEPARATE process.

Each cycle: read detection_settings (threshold, interval, active model), pull
is_analysed=FALSE rows from network_logs, group them into (source_id, src_ip,
1-minute) windows using the SAME feature extractor as training, score each
window with the Isolation Forest, and for windows at/above the sensitivity
threshold write a detection (severity from the score bands; threat_type is
UNKNOWN_ANOMALY here — task 1.13 adds rule-based categorisation). Finally mark
the processed logs analysed so they're never re-scored.

Run it (from backend/, venv active, DB up, after training IF_v1.0):
    python -m app.services.detection.engine
"""
from __future__ import annotations

import logging
import sys
import time
from collections import Counter
from pathlib import Path

import joblib
import numpy as np

_HERE = Path(__file__).resolve()
_ML_DIR = _HERE.parents[4] / "ml"
sys.path.insert(0, str(_ML_DIR))           # import the shared feature module
sys.path.insert(0, str(_HERE.parents[3]))  # backend/ for app.*

from features import extract_features, group_windows, to_vector  # noqa: E402
from normalize import normalize_score  # noqa: E402
from sqlalchemy import select, update  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.config import settings
from app.services import heartbeat  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import (  # noqa: E402
    Detection, DetectionSettings, NetworkLog,
)
from app.services.detection.severity import severity_for  # noqa: E402
from app.services.detection.rules import classify_threat  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s engine %(levelname)s %(message)s")
logger = logging.getLogger("threatsense.engine")

_MODELS_DIR = _ML_DIR / "models"
# Per-cycle cap. Was a hard-coded 5000. Configurable now because the scoring
# loop below was rewritten to score every window in one vectorised call, which
# removed the cost that made 5000 the ceiling — see run_cycle().
_MAX_LOGS_PER_CYCLE = settings.detection_max_logs_per_cycle
_model_cache: dict[str, dict] = {}


def load_model(version: str) -> dict:
    if version not in _model_cache:
        path = _MODELS_DIR / f"{version}.joblib"
        _model_cache[version] = joblib.load(path)
        logger.info("loaded model %s", path.name)
    return _model_cache[version]


def run_cycle(session: Session) -> tuple[int, int, int]:
    """Returns (logs_processed, detections_created, next_interval_seconds)."""
    cfg = session.scalar(select(DetectionSettings))
    if cfg is None:
        logger.warning("no detection_settings row; skipping cycle")
        return 0, 0, settings.syslog_flush_seconds
    interval = cfg.detection_interval_seconds
    threshold = float(cfg.sensitivity_threshold)
    version = cfg.active_model_version
    bundle = load_model(version)
    model = bundle["model"]
    smin, smax = bundle["score_min"], bundle["score_max"]
    mtype = bundle.get("model_type", "ISOLATION_FOREST")

    logs = session.scalars(
        select(NetworkLog).where(NetworkLog.is_analysed.is_(False))
        .order_by(NetworkLog.timestamp).limit(_MAX_LOGS_PER_CYCLE)
    ).all()
    if not logs:
        return 0, 0, interval

    records = [{
        "source_id": l.source_id, "src_ip": str(l.src_ip), "dst_ip": str(l.dst_ip),
        "dst_port": l.dst_port, "protocol": l.protocol, "packet_size": l.packet_size,
        "flags": l.flags, "timestamp": l.timestamp,
    } for l in logs]

    # Extract features for every window first, then score them all in ONE
    # call. This loop used to invoke model.score_samples() per window on a
    # single-row array. IsolationForest.score_samples walks all 200 trees per
    # call, and that per-call overhead dominated: measured on IF_v1.0, 690
    # windows took 7.367s one-at-a-time versus 0.015s batched — a ~500x
    # difference, with numpy.allclose confirming the scores are identical.
    #
    # That per-window cost was the NFR-01/NFR-02 tension. NFR-02 allows a
    # 10-second cycle; ingestion at the NFR-01 baseline produces far more
    # windows than the old loop could score inside it, which is why the cap
    # sat at 5000. Batching removes the cost rather than trading one
    # requirement off against the other.
    windows = list(group_windows(records).items())
    if not windows:
        session.execute(
            update(NetworkLog)
            .where(NetworkLog.log_id.in_([l.log_id for l in logs]))
            .values(is_analysed=True)
        )
        session.commit()
        return len(logs), 0, interval

    feats_by_window = [extract_features(wlogs) for _key, wlogs in windows]
    matrix = np.array([to_vector(f) for f in feats_by_window], dtype=float)
    raw_scores = model.score_samples(matrix)

    created = 0
    for ((source_id, src_ip, _bucket), wlogs), feats, raw in zip(
            windows, feats_by_window, raw_scores):
        score = normalize_score(float(raw), smin, smax)
        if score >= threshold:
            dst = Counter(r["dst_ip"] for r in wlogs).most_common(1)[0][0]
            session.add(Detection(
                source_id=source_id, source_ip=src_ip, destination_ip=dst,
                timestamp=max(r["timestamp"] for r in wlogs),
                anomaly_score=score, severity=severity_for(score),
                threat_type=classify_threat(feats, wlogs),
                model_version=version, model_type=mtype, feature_vector=feats,
            ))
            created += 1

    session.execute(
        update(NetworkLog)
        .where(NetworkLog.log_id.in_([l.log_id for l in logs]))
        .values(is_analysed=True)
    )
    session.commit()
    return len(logs), created, interval


def main() -> None:
    logger.info("detection engine starting")
    heartbeat.write("detection_engine", status="starting")
    while True:
        interval = settings.syslog_flush_seconds
        with SessionLocal() as session:
            processed, created, interval = run_cycle(session)
        if processed:
            logger.info("cycle: %d logs analysed, %d detections created", processed, created)
        # Written EVERY cycle, including quiet ones. A heartbeat only on
        # productive cycles would read as stale on an idle network, which is
        # precisely when an operator most wants to know the engine is alive.
        heartbeat.write("detection_engine",
                        last_cycle_logs=processed,
                        last_cycle_detections=created,
                        interval_seconds=interval)
        time.sleep(max(1, interval))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("engine stopped")
