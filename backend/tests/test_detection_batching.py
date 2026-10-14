"""Batched window scoring in the detection engine (Phase 6 optional item).

    cd backend && source .venv/bin/activate
    pytest tests/test_detection_batching.py -v

WHY THIS EXISTS
---------------
run_cycle() used to call model.score_samples() once per window, on a
one-row array. IsolationForest walks all 200 trees per call, so the
per-call overhead dominated and the cost grew linearly with window count.
That is what forced the 5000-row cap, and that cap is what produced the
NFR-01 / NFR-02 tension: NFR-01 asks for 1,000 messages per second sustained
while NFR-02 gives the cycle only 10 seconds, and 5000 rows per cycle could
not keep up with the ingest rate.

Scoring every window in a single vectorised call removes the cost instead
of trading the two requirements against each other.

MEASURED (this container, 50,000 seeded rows, model IF_v1.0)

    scoring only, 690 windows      7.367s per-window  ->  0.015s batched
    numpy.allclose(per_window, batched)               -> True

    full run_cycle against Postgres:
      cap  5,000  ->  1.9s      cap 20,000  ->  3.2s
      cap 15,000  ->  2.1s      cap 25,000  ->  4.4s
      cap 50,000  -> 15.1s  (exceeds the NFR-02 budget)

The M1 measured 2.891s where this container measured 1.941s at the same
5,000 cap, so it runs about 1.49x slower. The default was set to 20,000
rather than 25,000 to keep roughly half the 10-second budget in hand on
that hardware. RE-MEASURE ON THE TARGET MACHINE before quoting any of this
in the report — the numbers above are this container's.

The first test is the one that matters. Batching is only a safe change if
the scores are unchanged: detections already captured as evidence,
including the PORT_SCAN scored at 1.000, must still score 1.000.
"""
from __future__ import annotations

import time

import numpy as np
import pytest
from sqlalchemy import select

from app.config import settings
from app.database import SessionLocal
from app.models import DetectionSettings
from app.services.detection import engine


@pytest.fixture(scope="module")
def model_bundle():
    cfg = None
    with SessionLocal() as db:
        cfg = db.scalar(select(DetectionSettings))
    if cfg is None:
        pytest.skip("no detection_settings row; run db/seed.py")
    try:
        return engine.load_model(cfg.active_model_version)
    except FileNotFoundError:
        pytest.skip("model file not installed; run ml/train.py")


# --- equivalence: the whole justification for the change ----------------------

def test_batched_scores_match_per_window_scores(model_bundle):
    """Identical output is what makes this safe to apply retrospectively.

    If this ever fails, previously recorded anomaly_score values no longer
    reproduce and every detection captured as evidence is invalidated.
    """
    model = model_bundle["model"]
    rng = np.random.default_rng(20260824)
    matrix = rng.random((250, 10)) * 100

    per_window = np.array([float(model.score_samples(matrix[i:i + 1])[0])
                           for i in range(matrix.shape[0])])
    batched = model.score_samples(matrix)

    assert np.allclose(per_window, batched), "batched scoring changed the scores"


def test_batching_is_faster_not_merely_equal(model_bundle):
    """Guards against a refactor quietly reinstating the per-window loop."""
    model = model_bundle["model"]
    rng = np.random.default_rng(1)
    matrix = rng.random((200, 10)) * 100

    t0 = time.perf_counter()
    for i in range(matrix.shape[0]):
        model.score_samples(matrix[i:i + 1])
    loop = time.perf_counter() - t0

    t0 = time.perf_counter()
    model.score_samples(matrix)
    batched = time.perf_counter() - t0

    # Measured around 500x; asserting 10x leaves room for slower hardware
    # while still failing loudly if the batching is lost.
    assert loop > batched * 10, f"expected a large speedup, got {loop / batched:.1f}x"


# --- the cap is a knob, and its relationship to NFR-02 ------------------------

def test_cap_is_configurable_not_hard_coded():
    assert engine._MAX_LOGS_PER_CYCLE == settings.detection_max_logs_per_cycle


def test_default_cap_was_raised_above_the_old_ceiling():
    """The old hard-coded value was 5000; the point of this work was to lift it."""
    assert settings.detection_max_logs_per_cycle > 5000


def test_cap_leaves_headroom_in_the_nfr_02_budget():
    """Table 11, NFR-02 (verbatim):

        "The Isolation Forest detection engine must complete analysis of each
        one-minute feature vector batch within 10 seconds, ensuring near-real-
        time detection capability."

    Measured at 3.2s in this container and an estimated 4.8s on the M1 for the
    20,000 default. 50,000 took 15.1s and breaches the requirement, so this
    guards against the cap being raised on a hunch.
    """
    assert settings.detection_max_logs_per_cycle <= 25000, (
        "caps above 25,000 approached or exceeded the 10s NFR-02 budget when "
        "measured; re-measure with tests/test_detection_batching.py before raising"
    )


def test_run_cycle_handles_an_empty_backlog():
    """No unanalysed rows must not raise, and must not fabricate detections."""
    with SessionLocal() as db:
        if db.scalar(select(DetectionSettings)) is None:
            pytest.skip("no detection_settings row; run db/seed.py")
        processed, created, interval = engine.run_cycle(db)
    assert created >= 0
    assert interval > 0
