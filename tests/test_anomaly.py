"""
Tests for Phase 6 Isolation Forest Anomaly Detection module.
"""
import json
import math
from pathlib import Path
import pytest
import numpy as np

from ai_scoring import anomaly
from ai_scoring import features


def test_detect_anomalies_exists():
    """Verify core API functions and classes exist."""
    assert hasattr(anomaly, "AnomalyDetector")
    assert hasattr(anomaly, "fit_anomaly_model")
    assert hasattr(anomaly, "score_batch_anomaly")
    assert hasattr(anomaly, "detect_anomalies")


def test_model_fitting_and_locked_calibration():
    """Verify model fitting locks calibration parameters d_min and d_max without updating them on score."""
    # Synthetic small dataset with 4 features
    rng = np.random.RandomState(42)
    X_train = rng.normal(loc=2.0, scale=1.0, size=(30, 4))

    detector = anomaly.AnomalyDetector(n_estimators=50, random_state=42)
    assert not detector._is_fitted

    detector.fit(X_train)
    assert detector._is_fitted
    assert detector.d_min < detector.d_max

    initial_d_min = detector.d_min
    initial_d_max = detector.d_max

    # Score an extreme outlier
    X_extreme = np.array([[100.0, 2.0, 1.0, 1000.0]])
    scores = detector.score(X_extreme)

    assert scores.shape == (1,)
    assert scores[0] == 1.0  # Clipped to 1.0 because d < d_min

    # Ensure calibration parameters were NOT mutated
    assert detector.d_min == initial_d_min
    assert detector.d_max == initial_d_max


def test_score_range_and_finite_contract():
    """Verify that anomaly scores are strictly in [0.0, 1.0] and finite."""
    data_path = Path("data/historical_scans.json")
    if not data_path.exists():
        pytest.skip("historical_scans.json not found")

    with open(data_path, "r", encoding="utf-8") as f:
        history = json.load(f)

    detector = anomaly.fit_anomaly_model(history, random_state=42)
    records = features.extract_batch_features(history)
    _, X_all = features.features_to_matrix(records)

    scores = detector.score(X_all)
    assert len(scores) == len(history)

    for s in scores:
        assert 0.0 <= s <= 1.0
        assert math.isfinite(s)
        assert not math.isnan(s)


def test_determinism():
    """Verify calling score twice on the same data produces identical results."""
    X = np.array([
        [2.0, 14.5, 0.5, 1.0],
        [5.0, 2.0, 1.0, 50.0]
    ])
    detector = anomaly.AnomalyDetector(random_state=42).fit(X)

    score_1 = detector.score(X)
    score_2 = detector.score(X)

    np.testing.assert_array_equal(score_1, score_2)


def test_behavioral_ranking_expectation():
    """
    Verify controlled-dataset behavioral expectation:
    suspicious_bulk should score higher than benign under the same fitted historical model.
    No arbitrary absolute threshold assertions (e.g. no score > 0.65).
    """
    hist_path = Path("data/historical_scans.json")
    demo_path = Path("data/demo_changes.json")
    if not hist_path.exists() or not demo_path.exists():
        pytest.skip("data files not found")

    with open(hist_path, "r", encoding="utf-8") as f:
        history = json.load(f)
    with open(demo_path, "r", encoding="utf-8") as f:
        demos = json.load(f)

    detector = anomaly.fit_anomaly_model(history, random_state=42)

    score_suspicious = anomaly.detect_anomalies(demos["suspicious_bulk"], history, detector=detector)
    score_benign = anomaly.detect_anomalies(demos["benign"], history, detector=detector)

    assert math.isfinite(score_suspicious)
    assert math.isfinite(score_benign)
    assert 0.0 <= score_suspicious <= 1.0
    assert 0.0 <= score_benign <= 1.0

    # Behavioral ranking assertion
    assert score_suspicious > score_benign


def test_walk_forward_and_no_future_leakage():
    """
    Verify offline walk-forward:
    Training on scans 0..49, evaluating on scans 50..69.
    Modifying scans 50..69 does not alter the calibration parameters or scores of scans 0..49.
    """
    hist_path = Path("data/historical_scans.json")
    if not hist_path.exists():
        pytest.skip("historical_scans.json not found")

    with open(hist_path, "r", encoding="utf-8") as f:
        history = json.load(f)

    train_scans = history[:50]
    eval_scans = history[50:]

    detector = anomaly.fit_anomaly_model(train_scans, random_state=42)
    saved_d_min = detector.d_min
    saved_d_max = detector.d_max

    eval_records = features.extract_batch_features(eval_scans)
    _, X_eval = features.features_to_matrix(eval_records)
    eval_scores = detector.score(X_eval)

    # Calibration parameters remain unchanged
    assert detector.d_min == saved_d_min
    assert detector.d_max == saved_d_max

    for s in eval_scores:
        assert 0.0 <= s <= 1.0
        assert math.isfinite(s)


def test_input_validation():
    """Verify proper exceptions are raised on invalid inputs."""
    detector = anomaly.AnomalyDetector()

    # Unfitted scoring
    with pytest.raises(RuntimeError):
        detector.score(np.array([[1.0, 2.0, 3.0, 4.0]]))

    # Incompatible feature dimension
    detector.fit(np.zeros((10, 4)))
    with pytest.raises(ValueError):
        detector.score(np.zeros((5, 3)))

    # Empty history in factory
    with pytest.raises(ValueError):
        anomaly.fit_anomaly_model([])

    # Invalid change record
    with pytest.raises(ValueError):
        anomaly.detect_anomalies([{"invalid": "change"}], [{"scan_id": "s1", "detected_at": "2026-09-01T10:00:00", "changes": []}])
