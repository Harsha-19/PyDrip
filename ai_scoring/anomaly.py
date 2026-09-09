"""
Anomaly detection module.

Phase 6: Unsupervised batch-level anomaly detection using Isolation Forest.
Maps decision_function outputs to a normalized anomaly_score in [0.0, 1.0],
where higher values indicate higher anomaly.

Contract:
ONE SCAN BATCH -> ONE ANOMALY SCORE in [0.0, 1.0]
"""
from typing import List, Dict, Any, Optional, Union
import numpy as np
from sklearn.ensemble import IsolationForest

from ai_scoring.contract import validate_scan_history, validate_change
from ai_scoring.features import (
    extract_batch_features,
    build_features,
    features_to_matrix,
    FEATURE_COLUMNS
)


class AnomalyDetector:
    """
    Encapsulates a fitted IsolationForest model and its training baseline
    calibration parameters (d_min, d_max) for deterministic [0.0, 1.0] scoring.
    """
    def __init__(
        self,
        n_estimators: int = 100,
        contamination: Union[str, float] = "auto",
        random_state: int = 42
    ):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.model: Optional[IsolationForest] = None
        self.d_min: float = 0.0
        self.d_max: float = 1.0
        self._is_fitted: bool = False

    def fit(self, X_train: np.ndarray) -> "AnomalyDetector":
        """
        Fits IsolationForest on X_train.
        Computes and locks d_min and d_max strictly on X_train.
        """
        if not isinstance(X_train, np.ndarray):
            raise ValueError("X_train must be a numpy.ndarray")
        if X_train.ndim != 2 or X_train.shape[1] != len(FEATURE_COLUMNS):
            raise ValueError(f"X_train must have shape (N, {len(FEATURE_COLUMNS)})")
        if len(X_train) == 0:
            raise ValueError("X_train must not be empty")

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            max_samples="auto",
            contamination=self.contamination,
            max_features=1.0,
            bootstrap=False,
            random_state=self.random_state
        )
        self.model.fit(X_train)

        # Compute and lock baseline calibration boundaries on X_train strictly
        d_train = self.model.decision_function(X_train)
        self.d_min = float(np.min(d_train))
        self.d_max = float(np.max(d_train))
        self._is_fitted = True
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        """
        Computes normalized anomaly scores in [0.0, 1.0] using locked calibration parameters.
        Higher decision_function indicates inliers/normal; subtracting from d_max inverts the scale
        so higher anomaly_score indicates higher anomaly.
        """
        if not self._is_fitted or self.model is None:
            raise RuntimeError("AnomalyDetector must be fitted before scoring")
        if not isinstance(X, np.ndarray):
            raise ValueError("Input X must be a numpy.ndarray")
        if X.ndim == 1:
            X = X.reshape(1, -1)
        if X.shape[1] != len(FEATURE_COLUMNS):
            raise ValueError(f"Input X must have shape (N, {len(FEATURE_COLUMNS)})")

        d = self.model.decision_function(X)
        
        # Inverted normalization formula:
        # Most normal (d = d_max) -> 0.0
        # Most anomalous (d <= d_min) -> 1.0
        spread = self.d_max - self.d_min
        if spread <= 1e-9:
            normalized = np.zeros_like(d, dtype=np.float64)
        else:
            normalized = (self.d_max - d) / spread
            
        return np.clip(normalized, 0.0, 1.0)


def fit_anomaly_model(
    scan_history: List[Dict[str, Any]],
    n_estimators: int = 100,
    contamination: Union[str, float] = "auto",
    random_state: int = 42
) -> AnomalyDetector:
    """
    Fits an AnomalyDetector on historical scan history.
    Extracts features chronologically to avoid data leakage.
    """
    if not isinstance(scan_history, list) or not scan_history:
        raise ValueError("scan_history must be a non-empty list")
    if not validate_scan_history(scan_history):
        raise ValueError("scan_history failed contract validation")

    records = extract_batch_features(scan_history)
    _, X_train = features_to_matrix(records)

    detector = AnomalyDetector(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state
    )
    detector.fit(X_train)
    return detector


def score_batch_anomaly(
    detector: AnomalyDetector,
    feature_record: Dict[str, Any]
) -> float:
    """
    Scores a single batch feature dictionary, returning a normalized float in [0.0, 1.0].
    """
    if not isinstance(feature_record, dict):
        raise ValueError("feature_record must be a dictionary")

    row = [float(feature_record[col]) for col in FEATURE_COLUMNS]
    X = np.array([row], dtype=np.float64)
    score_arr = detector.score(X)
    return round(float(score_arr[0]), 4)


def detect_anomalies(
    change_batch: List[Dict[str, Any]],
    scan_history: List[Dict[str, Any]],
    detector: Optional[AnomalyDetector] = None
) -> float:
    """
    High-level entry point maintaining scaffold compatibility:
    1. Determines incoming batch timestamp.
    2. Filters scan_history strictly to scans prior to the batch timestamp to prevent future leakage.
    3. Extracts batch features relative to prior history.
    4. Fits detector on baseline scan_history (if detector is None).
    5. Returns normalized anomaly score in [0.0, 1.0].
    """
    if not isinstance(change_batch, list):
        raise ValueError("change_batch must be a list")
    for ch in change_batch:
        if not validate_change(ch):
            raise ValueError(f"Invalid change record: {ch}")
            
    if not isinstance(scan_history, list) or not scan_history:
        raise ValueError("scan_history must be a non-empty list")
        
    # Determine batch timestamp
    batch_ts = None
    for ch in change_batch:
        if ch.get("detected_at"):
            batch_ts = ch["detected_at"]
            break

    # Filter historical scans strictly prior to batch timestamp to prevent future-history leakage
    if batch_ts:
        prior_history = [s for s in scan_history if s.get("detected_at") and s["detected_at"] < batch_ts]
        # If no scans are prior to batch_ts (e.g. batch occurs at the start of history), use scan_history
        hist_for_features = prior_history if prior_history else scan_history
    else:
        hist_for_features = scan_history

    batch_feat = build_features(change_batch, hist_for_features, detected_at=batch_ts)

    if detector is None:
        detector = fit_anomaly_model(scan_history)

    return score_batch_anomaly(detector, batch_feat)
