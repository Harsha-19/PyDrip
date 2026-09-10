import numpy as np
from sklearn.ensemble import IsolationForest

class IsolationForestDetector:
    """
    Isolation Forest anomaly detector for evaluating batches of file changes.
    Used to detect unusual scan volumes or patterns (e.g., mass modification).
    """
    def __init__(self, random_state: int = 42, min_samples_for_training: int = 10):
        self.random_state = random_state
        self.min_samples_for_training = min_samples_for_training
        # Base estimator. contamination="auto" computes the offset.
        self.model = IsolationForest(
            random_state=self.random_state,
            n_estimators=100,
            contamination="auto",
            n_jobs=1  # CPU-friendly
        )
        self.is_fitted = False
        
    def _extract_features(self, scan_data: dict) -> np.ndarray:
        """
        Extracts a numeric feature vector from a scan representation.
        Expected keys in scan_data:
        - files_changed (int)
        - time_of_day (float 0-24)
        - directory_cluster_count (int)
        - change_velocity (float)
        """
        return np.array([
            float(scan_data.get("files_changed", 0.0)),
            float(scan_data.get("time_of_day", 0.0)),
            float(scan_data.get("directory_cluster_count", 0.0)),
            float(scan_data.get("change_velocity", 0.0))
        ]).reshape(1, -1)

    def fit(self, historical_scans: list[dict]):
        """
        Fits the Isolation Forest on historical scan data.
        Silently gracefully falls back if insufficient data.
        """
        if len(historical_scans) < self.min_samples_for_training:
            self.is_fitted = False
            return
            
        # Extract features for all historical scans
        features = np.vstack([self._extract_features(scan) for scan in historical_scans])
        self.model.fit(features)
        self.is_fitted = True

    def score(self, current_scan: dict) -> dict:
        """
        Scores a current scan. 
        Returns a dictionary with the normalized score and raw explainability features.
        
        Normalized anomaly score:
        0.0 = completely normal
        1.0 = highly anomalous
        """
        if not self.is_fitted:
            # Fallback behavior if insufficient history: assume not anomalous 
            # to avoid false positives.
            return {
                "anomaly_score": 0.0,
                "is_fallback": True,
                "reason": "Insufficient historical data for anomaly detection"
            }
            
        features = self._extract_features(current_scan)
        
        # Raw score from IsolationForest
        # It is negative for anomalies, positive for normal data
        raw_decision_score = self.model.decision_function(features)[0]
        
        # Normalize decision function mapping roughly [-0.5, 0.5] to [1.0, 0.0]
        # raw_decision_score > 0 -> normal -> score should be close to 0
        # raw_decision_score < 0 -> anomaly -> score should be close to 1
        normalized_score = 0.5 - raw_decision_score
        
        # Clamp between 0.0 and 1.0
        anomaly_score = max(0.0, min(1.0, float(normalized_score)))
        
        # Provide explainability data
        return {
            "anomaly_score": anomaly_score,
            "raw_decision_value": float(raw_decision_score),
            "features_used": {
                "files_changed": current_scan.get("files_changed", 0),
                "time_of_day": current_scan.get("time_of_day", 0.0),
                "directory_cluster_count": current_scan.get("directory_cluster_count", 0),
                "change_velocity": current_scan.get("change_velocity", 0.0)
            },
            "is_fallback": False
        }
