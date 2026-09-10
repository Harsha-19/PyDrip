"""
Feature engineering module.

Phase 5: Deterministic batch-level feature engineering for Isolation Forest (Phase 6).
Converts raw scan batches into numerical feature vectors.

Contract:
ONE SCAN BATCH -> ONE FEATURE VECTOR

Features:
1. number_of_files_changed: int (number of change events in batch, len(batch["changes"]))
2. time_of_day: float (decimal hour in [0.0, 24.0))
   * Note on time representation: Decimal hour (e.g. 02:00 -> 2.0, 14:00 -> 14.0) provides
     a single, highly explainable feature aligned with off-hours cybersecurity heuristics.
     Known MVP trade-off: unlike 2D cyclical encoding [sin, cos], decimal hour has a
     discontinuity at midnight (23:59 vs 00:01).
3. directory_clustering: float (concentration ratio in [0.0, 1.0])
4. change_velocity: float (instantaneous rate vs historical median baseline, uncapped)
"""
import datetime
import posixpath
import statistics
from typing import List, Dict, Any, Optional, Tuple
import numpy as np

from ai_scoring.contract import validate_scan_history, validate_change


FEATURE_COLUMNS: List[str] = [
    "number_of_files_changed",
    "time_of_day",
    "directory_clustering",
    "change_velocity"
]


def extract_directory(file_path: str) -> str:
    """
    Extracts normalized parent directory from a file path.
    Handles POSIX and Windows separators, root-level files, and nested directories.
    
    Examples:
        '/configs/app.conf' -> '/configs'
        '/app/config/security/auth.conf' -> '/app/config/security'
        '/file.conf' -> '/'
        'file.conf' -> '/'
    """
    normalized = file_path.replace("\\", "/").rstrip("/")
    if not normalized or normalized == "/":
        return "/"
    
    dirname = posixpath.dirname(normalized)
    if not dirname or dirname == "":
        return "/"
    return dirname


def compute_directory_clustering(changes: List[Dict[str, Any]]) -> float:
    """
    Derives directory concentration ratio:
    max(files in any single directory) / total_change_events.
    
    Returns:
        float in [0.0, 1.0] (0.0 if empty, 1.0 if all files in 1 dir or single file).
    """
    if not changes:
        return 0.0
    
    dir_counts: Dict[str, int] = {}
    for change in changes:
        fp = change.get("file_path", "")
        d = extract_directory(fp)
        dir_counts[d] = dir_counts.get(d, 0) + 1
        
    max_count = max(dir_counts.values())
    return round(float(max_count) / float(len(changes)), 4)


def parse_time_of_day(detected_at_str: str) -> float:
    """
    Converts ISO-8601 timestamp string into decimal hour in [0.0, 24.0).
    
    Example:
        '2026-09-08T14:30:00' -> 14.5
        '2026-09-09T02:00:00' -> 2.0
        '2026-09-09T00:00:00' -> 0.0
    """
    dt = datetime.datetime.fromisoformat(detected_at_str)
    dec_hour = dt.hour + (dt.minute / 60.0) + (dt.second / 3600.0) + (dt.microsecond / 3600000000.0)
    return round(dec_hour, 4)


def parse_timestamp(detected_at_str: str) -> float:
    """Parses ISO-8601 timestamp string to POSIX epoch seconds."""
    dt = datetime.datetime.fromisoformat(detected_at_str)
    return dt.timestamp()


def extract_batch_features(
    scan_history: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Extracts deterministic numerical feature records for an entire scan history.
    
    Chronological Processing & No Future Leakage:
    - Scans are processed in order.
    - For scan k, historical baseline velocity is calculated strictly using
      instantaneous velocities observed in scans prior to k (0...k-1).
    - Scan 0 and Scan 1 receive a neutral change_velocity default of 1.0.
    - The change velocity ratio is NOT artificially capped/clamped. Large ratios
      (e.g., 100, 500, 1200) remain intact for Phase 6 anomaly detection.
    
    Returns:
        List of dicts, one per scan batch.
    """
    if not isinstance(scan_history, list):
        raise ValueError("scan_history must be a list")
    
    if not validate_scan_history(scan_history):
        raise ValueError("scan_history failed contract validation")
        
    if not scan_history:
        return []

    feature_records: List[Dict[str, Any]] = []
    velocities_history: List[float] = []

    for i, scan in enumerate(scan_history):
        scan_id = scan.get("scan_id", f"scan_{i:03d}")
        changes = scan.get("changes", [])
        
        # 1. Number of files changed (number of change events in batch)
        n_files = len(changes)
        
        # 2. Time of day
        detected_at = scan.get("detected_at")
        if not detected_at or not isinstance(detected_at, str):
            raise ValueError(f"Scan '{scan_id}' missing valid 'detected_at' timestamp")
        tod = parse_time_of_day(detected_at)
        
        # 3. Directory clustering
        clustering = compute_directory_clustering(changes)
        
        # 4. Change velocity vs historical baseline
        curr_ts = parse_timestamp(detected_at)
        
        if i == 0:
            # First scan in history: no prior interval or baseline
            velocity_ratio = 1.0
        else:
            prev_detected_at = scan_history[i - 1].get("detected_at")
            if not prev_detected_at or not isinstance(prev_detected_at, str):
                raise ValueError(f"Scan '{scan_history[i - 1].get('scan_id')}' missing valid 'detected_at'")
            prev_ts = parse_timestamp(prev_detected_at)
            
            delta_seconds = curr_ts - prev_ts
            # Clamp elapsed time to minimum 1 minute (1/60 hour) to prevent division by zero / negative
            delta_hours = max(delta_seconds / 3600.0, 1.0 / 60.0)
            current_velocity = float(n_files) / delta_hours
            
            if not velocities_history:
                # First interval observed (scan 1): no prior velocity baseline yet
                velocity_ratio = 1.0
            else:
                historical_median = statistics.median(velocities_history)
                # Avoid division by zero if all prior scans had 0 changes
                baseline_vel = max(historical_median, 0.05)
                # Uncapped, un-clamped ratio
                velocity_ratio = current_velocity / baseline_vel
                
            # Append current_velocity strictly after calculating feature for scan i
            velocities_history.append(current_velocity)
            
        feature_records.append({
            "scan_id": scan_id,
            "number_of_files_changed": n_files,
            "time_of_day": tod,
            "directory_clustering": clustering,
            "change_velocity": round(float(velocity_ratio), 4)
        })

    return feature_records


def build_features(
    change_batch: List[Dict[str, Any]],
    scan_history: List[Dict[str, Any]],
    detected_at: Optional[str] = None
) -> Dict[str, Any]:
    """
    Extracts the feature vector for a single incoming change batch relative
    to an existing scan history baseline (used during score_changes).
    
    Args:
        change_batch: List of incoming change dicts.
        scan_history: List of historical scan dicts.
        detected_at: Optional timestamp string for incoming batch. If not provided,
                     infers from changes or defaults to current time.
    """
    if not isinstance(change_batch, list):
        raise ValueError("change_batch must be a list")
    for ch in change_batch:
        if not validate_change(ch):
            raise ValueError(f"Invalid change record: {ch}")
            
    n_files = len(change_batch)
    
    # Determine timestamp
    if not detected_at:
        # Try inferring from first change with detected_at
        for ch in change_batch:
            if ch.get("detected_at"):
                detected_at = ch["detected_at"]
                break
        if not detected_at:
            detected_at = datetime.datetime.now().isoformat()
            
    tod = parse_time_of_day(detected_at)
    clustering = compute_directory_clustering(change_batch)
    
    # Calculate velocity relative to scan_history baseline
    if not scan_history or len(scan_history) < 2:
        velocity_ratio = 1.0
    else:
        # Calculate historical velocities
        hist_velocities = []
        for j in range(1, len(scan_history)):
            prev_t = parse_timestamp(scan_history[j - 1]["detected_at"])
            curr_t = parse_timestamp(scan_history[j]["detected_at"])
            delta_h = max((curr_t - prev_t) / 3600.0, 1.0 / 60.0)
            vel = float(len(scan_history[j].get("changes", []))) / delta_h
            hist_velocities.append(vel)
            
        hist_median = statistics.median(hist_velocities) if hist_velocities else 0.5
        baseline_vel = max(hist_median, 0.05)
        
        last_scan_t = parse_timestamp(scan_history[-1]["detected_at"])
        curr_batch_t = parse_timestamp(detected_at)
        delta_h = max((curr_batch_t - last_scan_t) / 3600.0, 1.0 / 60.0)
        current_vel = float(n_files) / delta_h
        velocity_ratio = current_vel / baseline_vel

    return {
        "scan_id": "current_batch",
        "number_of_files_changed": n_files,
        "time_of_day": tod,
        "directory_clustering": clustering,
        "change_velocity": round(float(velocity_ratio), 4)
    }


def features_to_matrix(
    feature_records: List[Dict[str, Any]],
    feature_columns: Optional[List[str]] = None
) -> Tuple[List[str], np.ndarray]:
    """
    Converts a list of feature dictionaries into a 2D NumPy array
    ready for scikit-learn IsolationForest input in Phase 6.
    
    Returns:
        (feature_columns_used, 2D float64 numpy array of shape (N, len(feature_columns)))
    """
    if feature_columns is None:
        feature_columns = FEATURE_COLUMNS
        
    rows = []
    for rec in feature_records:
        row = [float(rec[col]) for col in feature_columns]
        rows.append(row)
        
    matrix = np.array(rows, dtype=np.float64) if rows else np.empty((0, len(feature_columns)), dtype=np.float64)
    return feature_columns, matrix
