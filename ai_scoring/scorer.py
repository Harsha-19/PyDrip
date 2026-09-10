"""
Main scoring module.

Phase 10: Unified scoring coordinator.
Connects Feature Engineering (Phase 5), Anomaly Detection (Phase 6),
Semantic Drift (Phase 7), Severity Engine (Phase 8), and Evidence Engine (Phase 9)
behind the public entry point: score_changes(change_list, scan_history).
"""
from typing import List, Dict, Any, Optional

from ai_scoring.contract import validate_change, validate_scan_history
from ai_scoring import features
from ai_scoring import anomaly
from ai_scoring import drift
from ai_scoring import severity
from ai_scoring import evidence


def score_changes(
    change_list: List[Dict[str, Any]],
    scan_history: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Main entry point for the AI/ML scoring layer.
    
    1. Strictly validates change_list and scan_history.
    2. Calculates batch-level anomaly score (Phase 5 & 6) if scan_history is non-empty.
    3. Calculates vectorized semantic drift (Phase 7) for all changes.
    4. Computes deterministic severity (Phase 8) for each change.
    5. Generates traceable evidence (Phase 9) for each change.
    6. Returns new list of enriched dictionaries without mutating input records.
    """
    if not isinstance(change_list, list):
        raise ValueError(f"change_list must be a list; got {type(change_list).__name__}")
    if not isinstance(scan_history, list):
        raise ValueError(f"scan_history must be a list; got {type(scan_history).__name__}")

    # Validate every change record strictly
    for ch in change_list:
        if not validate_change(ch):
            raise ValueError(f"Invalid change record: {ch}")

    # Early return for empty batch
    if not change_list:
        return []

    # Validate non-empty scan_history strictly
    batch_anomaly: Optional[float] = None
    batch_features: Optional[Dict[str, Any]] = None

    if len(scan_history) > 0:
        if not validate_scan_history(scan_history):
            raise ValueError("scan_history failed contract validation")

        # Determine batch timestamp if present
        batch_ts = None
        for ch in change_list:
            if ch.get("detected_at"):
                batch_ts = ch["detected_at"]
                break

        # Calculate batch anomaly score using Phase 6 Isolation Forest
        batch_anomaly = anomaly.detect_anomalies(change_list, scan_history)

        # Extract batch features for Phase 9 evidence context
        try:
            if batch_ts:
                prior_history = [s for s in scan_history if s.get("detected_at") and s["detected_at"] < batch_ts]
                hist_for_feat = prior_history if prior_history else scan_history
            else:
                hist_for_feat = scan_history
            batch_features = features.build_features(change_list, hist_for_feat, detected_at=batch_ts)
        except Exception:
            batch_features = None

    # Calculate batch semantic drift using Phase 7 SentenceTransformer
    drift_scores = drift.calculate_batch_drift(change_list)

    # Enrich each change record (Phases 8 & 9)
    enriched_list: List[Dict[str, Any]] = []

    for idx, ch in enumerate(change_list):
        d_score = drift_scores[idx]
        crit = ch.get("criticality", "Medium")
        ct = ch.get("change_type", "MODIFIED")

        # Phase 8: Severity
        sev = severity.calculate_severity(
            criticality=crit,
            change_type=ct,
            anomaly_score=batch_anomaly,
            drift_score=d_score
        )

        # Phase 9: Evidence
        ev = evidence.generate_evidence(
            change=ch,
            severity=sev,
            anomaly_score=batch_anomaly,
            drift_score=d_score,
            batch_features=batch_features
        )

        # Clone and enrich without mutating input dictionary
        enriched_ch = {
            **ch,
            "anomaly_score": batch_anomaly,
            "drift_score": d_score,
            "severity": sev,
            "evidence": ev
        }
        enriched_list.append(enriched_ch)

    return enriched_list
