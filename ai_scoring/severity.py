"""
Severity rules module.

Phase 8: Deterministic rule-based severity calculation.
Translates asset criticality, change type, anomaly score, and drift score
into exactly one deterministic severity: LOW, MEDIUM, HIGH, or CRITICAL.
"""
from dataclasses import dataclass
import math
from typing import Optional, Dict, Any, Tuple, List

# Threshold constants locked in Phase 8 specification
ANOMALY_ELEVATED: float = 0.60
ANOMALY_HIGH: float = 0.80
ANOMALY_EXTREME: float = 0.90

DRIFT_LOW: float = 0.05
DRIFT_MODERATE: float = 0.15
DRIFT_HIGH: float = 0.25

SEVERITY_LEVELS: Tuple[str, ...] = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
VALID_CRITICALITIES: Tuple[str, ...] = ("Low", "Medium", "High", "Critical")
VALID_CHANGE_TYPES: Tuple[str, ...] = ("ADDED", "DELETED", "MODIFIED")


@dataclass(frozen=True)
class SeverityExplanation:
    """
    Explainability record detailing why a final severity was selected.
    Consumed by Phase 9 Evidence Engine.
    """
    severity: str
    base_severity: str
    criticality: str
    change_type: str
    anomaly_score: Optional[float]
    drift_score: Optional[float]
    rules_triggered: Tuple[str, ...]
    escalation_reasons: Tuple[str, ...]


def _validate_score(val: Optional[float], name: str) -> Optional[float]:
    """Validates that a score is None or a finite float in [0.0, 1.0]."""
    if val is None:
        return None
    # Reject boolean types (bool is a subclass of int in Python)
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise ValueError(f"{name} must be a float, int, or None; got {type(val).__name__}")
    f_val = float(val)
    if not math.isfinite(f_val):
        raise ValueError(f"{name} must be finite; got {val}")
    if f_val < 0.0 or f_val > 1.0:
        raise ValueError(f"{name} must be in range [0.0, 1.0]; got {val}")
    return f_val


def evaluate_severity(
    criticality: str,
    change_type: str,
    anomaly_score: Optional[float] = None,
    drift_score: Optional[float] = None
) -> SeverityExplanation:
    """
    Evaluates severity deterministically and returns a rich SeverityExplanation
    containing all triggered rules and plain-English reasons for Phase 9.
    """
    # 1. Strict Input Validation
    if not isinstance(criticality, str) or criticality not in VALID_CRITICALITIES:
        raise ValueError(f"Invalid criticality '{criticality}'. Must be one of {VALID_CRITICALITIES}")
    if not isinstance(change_type, str) or change_type not in VALID_CHANGE_TYPES:
        raise ValueError(f"Invalid change_type '{change_type}'. Must be one of {VALID_CHANGE_TYPES}")

    valid_anomaly = _validate_score(anomaly_score, "anomaly_score")
    valid_drift = _validate_score(drift_score, "drift_score")

    rules_triggered: List[str] = []
    reasons: List[str] = []

    # 2. Immediate Fail-Safe Rule: Critical Deletion
    if criticality == "Critical" and change_type == "DELETED":
        rules_triggered.append("R1_FAILSAFE_CRITICAL_DELETION")
        reasons.append("Critical asset was DELETED; unconditionally evaluated as CRITICAL.")
        return SeverityExplanation(
            severity="CRITICAL",
            base_severity="HIGH",
            criticality=criticality,
            change_type=change_type,
            anomaly_score=valid_anomaly,
            drift_score=valid_drift,
            rules_triggered=tuple(rules_triggered),
            escalation_reasons=tuple(reasons)
        )

    # 3. Base Severity from Criticality
    # Level mapping: LOW=0, MEDIUM=1, HIGH=2, CRITICAL=3
    if criticality == "Critical":
        base_level = 2  # HIGH
        base_sev = "HIGH"
    elif criticality == "High":
        base_level = 1  # MEDIUM
        base_sev = "MEDIUM"
    else:  # Medium or Low
        base_level = 0  # LOW
        base_sev = "LOW"

    rules_triggered.append("R2_BASE_SEVERITY")
    reasons.append(f"Baseline severity for '{criticality}' asset initialized to {base_sev}.")

    curr_level = base_level

    # 4. Change-Type Adjustments
    if change_type == "DELETED":
        if criticality == "High":
            curr_level += 1
            rules_triggered.append("R3_CHANGE_TYPE_DELETED_HIGH")
            reasons.append("High-criticality asset deletion elevated severity by +1.")
        elif criticality == "Medium":
            curr_level += 1
            rules_triggered.append("R3_CHANGE_TYPE_DELETED_MEDIUM")
            reasons.append("Medium-criticality asset deletion elevated severity by +1.")
    elif change_type == "ADDED":
        if criticality == "Critical":
            curr_level += 1
            rules_triggered.append("R3_CHANGE_TYPE_ADDED_CRITICAL")
            reasons.append("New addition in Critical area elevated severity by +1.")
        elif criticality == "High":
            curr_level += 1
            rules_triggered.append("R3_CHANGE_TYPE_ADDED_HIGH")
            reasons.append("New addition in High-criticality path elevated severity by +1.")
        elif criticality == "Medium":
            curr_level += 1
            rules_triggered.append("R3_CHANGE_TYPE_ADDED_MEDIUM")
            reasons.append("New addition in Medium-criticality area elevated severity by +1.")
    elif change_type == "MODIFIED" and valid_drift is None:
        # Binary or uninspectable modification
        if criticality == "Critical" and valid_anomaly is not None and valid_anomaly >= ANOMALY_HIGH:
            curr_level = max(curr_level, 3)
            rules_triggered.append("R3_BINARY_CRITICAL_ANOMALY")
            reasons.append("Uninspectable modification to Critical asset under high anomaly elevated to CRITICAL.")

    # 5. Behavioral Anomaly Escalation (Independent)
    delta_anomaly = 0
    if valid_anomaly is not None:
        if valid_anomaly >= ANOMALY_EXTREME:
            delta_anomaly = 2
            rules_triggered.append("R4_ANOMALY_EXTREME")
            reasons.append(f"Extreme anomaly score ({valid_anomaly:.4f} >= {ANOMALY_EXTREME}) elevated severity by +2.")
        elif valid_anomaly >= ANOMALY_HIGH:
            delta_anomaly = 1
            rules_triggered.append("R4_ANOMALY_HIGH")
            reasons.append(f"High anomaly score ({valid_anomaly:.4f} >= {ANOMALY_HIGH}) elevated severity by +1.")
        elif valid_anomaly >= ANOMALY_ELEVATED:
            if criticality in ("High", "Critical"):
                delta_anomaly = 1
                rules_triggered.append("R4_ANOMALY_ELEVATED")
                reasons.append(f"Elevated anomaly score ({valid_anomaly:.4f} >= {ANOMALY_ELEVATED}) on {criticality} asset elevated severity by +1.")

    # 6. Content Drift Escalation (Independent)
    delta_drift = 0
    if valid_drift is not None:
        if valid_drift >= DRIFT_HIGH:
            delta_drift = 2
            rules_triggered.append("R5_DRIFT_HIGH")
            reasons.append(f"High semantic drift ({valid_drift:.4f} >= {DRIFT_HIGH}) elevated severity by +2.")
        elif valid_drift >= DRIFT_MODERATE:
            delta_drift = 1
            rules_triggered.append("R5_DRIFT_MODERATE")
            reasons.append(f"Moderate semantic drift ({valid_drift:.4f} >= {DRIFT_MODERATE}) elevated severity by +1.")
        elif valid_drift >= DRIFT_LOW:
            if criticality in ("Medium", "High", "Critical"):
                delta_drift = 1
                rules_triggered.append("R5_DRIFT_LOW")
                reasons.append(f"Detectable semantic drift ({valid_drift:.4f} >= {DRIFT_LOW}) on {criticality} asset elevated severity by +1.")

    curr_level += delta_anomaly + delta_drift

    # Guarantee Critical asset reaches CRITICAL on extreme anomaly
    if criticality == "Critical" and valid_anomaly is not None and valid_anomaly >= ANOMALY_EXTREME:
        curr_level = max(curr_level, 3)

    # 7. Compounding Risk Escalation (Both Signals High)
    if valid_anomaly is not None and valid_drift is not None:
        if valid_anomaly >= ANOMALY_HIGH and valid_drift >= DRIFT_MODERATE:
            rules_triggered.append("R6_COMPOUNDING_RISK")
            reasons.append(f"Compounding risk: High anomaly ({valid_anomaly:.4f}) and substantial drift ({valid_drift:.4f}) compound severity.")
            if criticality in ("Critical", "High"):
                curr_level = max(curr_level, 3)  # CRITICAL
            elif criticality == "Medium":
                curr_level = max(curr_level, 2)  # HIGH
            elif criticality == "Low":
                curr_level = max(curr_level, 1)  # MEDIUM

    # 8. Clamping & Formatting
    final_level = min(3, max(0, curr_level))
    final_severity = SEVERITY_LEVELS[final_level]

    return SeverityExplanation(
        severity=final_severity,
        base_severity=base_sev,
        criticality=criticality,
        change_type=change_type,
        anomaly_score=valid_anomaly,
        drift_score=valid_drift,
        rules_triggered=tuple(rules_triggered),
        escalation_reasons=tuple(reasons)
    )


def calculate_severity(
    criticality: str,
    change_type: str,
    anomaly_score: Optional[float] = None,
    drift_score: Optional[float] = None
) -> str:
    """
    Public core API: calculates deterministic severity string.
    Returns: 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL'.
    """
    explanation = evaluate_severity(
        criticality=criticality,
        change_type=change_type,
        anomaly_score=anomaly_score,
        drift_score=drift_score
    )
    return explanation.severity


def calculate_change_severity(
    change: Dict[str, Any],
    anomaly_score: Optional[float] = None,
    drift_score: Optional[float] = None
) -> str:
    """
    Convenience helper unpacking a raw change dictionary.
    """
    if not isinstance(change, dict):
        raise ValueError(f"change must be a dictionary; got {type(change).__name__}")
    criticality = change.get("criticality", "Medium")
    change_type = change.get("change_type", "MODIFIED")
    return calculate_severity(
        criticality=criticality,
        change_type=change_type,
        anomaly_score=anomaly_score,
        drift_score=drift_score
    )
