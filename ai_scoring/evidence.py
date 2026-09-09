"""
Evidence generation module.

Phase 9: Deterministic human-readable explanation generator.
Fulfills the schema defined in data/CONTRACT.md:
- anomaly_reason
- drift_reason
- criticality_reason
- severity_reason
"""
from typing import Dict, Any, Optional

from ai_scoring.severity import (
    evaluate_severity,
    ANOMALY_ELEVATED,
    ANOMALY_HIGH,
    ANOMALY_EXTREME,
    DRIFT_LOW,
    DRIFT_MODERATE,
    DRIFT_HIGH,
)


def generate_criticality_reason(criticality: str, file_path: str = "") -> str:
    """
    Explains the configured static importance of the asset objectively.
    """
    if criticality == "Critical":
        return (
            "Configured as a Critical asset. Assets at this tier represent core system "
            "components where modifications carry high baseline operational impact."
        )
    elif criticality == "High":
        return (
            "Configured as a High-priority asset. Assets at this tier govern significant system "
            "or application services where changes warrant priority review."
        )
    elif criticality == "Medium":
        return (
            "Configured as a Medium-priority asset. Represents standard operational "
            "configurations subject to standard verification."
        )
    elif criticality == "Low":
        return (
            "Configured as a Low-priority asset. Represents auxiliary or non-sensitive "
            "settings with minimal operational exposure."
        )
    else:
        return f"Configured with asset criticality tier '{criticality}'."


def generate_anomaly_reason(
    anomaly_score: Optional[float],
    batch_features: Optional[Dict[str, Any]] = None
) -> str:
    """
    Explains behavioral scan-batch unusualness relative to historical baseline distributions.
    """
    if anomaly_score is None:
        return "Behavioral anomaly score is unavailable (no prior historical scan baseline available for comparison)."

    feature_suffix = ""
    if isinstance(batch_features, dict):
        n_files = batch_features.get("number_of_files_changed")
        tod = batch_features.get("time_of_day")
        vel = batch_features.get("change_velocity")
        if n_files is not None and tod is not None and vel is not None:
            feature_suffix = (
                f" Observed batch features: {n_files} file(s) changed at "
                f"{float(tod):.1f}h with velocity ratio {float(vel):.1f}x baseline."
            )

    if anomaly_score >= ANOMALY_EXTREME:
        return (
            f"Extreme behavioral anomaly ({anomaly_score:.4f}): The change batch represents an "
            f"extreme outlier relative to historical baseline activity (above the 98.5th percentile), "
            f"indicating highly unusual timing, change volume, or burst velocity.{feature_suffix}"
        )
    elif anomaly_score >= ANOMALY_HIGH:
        return (
            f"High behavioral anomaly ({anomaly_score:.4f}): The change batch deviates substantially "
            f"from typical historical baseline patterns (above the 95.7th percentile of normal scans).{feature_suffix}"
        )
    elif anomaly_score >= ANOMALY_ELEVATED:
        return (
            f"Elevated behavioral activity ({anomaly_score:.4f}): The change batch exhibits noticeable "
            f"deviation in timing, clustering, or volume compared to normal operations (above the 90th percentile).{feature_suffix}"
        )
    else:
        return (
            f"Routine behavioral pattern ({anomaly_score:.4f}): The change batch timing, velocity, "
            f"and file count align with normal historical baseline patterns.{feature_suffix}"
        )


def generate_drift_reason(drift_score: Optional[float], change_type: str) -> str:
    """
    Objectively reports semantic divergence measured by the embedding model without overclaiming.
    """
    if change_type == "ADDED":
        return "Semantic drift is not applicable for newly added files (no previous baseline content exists for comparison)."
    if change_type == "DELETED":
        return "Semantic drift is not applicable for deleted files (file content was removed from the filesystem)."
    if drift_score is None:
        return (
            "Content is binary or non-textual; semantic embedding comparison cannot be computed. "
            "Integrity evaluated through cryptographic hash change."
        )

    if drift_score < 0.01:
        return (
            f"Negligible semantic drift ({drift_score:.4f}): The old and new textual contents "
            f"are semantically very similar."
        )
    elif drift_score < DRIFT_LOW:
        return (
            f"Low semantic drift ({drift_score:.4f}): The textual content shows minor semantic "
            f"divergence, consistent with small phrasing or parameter adjustments."
        )
    elif drift_score < DRIFT_MODERATE:
        return (
            f"Moderate semantic drift ({drift_score:.4f}): The content exhibits measurable "
            f"semantic divergence between old and new versions."
        )
    elif drift_score < DRIFT_HIGH:
        return (
            f"Substantial semantic drift ({drift_score:.4f}): The content exhibits significant "
            f"semantic divergence, indicating substantial modification of configuration or text structure."
        )
    else:
        return (
            f"High semantic drift ({drift_score:.4f}): The content exhibits major semantic "
            f"divergence, indicating extensive content restructuring or replacement."
        )


def generate_severity_reason(
    severity: str,
    criticality: str,
    change_type: str,
    anomaly_score: Optional[float],
    drift_score: Optional[float]
) -> str:
    """
    Synthesizes the complete deterministic causal chain using Phase 8 rules.
    """
    try:
        explanation = evaluate_severity(
            criticality=criticality,
            change_type=change_type,
            anomaly_score=anomaly_score,
            drift_score=drift_score
        )
        rules = explanation.rules_triggered
        base_sev = explanation.base_severity
    except Exception:
        # Fallback if evaluation raises
        rules = ()
        base_sev = "LOW"

    # Immediate fail-safe critical deletion
    if "R1_FAILSAFE_CRITICAL_DELETION" in rules:
        return (
            "Assigned CRITICAL under fail-safe rule: Critical asset was DELETED, triggering "
            "unconditional elevation regardless of telemetry signals."
        )

    # Compounding risk
    if "R6_COMPOUNDING_RISK" in rules:
        a_str = f"{anomaly_score:.4f}" if anomaly_score is not None else "N/A"
        d_str = f"{drift_score:.4f}" if drift_score is not None else "N/A"
        return (
            f"Assigned {severity}: {criticality} asset elevated due to compounding risk: "
            f"high behavioral anomaly ({a_str}) combined with substantial semantic drift ({d_str})."
        )

    # Binary modification on critical asset under high anomaly
    if "R3_BINARY_CRITICAL_ANOMALY" in rules:
        a_str = f"{anomaly_score:.4f}" if anomaly_score is not None else "N/A"
        return (
            f"Assigned CRITICAL: Critical asset underwent an uninspectable binary modification "
            f"during a high behavioral anomaly batch ({a_str})."
        )

    # Accumulate specific escalation factors
    factors = []
    if "R3_CHANGE_TYPE_DELETED_HIGH" in rules:
        factors.append("DELETED change type (+1 level)")
    elif "R3_CHANGE_TYPE_DELETED_MEDIUM" in rules:
        factors.append("DELETED change type (+1 level)")
    elif any(r in rules for r in ("R3_CHANGE_TYPE_ADDED_CRITICAL", "R3_CHANGE_TYPE_ADDED_HIGH", "R3_CHANGE_TYPE_ADDED_MEDIUM")):
        factors.append("ADDED change type (+1 level)")

    if "R4_ANOMALY_EXTREME" in rules:
        a_str = f"{anomaly_score:.4f}" if anomaly_score is not None else "N/A"
        factors.append(f"extreme behavioral anomaly ({a_str}, +2 levels)")
    elif "R4_ANOMALY_HIGH" in rules:
        a_str = f"{anomaly_score:.4f}" if anomaly_score is not None else "N/A"
        factors.append(f"high behavioral anomaly ({a_str}, +1 level)")
    elif "R4_ANOMALY_ELEVATED" in rules:
        a_str = f"{anomaly_score:.4f}" if anomaly_score is not None else "N/A"
        factors.append(f"elevated behavioral activity ({a_str}, +1 level)")

    if "R5_DRIFT_HIGH" in rules:
        d_str = f"{drift_score:.4f}" if drift_score is not None else "N/A"
        factors.append(f"high semantic drift ({d_str}, +2 levels)")
    elif "R5_DRIFT_MODERATE" in rules:
        d_str = f"{drift_score:.4f}" if drift_score is not None else "N/A"
        factors.append(f"moderate semantic drift ({d_str}, +1 level)")
    elif "R5_DRIFT_LOW" in rules:
        d_str = f"{drift_score:.4f}" if drift_score is not None else "N/A"
        factors.append(f"measurable semantic drift ({d_str}, +1 level)")

    if factors:
        joined = " and ".join(factors)
        return f"Assigned {severity}: {criticality} asset initialized at baseline {base_sev}, elevated by {joined}."
    else:
        return (
            f"Assigned {severity}: {criticality} asset remained at baseline {base_sev} "
            f"with routine behavioral activity and low semantic divergence."
        )


def generate_evidence(
    change: Dict[str, Any],
    severity: str,
    anomaly_score: Optional[float] = None,
    drift_score: Optional[float] = None,
    batch_features: Optional[Dict[str, Any]] = None
) -> Dict[str, str]:
    """
    Main entry point for Phase 9: Generates the 4 required human-readable evidence fields.
    """
    if not isinstance(change, dict):
        raise ValueError(f"change must be a dictionary; got {type(change).__name__}")
    if not isinstance(severity, str):
        raise ValueError(f"severity must be a string; got {type(severity).__name__}")

    criticality = change.get("criticality", "Medium")
    change_type = change.get("change_type", "MODIFIED")
    file_path = change.get("file_path", "")

    return {
        "anomaly_reason": generate_anomaly_reason(anomaly_score, batch_features=batch_features),
        "drift_reason": generate_drift_reason(drift_score, change_type=change_type),
        "criticality_reason": generate_criticality_reason(criticality, file_path=file_path),
        "severity_reason": generate_severity_reason(
            severity=severity,
            criticality=criticality,
            change_type=change_type,
            anomaly_score=anomaly_score,
            drift_score=drift_score
        )
    }
