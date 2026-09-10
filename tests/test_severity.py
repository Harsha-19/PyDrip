"""
Tests for Phase 8 Deterministic Severity Engine module.
"""
import math
import pytest

from ai_scoring import severity
from ai_scoring.severity import (
    calculate_severity,
    evaluate_severity,
    calculate_change_severity,
    SeverityExplanation,
    ANOMALY_ELEVATED,
    ANOMALY_HIGH,
    ANOMALY_EXTREME,
    DRIFT_LOW,
    DRIFT_MODERATE,
    DRIFT_HIGH,
)


def test_api_existence():
    """Verify all required Phase 8 public symbols and classes exist."""
    assert hasattr(severity, "calculate_severity")
    assert hasattr(severity, "evaluate_severity")
    assert hasattr(severity, "calculate_change_severity")
    assert hasattr(severity, "SeverityExplanation")
    assert hasattr(severity, "ANOMALY_ELEVATED")
    assert hasattr(severity, "ANOMALY_HIGH")
    assert hasattr(severity, "ANOMALY_EXTREME")
    assert hasattr(severity, "DRIFT_LOW")
    assert hasattr(severity, "DRIFT_MODERATE")
    assert hasattr(severity, "DRIFT_HIGH")


# ============================================================================
# 1. INPUT VALIDATION TESTS
# ============================================================================

def test_invalid_criticality():
    with pytest.raises(ValueError, match="Invalid criticality"):
        calculate_severity("SuperCritical", "MODIFIED")
    with pytest.raises(ValueError, match="Invalid criticality"):
        calculate_severity("", "MODIFIED")
    with pytest.raises(ValueError, match="Invalid criticality"):
        calculate_severity(None, "MODIFIED")  # type: ignore


def test_invalid_change_type():
    with pytest.raises(ValueError, match="Invalid change_type"):
        calculate_severity("Medium", "UPDATE")
    with pytest.raises(ValueError, match="Invalid change_type"):
        calculate_severity("Medium", "")
    with pytest.raises(ValueError, match="Invalid change_type"):
        calculate_severity("Medium", None)  # type: ignore


def test_invalid_anomaly_score():
    # Out of range
    with pytest.raises(ValueError, match="range"):
        calculate_severity("Medium", "MODIFIED", anomaly_score=-0.001)
    with pytest.raises(ValueError, match="range"):
        calculate_severity("Medium", "MODIFIED", anomaly_score=1.001)
    # Non-finite
    with pytest.raises(ValueError, match="finite"):
        calculate_severity("Medium", "MODIFIED", anomaly_score=float("nan"))
    with pytest.raises(ValueError, match="finite"):
        calculate_severity("Medium", "MODIFIED", anomaly_score=float("inf"))
    # Wrong type
    with pytest.raises(ValueError, match="must be a float"):
        calculate_severity("Medium", "MODIFIED", anomaly_score=True)  # type: ignore
    with pytest.raises(ValueError, match="must be a float"):
        calculate_severity("Medium", "MODIFIED", anomaly_score="0.5")  # type: ignore


def test_invalid_drift_score():
    # Out of range
    with pytest.raises(ValueError, match="range"):
        calculate_severity("Medium", "MODIFIED", drift_score=-0.001)
    with pytest.raises(ValueError, match="range"):
        calculate_severity("Medium", "MODIFIED", drift_score=1.001)
    # Non-finite
    with pytest.raises(ValueError, match="finite"):
        calculate_severity("Medium", "MODIFIED", drift_score=float("nan"))
    with pytest.raises(ValueError, match="finite"):
        calculate_severity("Medium", "MODIFIED", drift_score=float("-inf"))
    # Wrong type
    with pytest.raises(ValueError, match="must be a float"):
        calculate_severity("Medium", "MODIFIED", drift_score=False)  # type: ignore
    with pytest.raises(ValueError, match="must be a float"):
        calculate_severity("Medium", "MODIFIED", drift_score="0.2")  # type: ignore


# ============================================================================
# 2. FAIL-SAFE CRITICAL DELETION TESTS
# ============================================================================

def test_failsafe_critical_deletion():
    """Critical asset deletion must unconditionally evaluate as CRITICAL."""
    # With no scores
    assert calculate_severity("Critical", "DELETED") == "CRITICAL"
    # With low scores
    assert calculate_severity("Critical", "DELETED", anomaly_score=0.0, drift_score=0.0) == "CRITICAL"
    # With extreme scores
    assert calculate_severity("Critical", "DELETED", anomaly_score=1.0, drift_score=1.0) == "CRITICAL"

    exp = evaluate_severity("Critical", "DELETED")
    assert exp.severity == "CRITICAL"
    assert "R1_FAILSAFE_CRITICAL_DELETION" in exp.rules_triggered


# ============================================================================
# 3. BASE SEVERITY AND CHANGE-TYPE ELEVATION
# ============================================================================

def test_base_severities_without_signals():
    """Test base severities for MODIFIED without anomaly/drift."""
    assert calculate_severity("Low", "MODIFIED") == "LOW"
    assert calculate_severity("Medium", "MODIFIED") == "LOW"
    assert calculate_severity("High", "MODIFIED") == "MEDIUM"
    assert calculate_severity("Critical", "MODIFIED") == "HIGH"


def test_change_type_deleted_elevation():
    """DELETED elevates High to HIGH, Medium to MEDIUM, Low stays LOW."""
    assert calculate_severity("Low", "DELETED") == "LOW"
    assert calculate_severity("Medium", "DELETED") == "MEDIUM"
    assert calculate_severity("High", "DELETED") == "HIGH"
    assert calculate_severity("Critical", "DELETED") == "CRITICAL"


def test_change_type_added_elevation():
    """ADDED elevates Critical to CRITICAL, High to HIGH, Medium to MEDIUM, Low stays LOW."""
    assert calculate_severity("Low", "ADDED") == "LOW"
    assert calculate_severity("Medium", "ADDED") == "MEDIUM"
    assert calculate_severity("High", "ADDED") == "HIGH"
    assert calculate_severity("Critical", "ADDED") == "CRITICAL"


def test_binary_modification_failsafe():
    """Uninspectable binary modification on Critical asset under high anomaly reaches CRITICAL."""
    # Under high anomaly
    assert calculate_severity("Critical", "MODIFIED", anomaly_score=0.85, drift_score=None) == "CRITICAL"
    # Under low anomaly remains base HIGH
    assert calculate_severity("Critical", "MODIFIED", anomaly_score=0.20, drift_score=None) == "HIGH"


# ============================================================================
# 4. SIGNAL INDEPENDENCE TESTS (NO SUPPRESSION)
# ============================================================================

def test_low_drift_does_not_suppress_extreme_anomaly():
    """
    CRITICAL REQUIREMENT:
    Critical + MODIFIED + anomaly_score=0.99 + drift_score=0.00
    must NOT be downgraded just because drift is low.
    """
    res = calculate_severity("Critical", "MODIFIED", anomaly_score=0.99, drift_score=0.00)
    assert res == "CRITICAL"

    exp = evaluate_severity("Critical", "MODIFIED", anomaly_score=0.99, drift_score=0.00)
    assert exp.severity == "CRITICAL"
    assert "R4_ANOMALY_EXTREME" in exp.rules_triggered


def test_low_anomaly_does_not_suppress_high_drift():
    """High drift elevates regardless of low anomaly score."""
    # Low asset with drift >= 0.25 (+2 levels) -> HIGH
    assert calculate_severity("Low", "MODIFIED", anomaly_score=0.05, drift_score=0.30) == "HIGH"
    # Medium asset with drift >= 0.25 (+2 levels) -> HIGH
    assert calculate_severity("Medium", "MODIFIED", anomaly_score=0.05, drift_score=0.30) == "HIGH"
    # High asset with drift >= 0.25 (+2 levels) -> CRITICAL
    assert calculate_severity("High", "MODIFIED", anomaly_score=0.05, drift_score=0.30) == "CRITICAL"


# ============================================================================
# 5. MATHEMATICAL DRIFT ESCALATION TESTS
# ============================================================================

def test_drift_escalation_exact_brackets():
    """
    Verifies exact mathematical definition:
    - drift < 0.05: 0
    - 0.05 <= drift < 0.15: +1 for Medium/High/Critical, 0 for Low
    - 0.15 <= drift < 0.25: +1 for all
    - drift >= 0.25: +2 for all
    """
    # Low file
    assert calculate_severity("Low", "MODIFIED", drift_score=0.0499) == "LOW"
    assert calculate_severity("Low", "MODIFIED", drift_score=0.0500) == "LOW"  # 0 for Low
    assert calculate_severity("Low", "MODIFIED", drift_score=0.1499) == "LOW"
    assert calculate_severity("Low", "MODIFIED", drift_score=0.1500) == "MEDIUM"  # +1 for all
    assert calculate_severity("Low", "MODIFIED", drift_score=0.2499) == "MEDIUM"
    assert calculate_severity("Low", "MODIFIED", drift_score=0.2500) == "HIGH"  # +2 for all (0 + 2 = 2)

    # Medium file
    assert calculate_severity("Medium", "MODIFIED", drift_score=0.0499) == "LOW"
    assert calculate_severity("Medium", "MODIFIED", drift_score=0.0500) == "MEDIUM"  # +1
    assert calculate_severity("Medium", "MODIFIED", drift_score=0.1499) == "MEDIUM"
    assert calculate_severity("Medium", "MODIFIED", drift_score=0.1500) == "MEDIUM"  # base 0 + 1 = 1
    assert calculate_severity("Medium", "MODIFIED", drift_score=0.2500) == "HIGH"    # base 0 + 2 = 2

    # High file
    assert calculate_severity("High", "MODIFIED", drift_score=0.0499) == "MEDIUM"
    assert calculate_severity("High", "MODIFIED", drift_score=0.0500) == "HIGH"   # base 1 + 1 = 2
    assert calculate_severity("High", "MODIFIED", drift_score=0.1500) == "HIGH"   # base 1 + 1 = 2
    assert calculate_severity("High", "MODIFIED", drift_score=0.2500) == "CRITICAL"  # base 1 + 2 = 3


# ============================================================================
# 6. ANOMALY ESCALATION TESTS
# ============================================================================

def test_anomaly_escalation_exact_brackets():
    """
    Verifies anomaly brackets:
    - < 0.60: 0
    - 0.60 <= a < 0.80: +1 for High/Critical
    - 0.80 <= a < 0.90: +1 for all
    - >= 0.90: +2 for all
    """
    # Low file
    assert calculate_severity("Low", "MODIFIED", anomaly_score=0.5999) == "LOW"
    assert calculate_severity("Low", "MODIFIED", anomaly_score=0.6000) == "LOW"
    assert calculate_severity("Low", "MODIFIED", anomaly_score=0.7999) == "LOW"
    assert calculate_severity("Low", "MODIFIED", anomaly_score=0.8000) == "MEDIUM"
    assert calculate_severity("Low", "MODIFIED", anomaly_score=0.8999) == "MEDIUM"
    assert calculate_severity("Low", "MODIFIED", anomaly_score=0.9000) == "HIGH"  # 0 + 2 = 2

    # High file
    assert calculate_severity("High", "MODIFIED", anomaly_score=0.5999) == "MEDIUM"
    assert calculate_severity("High", "MODIFIED", anomaly_score=0.6000) == "HIGH"   # base 1 + 1 = 2
    assert calculate_severity("High", "MODIFIED", anomaly_score=0.8000) == "HIGH"   # base 1 + 1 = 2
    assert calculate_severity("High", "MODIFIED", anomaly_score=0.9000) == "CRITICAL"  # base 1 + 2 = 3

    # Critical file
    assert calculate_severity("Critical", "MODIFIED", anomaly_score=0.5999) == "HIGH"
    assert calculate_severity("Critical", "MODIFIED", anomaly_score=0.6000) == "CRITICAL"  # base 2 + 1 = 3


# ============================================================================
# 7. COMPOUNDING RISK (HIGH ANOMALY + MODERATE/HIGH DRIFT)
# ============================================================================

def test_compounding_risk():
    """anomaly >= 0.80 and drift >= 0.15 compounds severity."""
    # Critical and High reach CRITICAL
    assert calculate_severity("Critical", "MODIFIED", anomaly_score=0.80, drift_score=0.15) == "CRITICAL"
    assert calculate_severity("High", "MODIFIED", anomaly_score=0.85, drift_score=0.18) == "CRITICAL"
    # Medium reaches HIGH
    assert calculate_severity("Medium", "MODIFIED", anomaly_score=0.82, drift_score=0.16) == "HIGH"
    # Low reaches HIGH (base 0 + 1 (anomaly) + 1 (drift) = 2 = HIGH, floor is MEDIUM (1))
    assert calculate_severity("Low", "MODIFIED", anomaly_score=0.85, drift_score=0.20) == "HIGH"

    exp = evaluate_severity("High", "MODIFIED", anomaly_score=0.85, drift_score=0.18)
    assert "R6_COMPOUNDING_RISK" in exp.rules_triggered


# ============================================================================
# 8. NONE SCORE SEMANTICS
# ============================================================================

def test_none_scores():
    """None scores represent unobserved evidence, NOT zero."""
    assert calculate_severity("High", "MODIFIED", anomaly_score=None, drift_score=None) == "MEDIUM"
    assert calculate_severity("Critical", "MODIFIED", anomaly_score=None, drift_score=None) == "HIGH"
    assert calculate_severity("Medium", "MODIFIED", anomaly_score=None, drift_score=None) == "LOW"
    assert calculate_severity("Low", "MODIFIED", anomaly_score=None, drift_score=None) == "LOW"

    # With drift only
    assert calculate_severity("High", "MODIFIED", anomaly_score=None, drift_score=0.20) == "HIGH"
    # With anomaly only
    assert calculate_severity("High", "MODIFIED", anomaly_score=0.85, drift_score=None) == "HIGH"


# ============================================================================
# 9. EXPLAINABILITY HOOK AND DETERMINISM
# ============================================================================

def test_explainability_hook():
    """Verify evaluate_severity provides complete, immutable explanation."""
    exp = evaluate_severity("High", "MODIFIED", anomaly_score=0.85, drift_score=0.20)
    assert isinstance(exp, SeverityExplanation)
    assert exp.severity == "CRITICAL"
    assert exp.base_severity == "MEDIUM"
    assert exp.criticality == "High"
    assert exp.change_type == "MODIFIED"
    assert exp.anomaly_score == 0.85
    assert exp.drift_score == 0.20
    assert len(exp.rules_triggered) > 0
    assert len(exp.escalation_reasons) > 0
    for r in exp.escalation_reasons:
        assert isinstance(r, str) and len(r) > 0


def test_determinism():
    """100 repeated identical calls must yield identical outputs."""
    first = calculate_severity("High", "MODIFIED", anomaly_score=0.85, drift_score=0.20)
    for _ in range(100):
        assert calculate_severity("High", "MODIFIED", anomaly_score=0.85, drift_score=0.20) == first


def test_calculate_change_severity_helper():
    """Verify convenience helper unpacking change dict."""
    change = {
        "file_path": "/configs/auth.conf",
        "change_type": "MODIFIED",
        "criticality": "High"
    }
    sev = calculate_change_severity(change, anomaly_score=0.85, drift_score=0.20)
    assert sev == "CRITICAL"

    with pytest.raises(ValueError, match="dictionary"):
        calculate_change_severity("invalid")  # type: ignore
