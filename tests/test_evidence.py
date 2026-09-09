"""
Tests for Phase 9 Evidence Engine module.
"""
import pytest

from ai_scoring import evidence
from ai_scoring.evidence import (
    generate_evidence,
    generate_criticality_reason,
    generate_anomaly_reason,
    generate_drift_reason,
    generate_severity_reason,
)

REQUIRED_KEYS = {"anomaly_reason", "drift_reason", "criticality_reason", "severity_reason"}
DISALLOWED_SPECULATIVE_WORDS = [
    "active attack",
    "malicious",
    "unauthorized",
    "security breach",
    "formatting, whitespace, or cosmetic adjustments only",
]


def test_evidence_api_existence():
    """Verify core API functions exist."""
    assert hasattr(evidence, "generate_evidence")
    assert hasattr(evidence, "generate_criticality_reason")
    assert hasattr(evidence, "generate_anomaly_reason")
    assert hasattr(evidence, "generate_drift_reason")
    assert hasattr(evidence, "generate_severity_reason")


def test_schema_conformance():
    """Verify evidence dict has exact 4 required keys and all are non-empty strings."""
    change = {
        "file_path": "/configs/app.conf",
        "criticality": "High",
        "change_type": "MODIFIED",
    }
    result = generate_evidence(change, severity="HIGH", anomaly_score=0.85, drift_score=0.10)
    assert isinstance(result, dict)
    assert set(result.keys()) == REQUIRED_KEYS

    for k, v in result.items():
        assert isinstance(v, str), f"Key {k} value is not a string: {type(v)}"
        assert len(v.strip()) > 0, f"Key {k} value is empty"


def test_no_speculative_language():
    """Verify that generated reasons do not invent intent, attacks, or overclaim formatting."""
    # Test across multiple combinations
    test_cases = [
        ({"criticality": "Critical", "change_type": "DELETED"}, "CRITICAL", 0.95, None),
        ({"criticality": "High", "change_type": "ADDED"}, "CRITICAL", 0.85, None),
        ({"criticality": "Medium", "change_type": "MODIFIED"}, "MEDIUM", 0.88, 0.0000),
        ({"criticality": "Low", "change_type": "MODIFIED"}, "MEDIUM", 0.89, 0.0970),
        ({"criticality": "High", "change_type": "MODIFIED"}, "CRITICAL", 0.92, 0.2380),
        ({"criticality": "Critical", "change_type": "MODIFIED"}, "CRITICAL", 0.80, None),
    ]

    for ch, sev, a_score, d_score in test_cases:
        res = generate_evidence(ch, severity=sev, anomaly_score=a_score, drift_score=d_score)
        combined_text = " ".join(res.values()).lower()
        for word in DISALLOWED_SPECULATIVE_WORDS:
            assert word not in combined_text, f"Found speculative word '{word}' in: {combined_text}"


def test_criticality_reasons_all_tiers():
    """Verify criticality reasons for all valid tiers."""
    for tier in ("Critical", "High", "Medium", "Low"):
        reason = generate_criticality_reason(tier, "/configs/test.conf")
        assert isinstance(reason, str)
        assert tier in reason
        assert len(reason) > 20


def test_anomaly_reasons_all_brackets():
    """Verify anomaly reason wording across defined score brackets."""
    # None
    r_none = generate_anomaly_reason(None)
    assert "unavailable" in r_none

    # Routine (< 0.60)
    r_routine = generate_anomaly_reason(0.25)
    assert "Routine" in r_routine or "routine" in r_routine

    # Elevated (0.60 - 0.80)
    r_elevated = generate_anomaly_reason(0.70)
    assert "Elevated" in r_elevated or "elevated" in r_elevated

    # High (0.80 - 0.90)
    r_high = generate_anomaly_reason(0.85)
    assert "High" in r_high or "high" in r_high

    # Extreme (>= 0.90)
    r_extreme = generate_anomaly_reason(0.95)
    assert "Extreme" in r_extreme or "extreme" in r_extreme

    # With batch features
    feat = {"number_of_files_changed": 5, "time_of_day": 2.0, "change_velocity": 12.5}
    r_feat = generate_anomaly_reason(0.95, batch_features=feat)
    assert "Observed batch features:" in r_feat
    assert "5 file(s)" in r_feat


def test_drift_reasons_all_conditions():
    """Verify drift reasons for added, deleted, binary, and textual brackets."""
    # ADDED
    r_add = generate_drift_reason(None, change_type="ADDED")
    assert "not applicable for newly added files" in r_add

    # DELETED
    r_del = generate_drift_reason(None, change_type="DELETED")
    assert "not applicable for deleted files" in r_del

    # Binary MODIFIED
    r_bin = generate_drift_reason(None, change_type="MODIFIED")
    assert "binary or non-textual" in r_bin

    # Negligible (< 0.01)
    r_neg = generate_drift_reason(0.0000, change_type="MODIFIED")
    assert "Negligible" in r_neg
    assert "semantically very similar" in r_neg

    # Low (0.01 - 0.05)
    r_low = generate_drift_reason(0.0304, change_type="MODIFIED")
    assert "Low semantic drift" in r_low

    # Moderate (0.05 - 0.15)
    r_mod = generate_drift_reason(0.0970, change_type="MODIFIED")
    assert "Moderate semantic drift" in r_mod

    # Substantial (0.15 - 0.25)
    r_sub = generate_drift_reason(0.2000, change_type="MODIFIED")
    assert "Substantial semantic drift" in r_sub

    # High (>= 0.25)
    r_high = generate_drift_reason(0.3500, change_type="MODIFIED")
    assert "High semantic drift" in r_high


def test_severity_reasons_causal_chains():
    """Verify severity reasons reflect Phase 8 deterministic rules."""
    # Critical deletion fail-safe
    r1 = generate_severity_reason("CRITICAL", "Critical", "DELETED", None, None)
    assert "fail-safe" in r1.lower()
    assert "DELETED" in r1

    # Compounding risk
    r2 = generate_severity_reason("CRITICAL", "High", "MODIFIED", 0.85, 0.20)
    assert "compounding risk" in r2.lower()

    # Binary modification under anomaly
    r3 = generate_severity_reason("CRITICAL", "Critical", "MODIFIED", 0.85, None)
    assert "binary modification" in r3.lower()

    # Additive elevation
    r4 = generate_severity_reason("HIGH", "High", "MODIFIED", 0.85, 0.03)
    assert "elevated by high behavioral anomaly" in r4

    # Routine baseline
    r5 = generate_severity_reason("LOW", "Low", "MODIFIED", 0.10, 0.02)
    assert "baseline" in r5.lower()


def test_determinism():
    """Verify identical calls yield identical evidence dictionaries."""
    change = {"file_path": "/configs/auth.conf", "criticality": "High", "change_type": "MODIFIED"}
    ev1 = generate_evidence(change, "HIGH", anomaly_score=0.85, drift_score=0.10)
    for _ in range(100):
        ev2 = generate_evidence(change, "HIGH", anomaly_score=0.85, drift_score=0.10)
        assert ev1 == ev2


def test_input_validation():
    """Verify proper ValueError on invalid input types."""
    with pytest.raises(ValueError, match="dictionary"):
        generate_evidence("invalid", "HIGH")  # type: ignore
    with pytest.raises(ValueError, match="string"):
        generate_evidence({"criticality": "High"}, 123)  # type: ignore
