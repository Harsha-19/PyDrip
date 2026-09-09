"""
Tests for Phase 10 unified scoring coordinator (ai_scoring/scorer.py).
"""
import copy
import json
import inspect
from pathlib import Path
import pytest

from ai_scoring import scorer
from ai_scoring.scorer import score_changes


def test_score_changes_exists():
    """Verify score_changes public API exists."""
    assert hasattr(scorer, "score_changes")


# ============================================================================
# 1. INPUT VALIDATION TESTS
# ============================================================================

def test_invalid_input_types():
    """Verify ValueError on non-list inputs."""
    with pytest.raises(ValueError, match="change_list must be a list"):
        score_changes("invalid", [])  # type: ignore
    with pytest.raises(ValueError, match="scan_history must be a list"):
        score_changes([], "invalid")  # type: ignore


def test_invalid_change_records():
    """Verify ValueError on malformed change records."""
    # Missing file_path
    with pytest.raises(ValueError, match="Invalid change record"):
        score_changes([{"change_type": "MODIFIED"}], [])
    # Invalid change_type
    with pytest.raises(ValueError, match="Invalid change record"):
        score_changes([{"file_path": "/app.conf", "change_type": "RENAMED"}], [])
    # Invalid criticality
    with pytest.raises(ValueError, match="Invalid change record"):
        score_changes([{"file_path": "/app.conf", "change_type": "MODIFIED", "criticality": "Ultra"}], [])


def test_malformed_history_raises_value_error():
    """
    CRITICAL REQUIREMENT:
    A non-empty scan_history containing malformed records must NOT silently
    fall back to anomaly_score=None. It must strictly raise ValueError.
    """
    valid_change = {"file_path": "/app.conf", "change_type": "MODIFIED", "criticality": "High"}

    # Malformed scan: missing 'changes' list
    malformed_history_1 = [{"scan_id": "s1", "detected_at": "2026-09-08T12:00:00"}]
    with pytest.raises(ValueError, match="failed contract validation"):
        score_changes([valid_change], malformed_history_1)

    # Malformed scan: non-dict scan item
    malformed_history_2 = ["not_a_dict"]  # type: ignore
    with pytest.raises(ValueError, match="failed contract validation"):
        score_changes([valid_change], malformed_history_2)

    # Malformed scan: changes is not a list
    malformed_history_3 = [{"scan_id": "s1", "changes": "not_a_list"}]
    with pytest.raises(ValueError, match="failed contract validation"):
        score_changes([valid_change], malformed_history_3)


# ============================================================================
# 2. VALID EMPTY INPUT TESTS
# ============================================================================

def test_empty_change_list():
    """Empty change_list returns empty list immediately."""
    assert score_changes([], []) == []
    assert score_changes([], [{"scan_id": "s1", "changes": []}]) == []


def test_empty_scan_history_valid():
    """
    CRITICAL REQUIREMENT:
    scan_history == [] is a valid cold-start state.
    It proceeds cleanly and produces anomaly_score=None.
    """
    changes = [
        {"file_path": "/configs/app.conf", "change_type": "MODIFIED", "criticality": "High",
         "old_content": "timeout=30", "new_content": "timeout=60"}
    ]
    result = score_changes(changes, [])
    assert len(result) == 1
    enriched = result[0]
    assert enriched["anomaly_score"] is None
    assert enriched["drift_score"] is not None
    assert enriched["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert "evidence" in enriched
    assert enriched["evidence"]["anomaly_reason"] is not None


# ============================================================================
# 3. NON-MUTATION AND SCHEMA INVARIANTS
# ============================================================================

def test_input_non_mutation():
    """Input dictionaries must not be mutated in-place."""
    original_change = {
        "file_path": "/configs/app.conf",
        "change_type": "MODIFIED",
        "criticality": "High",
        "old_content": "a=1",
        "new_content": "a=2",
        "detected_at": "2026-09-09T12:00:00"
    }
    input_copy = copy.deepcopy(original_change)

    changes = [original_change]
    result = score_changes(changes, [])

    # Ensure input dict was not modified
    assert original_change == input_copy
    # Ensure returned dict is a new instance
    assert result[0] is not original_change
    # Ensure original keys are preserved
    for k in input_copy:
        assert result[0][k] == input_copy[k]


def test_exact_added_keys():
    """Verify that exactly anomaly_score, drift_score, severity, evidence are added."""
    change = {
        "file_path": "/configs/nginx.conf",
        "change_type": "MODIFIED",
        "criticality": "Low",
        "old_content": "a",
        "new_content": "b"
    }
    result = score_changes([change], [])
    enriched = result[0]

    expected_new_keys = {"anomaly_score", "drift_score", "severity", "evidence"}
    for k in expected_new_keys:
        assert k in enriched

    ev = enriched["evidence"]
    required_ev_keys = {"anomaly_reason", "drift_reason", "criticality_reason", "severity_reason"}
    assert set(ev.keys()) == required_ev_keys
    for ek, ev_val in ev.items():
        assert isinstance(ev_val, str) and len(ev_val.strip()) > 0


# ============================================================================
# 4. REGRESSION TESTS ON DEMO SCENARIOS
# ============================================================================

def test_demo_scenarios_regression():
    """
    Verify regression expectations across all 7 demo scenarios
    with historical_scans.json baseline.
    """
    hist_file = Path("data/historical_scans.json")
    demo_file = Path("data/demo_changes.json")
    if not hist_file.exists() or not demo_file.exists():
        pytest.skip("Required mock data files not found")

    with open(hist_file, "r", encoding="utf-8") as f:
        history = json.load(f)
    with open(demo_file, "r", encoding="utf-8") as f:
        demos = json.load(f)

    # Expected severities established in Phase 8
    expected_severities = {
        "benign": "MEDIUM",
        "formatting_only": "MEDIUM",
        "meaningful_change": "HIGH",
        "suspicious_bulk": "CRITICAL",
        "added_file": "CRITICAL",
        "deleted_file": "HIGH",
        "binary_modified": "CRITICAL",
    }

    for scenario_name, expected_sev in expected_severities.items():
        changes = demos[scenario_name]
        scored = score_changes(changes, history)

        assert len(scored) == len(changes)

        for item in scored:
            assert item["severity"] == expected_sev, (
                f"Scenario '{scenario_name}' on file '{item['file_path']}' got severity "
                f"'{item['severity']}', expected '{expected_sev}'"
            )
            # Verify evidence
            assert set(item["evidence"].keys()) == {
                "anomaly_reason", "drift_reason", "criticality_reason", "severity_reason"
            }
            for reason in item["evidence"].values():
                assert isinstance(reason, str) and len(reason.strip()) > 0


# ============================================================================
# 5. DETERMINISM AND NO HARDCODED LOGIC
# ============================================================================

def test_determinism():
    """Verify repeated calls return identical outputs."""
    changes = [
        {"file_path": "/configs/app.conf", "change_type": "MODIFIED", "criticality": "High",
         "old_content": "timeout=30", "new_content": "timeout=60"}
    ]
    out1 = score_changes(changes, [])
    out2 = score_changes(changes, [])
    assert out1 == out2


def test_no_hardcoded_overrides_in_scorer():
    """Verify scorer.py does not contain scenario names or hardcoded file paths."""
    src = inspect.getsource(scorer)
    forbidden_terms = [
        "suspicious_bulk",
        "meaningful_change",
        "formatting_only",
        "binary_modified",
        "/configs/nginx.conf",
        "/configs/database.conf",
        "/scripts/malware.sh",
    ]
    for term in forbidden_terms:
        assert term not in src, f"Found hardcoded test term '{term}' in scorer.py source code"
