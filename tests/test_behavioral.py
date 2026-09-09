"""
Phase 11: Comprehensive Behavioral Verification & Integration Tests.
Tests behavioral invariants, safety under edge cases, strict contract adherence,
linguistic invariants, immutability, and determinism.
"""
import copy
import json
from pathlib import Path
import pytest

from ai_scoring.scorer import score_changes
from ai_scoring.drift import get_model, calculate_drift


HIST_FILE = Path("data/historical_scans.json")
DEMO_FILE = Path("data/demo_changes.json")

DISALLOWED_SPECULATIVE_WORDS = [
    "active attack",
    "malicious",
    "unauthorized",
    "security breach",
    "formatting, whitespace, or cosmetic adjustments only",
]


@pytest.fixture(scope="module")
def dataset():
    """Loads historical scans and demo scenarios once for behavioral tests."""
    if not HIST_FILE.exists() or not DEMO_FILE.exists():
        pytest.skip("Required mock dataset files not found")
    with open(HIST_FILE, "r", encoding="utf-8") as f:
        history = json.load(f)
    with open(DEMO_FILE, "r", encoding="utf-8") as f:
        demos = json.load(f)
    return history, demos


# ============================================================================
# 1. CONTROLLED BEHAVIORAL RANKINGS & INVARIANTS
# ============================================================================

def test_controlled_behavioral_rankings(dataset):
    """
    Verifies controlled behavioral expectations across the demo dataset:
    1. anomaly(suspicious_bulk) > anomaly(benign)
    2. drift(formatting_only) <= drift(meaningful_change)
    3. severity(suspicious_bulk) >= severity(benign)
    """
    history, demos = dataset

    scored_benign = score_changes(demos["benign"], history)
    scored_bulk = score_changes(demos["suspicious_bulk"], history)
    scored_formatting = score_changes(demos["formatting_only"], history)
    scored_meaningful = score_changes(demos["meaningful_change"], history)

    # 1. Anomaly inequality
    a_benign = scored_benign[0]["anomaly_score"]
    a_bulk = scored_bulk[0]["anomaly_score"]
    assert a_bulk is not None and a_benign is not None
    assert a_bulk > a_benign, (
        f"Behavioral expectation failed: anomaly(suspicious_bulk)={a_bulk:.4f} "
        f"should be > anomaly(benign)={a_benign:.4f}"
    )

    # 2. Severity expectations
    assert scored_benign[0]["severity"] in {"LOW", "MEDIUM"}
    for item in scored_bulk:
        assert item["severity"] in {"HIGH", "CRITICAL"}

    sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    assert sev_order[scored_bulk[0]["severity"]] >= sev_order[scored_benign[0]["severity"]]

    # 3. Controlled drift expectation: formatting_only <= meaningful_change
    d_formatting = scored_formatting[0]["drift_score"]
    d_meaningful = scored_meaningful[0]["drift_score"]
    assert d_formatting is not None and d_meaningful is not None
    assert d_formatting <= d_meaningful, (
        f"Behavioral expectation failed: drift(formatting)={d_formatting:.4f} "
        f"should be <= drift(meaningful)={d_meaningful:.4f}"
    )

    # 4. Observational / Diagnostic check: compare against completely unrelated text
    # (Logged diagnostically, NOT treated as a rigid invariant or failure condition)
    unrelated_drift = calculate_drift("ALLOW_LOGIN=true\n", "The quick brown fox jumps over the lazy dog.")
    print(f"\n[OBSERVATIONAL DIAGNOSTIC] meaningful drift: {d_meaningful:.4f} vs unrelated drift: {unrelated_drift}")


# ============================================================================
# 2. SEVERITY FAIL-SAFES AND COMPOUNDING
# ============================================================================

def test_severity_fail_safes_and_compounding(dataset):
    """
    Verifies fail-safe elevation and compounding rules:
    - Critical + DELETED is unconditionally CRITICAL
    - Critical + binary MODIFIED under high anomaly is CRITICAL
    - Compounding high anomaly + high drift is CRITICAL
    """
    history, demos = dataset

    # Critical deletion fail-safe (cold start)
    crit_del = [{"file_path": "/core/security.db", "change_type": "DELETED", "criticality": "Critical"}]
    res_del = score_changes(crit_del, [])
    assert res_del[0]["severity"] == "CRITICAL"
    assert "fail-safe" in res_del[0]["evidence"]["severity_reason"].lower()

    # Binary modified demo scenario (/bin/app)
    scored_bin = score_changes(demos["binary_modified"], history)
    assert scored_bin[0]["severity"] == "CRITICAL"
    assert scored_bin[0]["drift_score"] is None
    assert "binary" in scored_bin[0]["evidence"]["severity_reason"].lower()

    # Compounding risk in suspicious_bulk
    scored_bulk = score_changes(demos["suspicious_bulk"], history)
    for item in scored_bulk:
        assert item["severity"] == "CRITICAL"
        if item["drift_score"] is not None and item["drift_score"] >= 0.15:
            assert "compounding risk" in item["evidence"]["severity_reason"].lower()


# ============================================================================
# 3. REQUIRED VS OPTIONAL FIELD BOUNDARIES
# ============================================================================

def test_required_vs_optional_field_boundaries():
    """
    Verifies that missing REQUIRED fields (file_path, change_type) strictly raise ValueError,
    while missing OPTIONAL fields (criticality, detected_at, old_content, new_content,
    old_hash, new_hash) are handled safely without unhandled exceptions.
    """
    # Missing required field: file_path
    with pytest.raises(ValueError, match="Invalid change record"):
        score_changes([{"change_type": "MODIFIED"}], [])

    # Missing required field: change_type
    with pytest.raises(ValueError, match="Invalid change record"):
        score_changes([{"file_path": "/app.conf"}], [])

    # Invalid required field: change_type
    with pytest.raises(ValueError, match="Invalid change record"):
        score_changes([{"file_path": "/app.conf", "change_type": "RENAMED"}], [])

    # Minimal change record: ONLY required fields provided
    minimal_change = [{"file_path": "/configs/app.conf", "change_type": "MODIFIED"}]
    res = score_changes(minimal_change, [])
    assert len(res) == 1
    enriched = res[0]

    # Validates safe defaults and enrichment
    assert enriched["file_path"] == "/configs/app.conf"
    assert enriched["change_type"] == "MODIFIED"
    assert enriched["anomaly_score"] is None
    assert enriched["drift_score"] is None  # no content provided
    assert enriched["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert set(enriched["evidence"].keys()) == {
        "anomaly_reason", "drift_reason", "criticality_reason", "severity_reason"
    }


# ============================================================================
# 4. CONTENT HANDLING EDGE CASES
# ============================================================================

def test_content_handling_edge_cases():
    """
    Verifies safe handling of empty strings, whitespace, asymmetric content,
    and large multi-line text blocks.
    """
    edge_cases = [
        # Empty text strings
        {"file_path": "/f1.txt", "change_type": "MODIFIED", "criticality": "Low",
         "old_content": "", "new_content": ""},
        # Whitespace-only strings
        {"file_path": "/f2.txt", "change_type": "MODIFIED", "criticality": "Low",
         "old_content": "   \n\t", "new_content": "  "},
        # Asymmetric missing content
        {"file_path": "/f3.txt", "change_type": "MODIFIED", "criticality": "Medium",
         "old_content": "content", "new_content": None},
        # Multi-line large content
        {"file_path": "/f4.txt", "change_type": "MODIFIED", "criticality": "High",
         "old_content": "\n".join([f"line_{i} = {i}" for i in range(150)]),
         "new_content": "\n".join([f"line_{i} = {i + 1}" for i in range(150)])},
        # Special characters & unicode
        {"file_path": "/f5.txt", "change_type": "MODIFIED", "criticality": "Low",
         "old_content": "secret = '🔑'", "new_content": "secret = '🔒'"}
    ]

    scored = score_changes(edge_cases, [])
    assert len(scored) == len(edge_cases)

    # Empty text -> drift 0.0
    assert scored[0]["drift_score"] == 0.0
    # Whitespace text -> drift 0.0
    assert scored[1]["drift_score"] == 0.0
    # Asymmetric None -> drift None
    assert scored[2]["drift_score"] is None
    # Multi-line -> valid finite float
    assert isinstance(scored[3]["drift_score"], float)
    # Unicode -> valid finite float
    assert isinstance(scored[4]["drift_score"], float)

    for item in scored:
        for ev_text in item["evidence"].values():
            assert isinstance(ev_text, str) and len(ev_text.strip()) > 0


# ============================================================================
# 5. EVIDENCE LINGUISTIC INVARIANTS (NO SPECULATIVE LANGUAGE)
# ============================================================================

def test_evidence_linguistic_invariants(dataset):
    """
    Verifies that across all 7 demo scenarios, no speculative or ungrounded language
    ('active attack', 'malicious', 'unauthorized', 'security breach',
    'formatting, whitespace, or cosmetic adjustments only') is ever generated.
    """
    history, demos = dataset

    for scenario_name, changes in demos.items():
        scored = score_changes(changes, history)
        for item in scored:
            combined_evidence = " ".join(item["evidence"].values()).lower()
            for word in DISALLOWED_SPECULATIVE_WORDS:
                assert word not in combined_evidence, (
                    f"Disallowed speculative term '{word}' found in scenario "
                    f"'{scenario_name}' on file '{item['file_path']}':\n{combined_evidence}"
                )


# ============================================================================
# 6. PIPELINE IMMUTABILITY AND DETERMINISM
# ============================================================================

def test_pipeline_immutability_and_determinism(dataset):
    """
    Verifies:
    1. Input dictionaries and lists are not modified in-place.
    2. 100% deterministic outputs across repeated calls on identical data.
    """
    history, demos = dataset
    original_changes = demos["meaningful_change"]
    changes_clone = copy.deepcopy(original_changes)

    # First run
    run_1 = score_changes(original_changes, history)

    # Verify input non-mutation
    assert original_changes == changes_clone
    assert original_changes[0] is not run_1[0]

    # Second run
    run_2 = score_changes(original_changes, history)

    # Verify determinism
    assert run_1 == run_2


# ============================================================================
# 7. SINGLETON MODEL REUSE
# ============================================================================

def test_singleton_model_caching():
    """
    Verifies that get_model() returns the identical cached SentenceTransformer instance
    across repeated calls. (Note: unit test verifies instance reuse, not total absence of leaks).
    """
    m1 = get_model()
    m2 = get_model()
    assert m1 is m2
