"""
Tests for Phase 7 Semantic Drift Detection module.
"""
import json
import math
from pathlib import Path
import pytest

from ai_scoring import drift


def test_calculate_drift_exists():
    """Verify core API symbols exist."""
    assert hasattr(drift, "calculate_drift")
    assert hasattr(drift, "calculate_change_drift")
    assert hasattr(drift, "calculate_batch_drift")
    assert hasattr(drift, "get_model")


def test_null_and_missing_content_behavior():
    """Verify None is returned when content is missing or change is not a text MODIFIED."""
    # None inputs
    assert drift.calculate_drift(None, "content") is None
    assert drift.calculate_drift("content", None) is None
    assert drift.calculate_drift(None, None) is None

    # ADDED file -> None
    added_change = {
        "file_path": "/scripts/malware.sh",
        "change_type": "ADDED",
        "old_content": None,
        "new_content": "echo 'owned'"
    }
    assert drift.calculate_change_drift(added_change) is None

    # DELETED file -> None
    deleted_change = {
        "file_path": "/configs/backup.conf",
        "change_type": "DELETED",
        "old_content": "backup_enabled=true",
        "new_content": None
    }
    assert drift.calculate_change_drift(deleted_change) is None

    # Binary MODIFIED -> None
    binary_change = {
        "file_path": "/bin/app",
        "change_type": "MODIFIED",
        "old_content": None,
        "new_content": None
    }
    assert drift.calculate_change_drift(binary_change) is None

    # Invalid types
    assert drift.calculate_drift(123, "content") is None  # type: ignore
    assert drift.calculate_change_drift("not_a_dict") is None  # type: ignore


def test_identical_and_empty_text():
    """Verify identical text and whitespace-only text fast-paths to 0.0."""
    assert drift.calculate_drift("ALLOW_LOGIN=true", "ALLOW_LOGIN=true") == 0.0
    assert drift.calculate_drift("", "") == 0.0
    assert drift.calculate_drift("   \n\t  ", "  ") == 0.0


def test_semantic_behavioral_hierarchy():
    """
    Verify relative semantic expectations:
    - Identical content drift == 0.0
    - Formatting-only drift < meaningful drift
    - Meaningful drift < completely unrelated content drift
    No arbitrary absolute threshold assertions.
    """
    model = drift.get_model()

    # 1. Identical
    d_identical = drift.calculate_drift("ALLOW_LOGIN=true\n", "ALLOW_LOGIN=true\n", model=model)
    assert d_identical == 0.0

    # 2. Formatting-only (e.g. whitespace around =)
    d_formatting = drift.calculate_drift("DB_HOST=localhost\nDB_PORT=5432\n", "DB_HOST = localhost\nDB_PORT = 5432\n", model=model)

    # 3. Meaningful security change
    d_meaningful = drift.calculate_drift("ALLOW_LOGIN=true\n", "ALLOW_LOGIN=false\n", model=model)

    # 4. Completely unrelated text
    d_unrelated = drift.calculate_drift("ALLOW_LOGIN=true\n", "The quick brown fox jumps over the lazy dog\n", model=model)

    # Verify finite and in range [0, 1]
    for d in [d_identical, d_formatting, d_meaningful, d_unrelated]:
        assert d is not None
        assert 0.0 <= d <= 1.0
        assert math.isfinite(d)

    # Relative behavioral hierarchy
    assert d_identical <= d_formatting
    assert d_formatting < d_meaningful
    assert d_meaningful < d_unrelated


def test_determinism():
    """Verify calling calculate_drift twice with identical text yields identical float score."""
    model = drift.get_model()
    s1 = drift.calculate_drift("timeout=30", "timeout=35", model=model)
    s2 = drift.calculate_drift("timeout=30", "timeout=35", model=model)
    assert s1 == s2


def test_batch_equivalence():
    """Verify calculate_batch_drift produces identical outputs to individual calls."""
    changes = [
        {
            "file_path": "/configs/nginx.conf",
            "change_type": "MODIFIED",
            "old_content": "timeout=30\n",
            "new_content": "timeout=35\n"
        },
        {
            "file_path": "/configs/auth.conf",
            "change_type": "MODIFIED",
            "old_content": "ALLOW_LOGIN=true\n",
            "new_content": "ALLOW_LOGIN=false\n"
        },
        {
            "file_path": "/scripts/script.sh",
            "change_type": "ADDED",
            "old_content": None,
            "new_content": "echo 'hi'"
        },
        {
            "file_path": "/configs/same.conf",
            "change_type": "MODIFIED",
            "old_content": "test",
            "new_content": "test"
        }
    ]

    model = drift.get_model()
    batch_scores = drift.calculate_batch_drift(changes, model=model)
    individual_scores = [drift.calculate_change_drift(c, model=model) for c in changes]

    assert batch_scores == individual_scores
    assert batch_scores[2] is None
    assert batch_scores[3] == 0.0


def test_demo_scenarios_drift():
    """Verify semantic drift across demo scenarios from data/demo_changes.json."""
    demo_path = Path("data/demo_changes.json")
    if not demo_path.exists():
        pytest.skip("demo_changes.json not found")

    with open(demo_path, "r", encoding="utf-8") as f:
        demos = json.load(f)

    model = drift.get_model()

    # formatting_only
    d_format = drift.calculate_change_drift(demos["formatting_only"][0], model=model)
    # meaningful_change
    d_meaningful = drift.calculate_change_drift(demos["meaningful_change"][0], model=model)

    assert d_format is not None
    assert d_meaningful is not None
    assert d_format < d_meaningful

    # added_file -> None
    assert drift.calculate_change_drift(demos["added_file"][0], model=model) is None
    # deleted_file -> None
    assert drift.calculate_change_drift(demos["deleted_file"][0], model=model) is None
    # binary_modified -> None
    assert drift.calculate_change_drift(demos["binary_modified"][0], model=model) is None
