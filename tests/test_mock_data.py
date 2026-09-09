"""Tests for mock data generation."""
from ai_scoring.mock_data import generate_historical_history, generate_demo_scenarios
from ai_scoring.contract import validate_change, validate_scan_history

def test_historical_dataset():
    history = generate_historical_history()
    assert 50 <= len(history) <= 100
    assert validate_scan_history(history)
    
    # Check chronological order
    timestamps = [batch["detected_at"] for batch in history]
    assert timestamps == sorted(timestamps)
    
    # Determinism
    history2 = generate_historical_history()
    assert history == history2

def test_demo_benign():
    scenarios = generate_demo_scenarios()
    benign = scenarios["benign"]
    assert len(benign) == 1
    assert benign[0]["criticality"] in ["Low", "Medium"]
    assert validate_change(benign[0])

def test_demo_formatting():
    scenarios = generate_demo_scenarios()
    fmt = scenarios["formatting_only"][0]
    assert fmt["old_content"] != fmt["new_content"]
    assert fmt["old_content"].replace(" ", "") == fmt["new_content"].replace(" ", "")
    assert validate_change(fmt)

def test_demo_meaningful():
    scenarios = generate_demo_scenarios()
    meaningful = scenarios["meaningful_change"][0]
    assert meaningful["old_content"] != meaningful["new_content"]
    assert "true" in meaningful["old_content"] and "false" in meaningful["new_content"]
    assert validate_change(meaningful)

def test_demo_suspicious_bulk():
    scenarios = generate_demo_scenarios()
    bulk = scenarios["suspicious_bulk"]
    assert len(bulk) >= 4
    for change in bulk:
        assert validate_change(change)
        assert change["criticality"] in ["High", "Critical"]
        assert "T02:0" in change["detected_at"]

def test_demo_added():
    scenarios = generate_demo_scenarios()
    added = scenarios["added_file"][0]
    assert added["change_type"] == "ADDED"
    assert added["old_hash"] is None
    assert added["old_content"] is None
    assert validate_change(added)

def test_demo_deleted():
    scenarios = generate_demo_scenarios()
    deleted = scenarios["deleted_file"][0]
    assert deleted["change_type"] == "DELETED"
    assert deleted["new_hash"] is None
    assert deleted["new_content"] is None
    assert validate_change(deleted)

def test_demo_binary():
    scenarios = generate_demo_scenarios()
    binary = scenarios["binary_modified"][0]
    assert binary["change_type"] == "MODIFIED"
    assert binary["old_content"] is None
    assert binary["new_content"] is None
    assert binary["old_hash"] is not None
    assert binary["new_hash"] is not None
    assert validate_change(binary)

def test_determinism():
    scenarios1 = generate_demo_scenarios()
    scenarios2 = generate_demo_scenarios()
    assert scenarios1 == scenarios2
