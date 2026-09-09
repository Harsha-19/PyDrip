"""Tests for the data contract validation."""
import json
import os
from ai_scoring.contract import validate_change, validate_scan_history

def get_fixture_data():
    path = os.path.join(os.path.dirname(__file__), "..", "data", "contract_examples.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def test_valid_examples():
    data = get_fixture_data()
    assert validate_change(data["example_1"]["change"])
    assert validate_change(data["example_2"]["change"])
    assert validate_change(data["example_3"]["change"])
    assert validate_change(data["example_4"]["change"])
    
    # Test example 5 (multiple changes)
    for c in data["example_5"]["changes"]:
        assert validate_change(c)
        
    # Test example 6 (historical scans)
    assert validate_scan_history(data["example_6"]["history"])

def test_invalid_change_missing_file_path():
    assert not validate_change({"change_type": "MODIFIED"})

def test_invalid_change_type():
    assert not validate_change({"file_path": "/a", "change_type": "UNKNOWN"})

def test_invalid_criticality():
    assert not validate_change({"file_path": "/a", "change_type": "MODIFIED", "criticality": "SuperHigh"})

def test_invalid_scan_history():
    assert not validate_scan_history([{"scan_id": "scan_1"}]) # missing changes
