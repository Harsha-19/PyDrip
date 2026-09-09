"""Unit tests for Phase 7 Audit Integration across Baseline, Scan, and Config workflows."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.config import DEFAULT_CONFIG_PATH, load_config, save_config
from app.core.baseline import MonitoredPathNotFoundError, create_baseline
from app.core.scanner import NoBaselineFoundError, run_scan
from app.database import (
    append_audit_log,
    get_audit_history,
    initialize_database,
)
from app.main import app
from app.models import (
    AppConfig,
    Criticality,
    CriticalityRulesConfig,
    MonitoredPathConfig,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def preserve_config_state():
    """Ensure tests that modify config.yaml restore the original content afterwards."""
    original_config = load_config()
    yield
    save_config(original_config)


@pytest.fixture
def audit_workspace(tmp_path: Path):
    """Fixture providing an isolated SQLite database and sample directory for audit testing."""
    db_file = tmp_path / "test_audit.db"
    initialize_database(db_file)

    sample_dir = tmp_path / "sample_data"
    sample_dir.mkdir()
    (sample_dir / "app.py").write_text("print('test')", encoding="utf-8")
    (sample_dir / ".env").write_text("SECRET_KEY=supersecret", encoding="utf-8")

    config = AppConfig(
        monitored_paths=[
            MonitoredPathConfig(path=str(sample_dir), criticality=Criticality.Medium)
        ],
        criticality_rules=CriticalityRulesConfig(
            extensions={
                ".env": Criticality.Critical,
                ".py": Criticality.Medium,
            }
        ),
    )

    return {
        "db_file": db_file,
        "sample_dir": sample_dir,
        "config": config,
        "tmp_path": tmp_path,
    }


def test_baseline_creates_baseline_created_audit_event(audit_workspace):
    """Test 1 & 14: Verify successful baseline creates exactly one BASELINE_CREATED event with scan_id."""
    ws = audit_workspace
    summary = create_baseline(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])

    history = get_audit_history(db_path=ws["db_file"])
    assert len(history) == 1
    event = history[0]

    assert event["action"] == "BASELINE_CREATED"
    assert f"scan_id={summary.scan_id}" in event["details"]
    assert "files_indexed=2" in event["details"]
    assert event["timestamp"] is not None


def test_failed_baseline_does_not_create_audit_event(audit_workspace):
    """Test 6: Verify failed baseline does NOT falsely create a BASELINE_CREATED event."""
    ws = audit_workspace
    bad_config = AppConfig(
        monitored_paths=[
            MonitoredPathConfig(path=str(ws["tmp_path"] / "nonexistent_dir"), criticality=Criticality.Low)
        ],
        criticality_rules=CriticalityRulesConfig(extensions={}),
    )

    with pytest.raises(MonitoredPathNotFoundError):
        create_baseline(config=bad_config, db_path=ws["db_file"], base_dir=ws["tmp_path"])

    history = get_audit_history(db_path=ws["db_file"])
    assert len(history) == 0


def test_scan_creates_scan_completed_audit_event(audit_workspace):
    """Test 2 & 11 & 12 & 13: Verify successful scan creates SCAN_COMPLETED event with scan_id, baseline_id, counts."""
    ws = audit_workspace
    base_summary = create_baseline(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])

    # Modify one file
    (ws["sample_dir"] / "app.py").write_text("print('updated')", encoding="utf-8")

    scan_summary = run_scan(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])

    history = get_audit_history(db_path=ws["db_file"])
    assert len(history) == 2  # 1 BASELINE_CREATED + 1 SCAN_COMPLETED

    scan_event = history[1]
    assert scan_event["action"] == "SCAN_COMPLETED"
    assert f"scan_id={scan_summary.scan_id}" in scan_event["details"]
    assert f"baseline_scan_id={base_summary.scan_id}" in scan_event["details"]
    assert "changes=1" in scan_event["details"]
    assert "modified=1" in scan_event["details"]
    assert "added=0" in scan_event["details"]
    assert "deleted=0" in scan_event["details"]


def test_zero_change_scan_creates_audit_event(audit_workspace):
    """Test 3: Verify zero-change scan is recorded as successful in audit log."""
    ws = audit_workspace
    create_baseline(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])

    scan_summary = run_scan(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])
    assert scan_summary.total_changes == 0

    history = get_audit_history(db_path=ws["db_file"])
    assert len(history) == 2

    scan_event = history[1]
    assert scan_event["action"] == "SCAN_COMPLETED"
    assert "changes=0" in scan_event["details"]


def test_failed_scan_does_not_create_audit_event(audit_workspace):
    """Test 7: Verify failed scan (e.g. no baseline) does not write SCAN_COMPLETED."""
    ws = audit_workspace
    with pytest.raises(NoBaselineFoundError):
        run_scan(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])

    history = get_audit_history(db_path=ws["db_file"])
    assert len(history) == 0


def test_put_config_auditing_and_validation_rejection():
    """Test 4 & 5: Verify valid PUT /config appends CONFIG_UPDATE, while invalid rejects without logging."""
    # 1. Invalid payload rejected by Pydantic validation -> HTTP 422
    initial_history_len = len(get_audit_history())
    invalid_payload = {
        "monitored_paths": [{"path": "./sample_data", "criticality": "NonExistentLevel"}],
        "criticality_rules": {"extensions": {}}
    }
    resp = client.put("/config", json=invalid_payload)
    assert resp.status_code == 422
    assert len(get_audit_history()) == initial_history_len

    # 2. Valid payload accepted -> HTTP 200 and audit entry appended
    valid_payload = {
        "monitored_paths": [{"path": "./sample_data", "criticality": "High"}],
        "criticality_rules": {"extensions": {".env": "Critical"}}
    }
    resp2 = client.put("/config", json=valid_payload)
    assert resp2.status_code == 200

    updated_history = get_audit_history()
    assert len(updated_history) == initial_history_len + 1
    last_event = updated_history[-1]
    assert last_event["action"] == "CONFIG_UPDATE"
    assert "Monitored paths: 1" in last_event["details"]


def test_audit_log_append_only_and_ordering(audit_workspace):
    """Test 8 & 9 & 10: Verify append-only property and chronological order preservation."""
    ws = audit_workspace

    id1 = append_audit_log("ACTION_1", "Details 1", timestamp="2026-09-09T10:00:00Z", db_path=ws["db_file"])
    id2 = append_audit_log("ACTION_2", "Details 2", timestamp="2026-09-09T11:00:00Z", db_path=ws["db_file"])
    id3 = append_audit_log("ACTION_3", "Details 3", timestamp="2026-09-09T12:00:00Z", db_path=ws["db_file"])

    assert id1 < id2 < id3

    history = get_audit_history(db_path=ws["db_file"])
    assert len(history) == 3
    assert [h["action"] for h in history] == ["ACTION_1", "ACTION_2", "ACTION_3"]
    assert [h["id"] for h in history] == [id1, id2, id3]


def test_audit_log_contains_no_sensitive_file_contents(audit_workspace):
    """Test 15: Verify audit log records contain operational metadata, never sensitive file contents or secrets."""
    ws = audit_workspace
    create_baseline(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])
    run_scan(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])

    history = get_audit_history(db_path=ws["db_file"])
    for event in history:
        # Check that secret content from .env ("supersecret") is never stored in audit details
        assert "supersecret" not in event["details"]
        assert "SECRET_KEY" not in event["details"]
        assert "print(" not in event["details"]
