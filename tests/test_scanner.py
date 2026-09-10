"""Unit tests for Phase 6 Scan and Diff Engine."""

import hashlib
from pathlib import Path
import pytest

from app.core.baseline import MonitoredPathNotFoundError, create_baseline
from app.core.scanner import NoBaselineFoundError, run_scan
from app.database import (
    get_audit_history,
    get_changes_by_scan_id,
    initialize_database,
)
from app.models import (
    AppConfig,
    ChangeType,
    Criticality,
    CriticalityRulesConfig,
    MonitoredPathConfig,
)


@pytest.fixture
def scanner_workspace(tmp_path: Path):
    """Fixture providing an isolated workspace for baseline + scan testing."""
    db_file = tmp_path / "test_fim.db"
    initialize_database(db_file)

    sample_dir = tmp_path / "sample_data"
    sample_dir.mkdir()

    # Seed initial known files
    (sample_dir / "app.py").write_text("print('version 1.0')", encoding="utf-8")
    (sample_dir / "config.conf").write_text("setting=original", encoding="utf-8")
    (sample_dir / ".env").write_text("DB_PASS=secret1", encoding="utf-8")
    (sample_dir / "todelete.txt").write_text("will be deleted", encoding="utf-8")
    (sample_dir / "binary.bin").write_bytes(bytes([10, 20, 30, 40]))
    (sample_dir / "static.txt").write_text("remains untouched", encoding="utf-8")

    config = AppConfig(
        monitored_paths=[
            MonitoredPathConfig(path=str(sample_dir), criticality=Criticality.Medium)
        ],
        criticality_rules=CriticalityRulesConfig(
            extensions={
                ".env": Criticality.Critical,
                ".conf": Criticality.High,
                ".cfg": Criticality.High,
                ".py": Criticality.Medium,
                ".txt": Criticality.Low,
            }
        ),
    )

    return {
        "db_file": db_file,
        "sample_dir": sample_dir,
        "config": config,
        "tmp_path": tmp_path,
    }


def test_scan_no_baseline_raises_error(scanner_workspace):
    """Test 11: Verify running scan without any baseline raises NoBaselineFoundError."""
    ws = scanner_workspace
    with pytest.raises(NoBaselineFoundError) as exc_info:
        run_scan(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])
    assert "no baseline found" in str(exc_info.value).lower()


def test_scan_unchanged_zero_changes(scanner_workspace):
    """Test 1: Create baseline, leave files untouched, verify zero changes detected."""
    ws = scanner_workspace
    base_summary = create_baseline(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])
    assert base_summary.files_indexed == 6

    scan_summary = run_scan(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])
    assert scan_summary.total_changes == 0
    assert scan_summary.added_count == 0
    assert scan_summary.deleted_count == 0
    assert scan_summary.modified_count == 0
    assert scan_summary.baseline_scan_id == base_summary.scan_id

    # Verify no records in changes table
    records = get_changes_by_scan_id(scan_summary.scan_id, db_path=ws["db_file"])
    assert len(records) == 0


def test_scan_detects_modified_file(scanner_workspace):
    """Test 2 & 6 & 7 & 8: Verify modifying an existing file triggers MODIFIED change."""
    ws = scanner_workspace
    base_summary = create_baseline(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])

    # Compute original hash
    orig_hash = hashlib.sha256(b"print('version 1.0')").hexdigest()

    # Modify app.py
    (ws["sample_dir"] / "app.py").write_text("print('version 2.0 - altered')", encoding="utf-8")
    new_hash = hashlib.sha256(b"print('version 2.0 - altered')").hexdigest()

    scan_summary = run_scan(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])
    assert scan_summary.total_changes == 1
    assert scan_summary.modified_count == 1
    assert scan_summary.added_count == 0
    assert scan_summary.deleted_count == 0

    records = get_changes_by_scan_id(scan_summary.scan_id, db_path=ws["db_file"])
    assert len(records) == 1
    rec = records[0]

    assert rec["change_type"] == "MODIFIED"
    assert rec["old_hash"] == orig_hash
    assert rec["new_hash"] == new_hash
    assert rec["old_hash"] != rec["new_hash"]
    assert rec["criticality"] == "Medium"
    # Null AI scoring fields
    assert rec["anomaly_score"] is None
    assert rec["drift_score"] is None
    assert rec["severity"] is None


def test_scan_detects_added_file(scanner_workspace):
    """Test 3: Verify creating a new file triggers ADDED change with old_hash=None."""
    ws = scanner_workspace
    base_summary = create_baseline(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])

    # Add brand new file
    (ws["sample_dir"] / "new_exploit.py").write_text("# new payload", encoding="utf-8")
    new_py_hash = hashlib.sha256(b"# new payload").hexdigest()

    scan_summary = run_scan(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])
    assert scan_summary.total_changes == 1
    assert scan_summary.added_count == 1
    assert scan_summary.modified_count == 0
    assert scan_summary.deleted_count == 0

    records = get_changes_by_scan_id(scan_summary.scan_id, db_path=ws["db_file"])
    assert len(records) == 1
    rec = records[0]
    assert rec["change_type"] == "ADDED"
    assert rec["old_hash"] is None
    assert rec["new_hash"] == new_py_hash
    assert rec["criticality"] == "Medium"


def test_scan_detects_deleted_file(scanner_workspace):
    """Test 4: Verify deleting an existing file triggers DELETED change with new_hash=None."""
    ws = scanner_workspace
    base_summary = create_baseline(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])

    todelete_hash = hashlib.sha256(b"will be deleted").hexdigest()

    # Delete todelete.txt
    (ws["sample_dir"] / "todelete.txt").unlink()

    scan_summary = run_scan(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])
    assert scan_summary.total_changes == 1
    assert scan_summary.deleted_count == 1
    assert scan_summary.added_count == 0
    assert scan_summary.modified_count == 0

    records = get_changes_by_scan_id(scan_summary.scan_id, db_path=ws["db_file"])
    assert len(records) == 1
    rec = records[0]
    assert rec["change_type"] == "DELETED"
    assert rec["old_hash"] == todelete_hash
    assert rec["new_hash"] is None
    assert rec["criticality"] == "Low"  # From baseline criticality rule for .txt


def test_scan_multiple_changes_simultaneous(scanner_workspace):
    """Test 5 & 9 & 10: Verify multiple simultaneous changes (ADDED, DELETED, MODIFIED) in one scan."""
    ws = scanner_workspace
    base_summary = create_baseline(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])

    # 1. Modify .env
    (ws["sample_dir"] / ".env").write_text("DB_PASS=compromised_secret", encoding="utf-8")
    # 2. Add brand new config file
    (ws["sample_dir"] / "backdoor.conf").write_text("backdoor=true", encoding="utf-8")
    # 3. Delete todelete.txt
    (ws["sample_dir"] / "todelete.txt").unlink()
    # 4. static.txt, binary.bin, app.py remain UNTOUCHED

    scan_summary = run_scan(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])
    assert scan_summary.total_changes == 3
    assert scan_summary.modified_count == 1
    assert scan_summary.added_count == 1
    assert scan_summary.deleted_count == 1

    # Check distinct scan_id
    assert scan_summary.scan_id != base_summary.scan_id
    assert scan_summary.scan_id.startswith("scan-")

    records = get_changes_by_scan_id(scan_summary.scan_id, db_path=ws["db_file"])
    assert len(records) == 3

    types_by_filename = {Path(r["file_path"]).name: r for r in records}
    assert ".env" in types_by_filename
    assert types_by_filename[".env"]["change_type"] == "MODIFIED"
    assert types_by_filename[".env"]["criticality"] == "Critical"

    assert "backdoor.conf" in types_by_filename
    assert types_by_filename["backdoor.conf"]["change_type"] == "ADDED"
    assert types_by_filename["backdoor.conf"]["criticality"] == "High"

    assert "todelete.txt" in types_by_filename
    assert types_by_filename["todelete.txt"]["change_type"] == "DELETED"
    assert types_by_filename["todelete.txt"]["criticality"] == "Low"

    # Verify untouched files do NOT appear in change records
    assert "static.txt" not in types_by_filename
    assert "binary.bin" not in types_by_filename
    assert "app.py" not in types_by_filename

    # Verify audit log recorded scan
    audit = get_audit_history(db_path=ws["db_file"])
    scan_audits = [a for a in audit if a["action"] == "SCAN_COMPLETED"]
    assert len(scan_audits) == 1
    assert f"scan_id={scan_summary.scan_id}" in scan_audits[0]["details"]


def test_scan_binary_file_modification(scanner_workspace):
    """Test 13: Verify binary file modification is detected via SHA-256."""
    ws = scanner_workspace
    base_summary = create_baseline(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])

    orig_bin_hash = hashlib.sha256(bytes([10, 20, 30, 40])).hexdigest()

    # Modify binary file
    (ws["sample_dir"] / "binary.bin").write_bytes(bytes([10, 20, 30, 99, 100]))
    new_bin_hash = hashlib.sha256(bytes([10, 20, 30, 99, 100])).hexdigest()

    scan_summary = run_scan(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])
    assert scan_summary.total_changes == 1
    assert scan_summary.modified_count == 1

    records = get_changes_by_scan_id(scan_summary.scan_id, db_path=ws["db_file"])
    assert len(records) == 1
    rec = records[0]
    assert rec["change_type"] == "MODIFIED"
    assert rec["old_hash"] == orig_bin_hash
    assert rec["new_hash"] == new_bin_hash


def test_scan_missing_monitored_path_raises_error(scanner_workspace):
    """Test 12: Verify missing monitored path raises MonitoredPathNotFoundError."""
    ws = scanner_workspace
    create_baseline(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])

    bad_config = AppConfig(
        monitored_paths=[
            MonitoredPathConfig(path=str(ws["tmp_path"] / "non_existent_folder"), criticality=Criticality.Medium)
        ],
        criticality_rules=CriticalityRulesConfig(extensions={}),
    )

    with pytest.raises(MonitoredPathNotFoundError) as exc_info:
        run_scan(config=bad_config, db_path=ws["db_file"], base_dir=ws["tmp_path"])
    assert "does not exist" in str(exc_info.value).lower()
