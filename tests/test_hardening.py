"""Hardening and edge case tests for Phase 10."""

import hashlib
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.config import load_config, save_config
from app.core.baseline import (
    MonitoredPathNotFoundError,
    create_baseline,
    resolve_criticality,
)
from app.core.hasher import calculate_sha256
from app.core.scanner import NoBaselineFoundError, run_scan
from app.database import (
    get_audit_history,
    get_baselines_by_scan_id,
    get_changes_by_scan_id,
    get_latest_baseline,
    get_latest_baseline_scan_id,
    initialize_database,
    insert_change_records,
)
from app.main import app
from app.models import (
    AppConfig,
    ChangeType,
    Criticality,
    CriticalityRulesConfig,
    MonitoredPathConfig,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def preserve_config():
    orig = load_config()
    yield
    save_config(orig)


# ==============================================================================
# 1. HASHING HARDENING
# ==============================================================================

def test_hasher_invalid_chunk_size_raises_value_error(tmp_path: Path):
    """Verify calculate_sha256 raises ValueError on invalid chunk_size <= 0."""
    f = tmp_path / "test.txt"
    f.write_text("content", encoding="utf-8")

    with pytest.raises(ValueError) as exc:
        calculate_sha256(f, chunk_size=0)
    assert "positive integer" in str(exc.value)

    with pytest.raises(ValueError):
        calculate_sha256(f, chunk_size=-1024)


def test_hasher_large_streamed_file_matches(tmp_path: Path):
    """Verify hashing a large 2MB file streaming without loading all bytes at once."""
    large_file = tmp_path / "large.dat"
    chunk = b"A" * 65536
    hasher = hashlib.sha256()
    with open(large_file, "wb") as f:
        for _ in range(32):  # 2 MB total
            f.write(chunk)
            hasher.update(chunk)

    expected = hasher.hexdigest()
    actual = calculate_sha256(large_file, chunk_size=32768)
    assert actual == expected


# ==============================================================================
# 2. BASELINE HARDENING
# ==============================================================================

def test_baseline_monitored_single_file_direct(tmp_path: Path):
    """Verify baseline handles a single file configured directly as monitored path."""
    db_file = tmp_path / "test_single.db"
    initialize_database(db_file)

    single_file = tmp_path / "direct.conf"
    single_file.write_text("port=8080", encoding="utf-8")

    config = AppConfig(
        monitored_paths=[
            MonitoredPathConfig(path=str(single_file), criticality=Criticality.Medium)
        ],
        criticality_rules=CriticalityRulesConfig(extensions={".conf": Criticality.High}),
    )

    summary = create_baseline(config=config, db_path=db_file, base_dir=tmp_path)
    assert summary.files_indexed == 1

    records = get_baselines_by_scan_id(summary.scan_id, db_path=db_file)
    assert len(records) == 1
    assert records[0]["criticality"] == "High"


def test_baseline_does_not_modify_or_delete_files(tmp_path: Path):
    """Verify baseline snapshot operation is strictly read-only and does not mutate files."""
    db_file = tmp_path / "test_readonly.db"
    initialize_database(db_file)

    test_file = tmp_path / "safe.py"
    content = "print('immutable content')"
    test_file.write_text(content, encoding="utf-8")
    orig_mtime = test_file.stat().st_mtime

    config = AppConfig(
        monitored_paths=[MonitoredPathConfig(path=str(tmp_path), criticality=Criticality.Medium)],
        criticality_rules=CriticalityRulesConfig(extensions={}),
    )

    create_baseline(config=config, db_path=db_file, base_dir=tmp_path)

    # Verify content and mtime are untouched
    assert test_file.read_text(encoding="utf-8") == content
    assert test_file.stat().st_mtime == orig_mtime


# ==============================================================================
# 3. SCANNER REPEATABILITY & COMBINATIONS
# ==============================================================================

def test_scan_repeatability_without_filesystem_changes(tmp_path: Path):
    """Verify repeated scans against the same baseline yield identical change detection."""
    db_file = tmp_path / "test_repeat.db"
    initialize_database(db_file)

    sample_dir = tmp_path / "sample"
    sample_dir.mkdir()
    (sample_dir / "f1.txt").write_text("initial", encoding="utf-8")

    config = AppConfig(
        monitored_paths=[MonitoredPathConfig(path=str(sample_dir), criticality=Criticality.Low)],
        criticality_rules=CriticalityRulesConfig(extensions={}),
    )

    base = create_baseline(config=config, db_path=db_file, base_dir=tmp_path)

    # Modify file
    (sample_dir / "f1.txt").write_text("altered", encoding="utf-8")

    # Scan 1
    scan1 = run_scan(config=config, db_path=db_file, base_dir=tmp_path)
    assert scan1.total_changes == 1
    assert scan1.modified_count == 1
    assert scan1.baseline_scan_id == base.scan_id

    # Scan 2 (filesystem not modified again)
    scan2 = run_scan(config=config, db_path=db_file, base_dir=tmp_path)
    assert scan2.total_changes == 1
    assert scan2.modified_count == 1
    assert scan2.baseline_scan_id == base.scan_id
    assert scan2.scan_id != scan1.scan_id  # Unique scan IDs


def test_scanner_complex_nested_diff_combinations(tmp_path: Path):
    """Verify complex mixed diff combinations with deeply nested folders."""
    db_file = tmp_path / "test_nested.db"
    initialize_database(db_file)

    root_dir = tmp_path / "project"
    sub1 = root_dir / "sub1" / "sub2"
    sub1.mkdir(parents=True)

    (root_dir / "root.conf").write_text("root=1", encoding="utf-8")
    (sub1 / "deep.env").write_text("KEY=orig", encoding="utf-8")
    (sub1 / "delete_me.py").write_text("pass", encoding="utf-8")
    (root_dir / "stable.txt").write_text("stable", encoding="utf-8")

    config = AppConfig(
        monitored_paths=[MonitoredPathConfig(path=str(root_dir), criticality=Criticality.Medium)],
        criticality_rules=CriticalityRulesConfig(
            extensions={".env": Criticality.Critical, ".conf": Criticality.High, ".py": Criticality.Medium, ".txt": Criticality.Low}
        ),
    )

    base = create_baseline(config=config, db_path=db_file, base_dir=tmp_path)
    assert base.files_indexed == 4

    # Apply diffs:
    # 1. Modify deep.env
    (sub1 / "deep.env").write_text("KEY=changed", encoding="utf-8")
    # 2. Delete delete_me.py
    (sub1 / "delete_me.py").unlink()
    # 3. Add new file in nested folder
    (sub1 / "brand_new.cfg").write_text("config=new", encoding="utf-8")
    # root.conf and stable.txt remain unchanged

    scan = run_scan(config=config, db_path=db_file, base_dir=tmp_path)
    assert scan.total_changes == 3
    assert scan.modified_count == 1
    assert scan.deleted_count == 1
    assert scan.added_count == 1

    changes = get_changes_by_scan_id(scan.scan_id, db_path=db_file)
    by_name = {Path(c["file_path"]).name: c for c in changes}

    assert by_name["deep.env"]["change_type"] == "MODIFIED"
    assert by_name["deep.env"]["criticality"] == "Critical"

    assert by_name["delete_me.py"]["change_type"] == "DELETED"
    assert by_name["delete_me.py"]["criticality"] == "Medium"
    assert by_name["delete_me.py"]["new_hash"] is None

    assert by_name["brand_new.cfg"]["change_type"] == "ADDED"
    assert by_name["brand_new.cfg"]["old_hash"] is None


# ==============================================================================
# 4. DATABASE & REPEATED INITIALIZATION HARDENING
# ==============================================================================

def test_database_idempotent_multiple_calls_no_data_loss(tmp_path: Path):
    """Verify calling initialize_database 10 times consecutively maintains data integrity."""
    db_file = tmp_path / "repeated_init.db"

    # Initial creation
    initialize_database(db_file)
    create_baseline(
        config=AppConfig(monitored_paths=[], criticality_rules=CriticalityRulesConfig(extensions={})),
        db_path=db_file,
        base_dir=tmp_path,
    )

    # 10 repeated inits
    for _ in range(10):
        initialize_database(db_file)

    history = get_audit_history(db_path=db_file)
    assert len(history) == 1
    assert history[0]["action"] == "BASELINE_CREATED"
