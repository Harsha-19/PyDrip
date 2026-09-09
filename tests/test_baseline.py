"""Unit tests for Phase 5 Baseline Creation Engine."""

import hashlib
from pathlib import Path
import pytest

from app.core.baseline import (
    MonitoredPathNotFoundError,
    create_baseline,
    resolve_criticality,
)
from app.database import (
    get_audit_history,
    get_baselines_by_scan_id,
    get_latest_baseline,
    initialize_database,
)
from app.models import (
    AppConfig,
    Criticality,
    CriticalityRulesConfig,
    MonitoredPathConfig,
)


@pytest.fixture
def sample_workspace(tmp_path: Path):
    """Fixture to set up an isolated workspace with a temporary DB and sample files."""
    db_file = tmp_path / "test_fim.db"
    initialize_database(db_file)

    sample_dir = tmp_path / "sample_data"
    sample_dir.mkdir()

    # Seed files with different extensions and contents
    (sample_dir / "app.py").write_text("print('hello world')", encoding="utf-8")
    (sample_dir / "config.conf").write_text("server=localhost", encoding="utf-8")
    (sample_dir / ".env").write_text("SECRET_KEY=12345", encoding="utf-8")
    (sample_dir / "notes.txt").write_text("some notes", encoding="utf-8")
    (sample_dir / "binary.bin").write_bytes(bytes([0, 1, 2, 3, 255]))

    # Subdirectory
    sub_dir = sample_dir / "nested"
    sub_dir.mkdir()
    (sub_dir / "sub_script.py").write_text("# nested python script", encoding="utf-8")

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


def test_resolve_criticality():
    """Verify resolve_criticality matches rules or falls back correctly."""
    rules = {
        ".env": Criticality.Critical,
        ".conf": Criticality.High,
        ".py": Criticality.Medium,
        ".txt": Criticality.Low,
    }

    assert resolve_criticality(Path("test.env"), Criticality.Medium, rules) == Criticality.Critical
    assert resolve_criticality(Path(".env"), Criticality.Medium, rules) == Criticality.Critical
    assert resolve_criticality(Path("app.conf"), Criticality.Medium, rules) == Criticality.High
    assert resolve_criticality(Path("main.py"), Criticality.Low, rules) == Criticality.Medium
    assert resolve_criticality(Path("readme.txt"), Criticality.High, rules) == Criticality.Low
    # Fallback to path default for unknown extensions
    assert resolve_criticality(Path("unknown.xyz"), Criticality.High, rules) == Criticality.High


def test_create_baseline_success(sample_workspace):
    """Verify baseline creation records all files, hashes, sizes, mtime, and criticality in SQLite."""
    ws = sample_workspace
    summary = create_baseline(
        config=ws["config"],
        db_path=ws["db_file"],
        base_dir=ws["tmp_path"],
    )

    assert summary.status == "success"
    assert summary.scan_id.startswith("base-")
    assert summary.files_indexed == 6  # 5 in root + 1 in nested

    # Retrieve from DB
    records = get_baselines_by_scan_id(summary.scan_id, db_path=ws["db_file"])
    assert len(records) == 6

    # Verify SHA-256 calculation matches actual file bytes
    records_by_name = {Path(r["file_path"]).name: r for r in records}
    
    app_py_rec = records_by_name["app.py"]
    expected_app_hash = hashlib.sha256(b"print('hello world')").hexdigest()
    assert app_py_rec["sha256"] == expected_app_hash
    assert app_py_rec["size_bytes"] == len(b"print('hello world')")
    assert app_py_rec["criticality"] == "Medium"
    assert app_py_rec["mtime"] > 0
    assert app_py_rec["created_at"] == summary.created_at

    # Verify .env criticality
    env_rec = records_by_name[".env"]
    assert env_rec["criticality"] == "Critical"
    assert env_rec["sha256"] == hashlib.sha256(b"SECRET_KEY=12345").hexdigest()

    # Verify binary file
    bin_rec = records_by_name["binary.bin"]
    assert bin_rec["sha256"] == hashlib.sha256(bytes([0, 1, 2, 3, 255])).hexdigest()
    assert bin_rec["size_bytes"] == 5

    # Verify audit log was appended
    audit = get_audit_history(db_path=ws["db_file"])
    assert len(audit) == 1
    assert audit[0]["action"] == "BASELINE_CREATED"
    assert f"scan_id={summary.scan_id}" in audit[0]["details"]


def test_repeated_baselines_produce_distinct_scan_ids(sample_workspace):
    """Verify repeated baseline operations generate unique distinguishable scan IDs."""
    ws = sample_workspace
    summary1 = create_baseline(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])
    summary2 = create_baseline(config=ws["config"], db_path=ws["db_file"], base_dir=ws["tmp_path"])

    assert summary1.scan_id != summary2.scan_id

    records1 = get_baselines_by_scan_id(summary1.scan_id, db_path=ws["db_file"])
    records2 = get_baselines_by_scan_id(summary2.scan_id, db_path=ws["db_file"])
    assert len(records1) == 6
    assert len(records2) == 6

    # Latest baseline should be summary2
    latest = get_latest_baseline(db_path=ws["db_file"])
    assert len(latest) == 6
    assert latest[0]["scan_id"] == summary2.scan_id


def test_empty_monitored_directory(tmp_path: Path):
    """Verify baseline creation on an empty folder produces 0 indexed files without error."""
    db_file = tmp_path / "test_fim.db"
    initialize_database(db_file)

    empty_dir = tmp_path / "empty_folder"
    empty_dir.mkdir()

    config = AppConfig(
        monitored_paths=[
            MonitoredPathConfig(path=str(empty_dir), criticality=Criticality.Low)
        ],
        criticality_rules=CriticalityRulesConfig(extensions={}),
    )

    summary = create_baseline(config=config, db_path=db_file, base_dir=tmp_path)
    assert summary.files_indexed == 0

    records = get_baselines_by_scan_id(summary.scan_id, db_path=db_file)
    assert len(records) == 0


def test_missing_monitored_path_raises_error(tmp_path: Path):
    """Verify missing monitored path raises MonitoredPathNotFoundError."""
    db_file = tmp_path / "test_fim.db"
    initialize_database(db_file)

    non_existent_dir = tmp_path / "does_not_exist_folder"

    config = AppConfig(
        monitored_paths=[
            MonitoredPathConfig(path=str(non_existent_dir), criticality=Criticality.Medium)
        ],
        criticality_rules=CriticalityRulesConfig(extensions={}),
    )

    with pytest.raises(MonitoredPathNotFoundError) as exc_info:
        create_baseline(config=config, db_path=db_file, base_dir=tmp_path)
    assert "does not exist" in str(exc_info.value).lower()
