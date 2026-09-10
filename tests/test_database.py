"""Unit tests for SQLite database access layer and migration handling (Phase 3 & 6)."""

from pathlib import Path
import sqlite3
import pytest

from app.database import (
    DEFAULT_DB_PATH,
    append_audit_log,
    get_audit_history,
    get_baselines_by_scan_id,
    get_changes_by_scan_id,
    get_latest_baseline,
    get_latest_baseline_scan_id,
    get_scan_report_by_scan_id,
    initialize_database,
    insert_baseline_records,
    insert_change_records,
    insert_scan_report,
)
from app.models import ChangeType, Criticality


@pytest.fixture
def test_db(tmp_path: Path) -> Path:
    """Fixture to provide an isolated temporary SQLite database for each test."""
    db_file = tmp_path / "test_fim.db"
    initialize_database(db_file)
    return db_file


def test_default_db_path_location():
    """Verify default database location is d:/hackathon/pydrip/data/fim.db."""
    expected_suffix = Path("pydrip") / "data" / "fim.db"
    assert str(DEFAULT_DB_PATH).endswith(str(expected_suffix))


def test_initialize_database_idempotent(test_db: Path):
    """Verify database initialization creates tables and is safe to call repeatedly."""
    # Seed one audit log
    row_id = append_audit_log("TEST_ACTION", "Details 1", db_path=test_db)
    assert row_id == 1

    # Re-run initialize_database
    initialize_database(test_db)

    # Verify existing data was NOT destroyed
    history = get_audit_history(test_db)
    assert len(history) == 1
    assert history[0]["action"] == "TEST_ACTION"


def test_baseline_records_insert_and_retrieve(test_db: Path):
    """Verify baseline insertion, scan_id retrieval, and latest baseline detection."""
    records_scan1 = [
        {
            "scan_id": "base-001",
            "file_path": "./sample_data/app.py",
            "sha256": "a" * 64,
            "size_bytes": 1024,
            "mtime": 1725880000.0,
            "criticality": Criticality.Medium.value,
            "created_at": "2026-09-09T15:00:00Z",
        },
        {
            "scan_id": "base-001",
            "file_path": "./sample_data/.env",
            "sha256": "b" * 64,
            "size_bytes": 128,
            "mtime": 1725880000.0,
            "criticality": Criticality.Critical.value,
            "created_at": "2026-09-09T15:00:00Z",
        },
    ]

    insert_baseline_records(records_scan1, db_path=test_db)

    res1 = get_baselines_by_scan_id("base-001", db_path=test_db)
    assert len(res1) == 2
    assert res1[0]["file_path"] == "./sample_data/.env"
    assert res1[0]["criticality"] == "Critical"
    assert res1[1]["file_path"] == "./sample_data/app.py"

    assert get_latest_baseline_scan_id(db_path=test_db) == "base-001"
    latest_rows = get_latest_baseline(db_path=test_db)
    assert len(latest_rows) == 2

    # Insert a second baseline scan
    records_scan2 = [
        {
            "scan_id": "base-002",
            "file_path": "./sample_data/app.py",
            "sha256": "c" * 64,
            "size_bytes": 1050,
            "mtime": 1725881000.0,
            "criticality": Criticality.Medium.value,
            "created_at": "2026-09-09T15:10:00Z",
        }
    ]
    insert_baseline_records(records_scan2, db_path=test_db)

    assert get_latest_baseline_scan_id(db_path=test_db) == "base-002"
    latest_rows2 = get_latest_baseline(db_path=test_db)
    assert len(latest_rows2) == 1
    assert latest_rows2[0]["scan_id"] == "base-002"


def test_changes_insert_and_retrieve_with_null_ai_scoring(test_db: Path):
    """Verify change records insertion with null AI/scoring fields and criticality."""
    changes = [
        {
            "scan_id": "scan-100",
            "file_path": "./sample_data/app.py",
            "change_type": ChangeType.MODIFIED.value,
            "old_hash": "a" * 64,
            "new_hash": "c" * 64,
            "criticality": "Medium",
            "drift_score": None,
            "anomaly_score": None,
            "severity": None,
            "detected_at": "2026-09-09T15:15:00Z",
        },
        {
            "scan_id": "scan-100",
            "file_path": "./sample_data/new.txt",
            "change_type": ChangeType.ADDED.value,
            "old_hash": None,
            "new_hash": "d" * 64,
            "criticality": "Low",
            "drift_score": None,
            "anomaly_score": None,
            "severity": None,
            "detected_at": "2026-09-09T15:15:00Z",
        },
    ]

    insert_change_records(changes, db_path=test_db)

    fetched = get_changes_by_scan_id("scan-100", db_path=test_db)
    assert len(fetched) == 2
    assert fetched[0]["file_path"] == "./sample_data/app.py"
    assert fetched[0]["change_type"] == "MODIFIED"
    assert fetched[0]["old_hash"] == "a" * 64
    assert fetched[0]["new_hash"] == "c" * 64
    assert fetched[0]["criticality"] == "Medium"
    assert fetched[0]["drift_score"] is None
    assert fetched[0]["anomaly_score"] is None
    assert fetched[0]["severity"] is None

    assert fetched[1]["change_type"] == "ADDED"
    assert fetched[1]["old_hash"] is None
    assert fetched[1]["criticality"] == "Low"


def test_append_only_audit_log(test_db: Path):
    """Verify audit log is strictly append-only and returned chronologically."""
    id1 = append_audit_log("BASELINE_CREATED", "scan_id=base-001, files=10", timestamp="2026-09-09T15:00:00Z", db_path=test_db)
    id2 = append_audit_log("CONFIG_UPDATED", "monitored_paths updated", timestamp="2026-09-09T15:05:00Z", db_path=test_db)
    id3 = append_audit_log("SCAN_COMPLETED", "scan_id=scan-001, changes=2", timestamp="2026-09-09T15:10:00Z", db_path=test_db)

    assert id1 == 1
    assert id2 == 2
    assert id3 == 3

    history = get_audit_history(db_path=test_db)
    assert len(history) == 3
    assert [h["action"] for h in history] == ["BASELINE_CREATED", "CONFIG_UPDATED", "SCAN_COMPLETED"]
    assert history[0]["timestamp"] == "2026-09-09T15:00:00Z"
    assert history[2]["timestamp"] == "2026-09-09T15:10:00Z"


def test_scan_reports_insert_and_retrieve(test_db: Path):
    """Verify storing and retrieving scan report texts."""
    rep_id = insert_scan_report("scan-999", "Security report text summary", db_path=test_db)
    assert rep_id == 1

    report = get_scan_report_by_scan_id("scan-999", db_path=test_db)
    assert report is not None
    assert report["scan_id"] == "scan-999"
    assert report["report_text"] == "Security report text summary"


def test_phase3_to_phase6_schema_migration(tmp_path: Path):
    """Verify an existing Phase 3 database without 'criticality' column in changes table is safely migrated.

    1. Create a Phase-3-style schema without criticality in changes.
    2. Insert pre-existing baseline, audit, and change records.
    3. Run initialize_database (migration).
    4. Verify 'criticality' column is added with default value.
    5. Verify existing data is preserved.
    6. Verify new inserts with explicit criticality succeed and are retrievable.
    """
    db_file = tmp_path / "legacy_fim.db"

    # 1. Manually create Phase 3 legacy schema
    conn = sqlite3.connect(str(db_file))
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            file_path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            mtime REAL NOT NULL,
            criticality TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    cursor.execute(
        """
        CREATE TABLE changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            file_path TEXT NOT NULL,
            change_type TEXT NOT NULL,
            old_hash TEXT,
            new_hash TEXT,
            drift_score REAL,
            anomaly_score REAL,
            severity TEXT,
            detected_at TEXT NOT NULL
        );
        """
    )
    cursor.execute(
        """
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            timestamp TEXT NOT NULL
        );
        """
    )
    cursor.execute(
        """
        CREATE TABLE scan_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            report_text TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )

    # 2. Insert representative legacy change and audit data
    cursor.execute(
        """
        INSERT INTO changes (scan_id, file_path, change_type, old_hash, new_hash, drift_score, anomaly_score, severity, detected_at)
        VALUES ('legacy-scan-1', 'app.py', 'MODIFIED', 'hash1', 'hash2', NULL, NULL, NULL, '2026-09-09T14:00:00Z');
        """
    )
    cursor.execute(
        """
        INSERT INTO audit_log (action, details, timestamp)
        VALUES ('LEGACY_EVENT', 'Prior to migration', '2026-09-09T14:00:00Z');
        """
    )
    conn.commit()
    conn.close()

    # 3. Run initialize_database on legacy database
    initialize_database(db_file)

    # 4. Verify criticality column exists in changes table
    conn = sqlite3.connect(str(db_file))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(changes);")
    cols = [col["name"] for col in cursor.fetchall()]
    assert "criticality" in cols

    # 5. Verify pre-existing data was preserved and received the default 'Medium' criticality
    cursor.execute("SELECT * FROM changes WHERE scan_id = 'legacy-scan-1';")
    legacy_row = dict(cursor.fetchone())
    assert legacy_row["file_path"] == "app.py"
    assert legacy_row["change_type"] == "MODIFIED"
    assert legacy_row["criticality"] == "Medium"

    cursor.execute("SELECT * FROM audit_log WHERE action = 'LEGACY_EVENT';")
    assert cursor.fetchone() is not None
    conn.close()

    # 6. Verify subsequent insert_change_records with explicit criticality works
    new_changes = [
        {
            "scan_id": "new-scan-2",
            "file_path": ".env",
            "change_type": "MODIFIED",
            "old_hash": "h1",
            "new_hash": "h2",
            "criticality": "Critical",
            "drift_score": None,
            "anomaly_score": None,
            "severity": None,
            "detected_at": "2026-09-09T16:00:00Z",
        }
    ]
    insert_change_records(new_changes, db_path=db_file)

    retrieved = get_changes_by_scan_id("new-scan-2", db_path=db_file)
    assert len(retrieved) == 1
    assert retrieved[0]["file_path"] == ".env"
    assert retrieved[0]["criticality"] == "Critical"
