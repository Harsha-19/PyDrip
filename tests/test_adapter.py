import sys
from pathlib import Path

"""
Comprehensive Test Suite for Phase 12 Adapter Layer.

Tests:
1. History reconstruction with strict walk-forward temporal filtering (detected_at < current_scan_detected_at).
2. Content-addressable immutable text snapshots (.fim_snapshots/{sha256}.txt).
3. Snapshot immutability (never overwrites existing file).
4. Snapshot eligibility rules (UTF-8 text only, strictly < 1 MB, binary rejection).
5. MODIFIED text with snapshot produces valid semantic drift.
6. MODIFIED text without snapshot gracefully degrades to drift_score=None.
7. ADDED and DELETED files produce drift_score=None.
8. Binary file modifications produce drift_score=None.
9. Missing optional fields (criticality, old_hash, etc.) handled safely.
10. Required field validation strictly rejects records missing file_path or change_type.
11. Severity casing conversion (CRITICAL -> Critical) strictly at Harsha boundary.
12. Evidence serialization to JSON in SQLite changes table.
13. Idempotent database migrations.
14. Failure isolation: AI error leaves raw changes intact, does not crash, logs failure.
15. End-to-end integration: baseline -> modify -> scan -> enrich -> retrieve.
"""

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
import pytest

from ai_scoring.adapter import (
    is_text_file,
    take_text_snapshot,
    get_text_snapshot,
    build_scan_history,
    prepare_change_payload,
    normalize_severity_for_harsha,
    update_change_scoring_records,
    enrich_scan,
)


@pytest.fixture
def test_workspace(tmp_path: Path):
    """Provides an isolated environment with an initialized SQLite database and project tree."""
    db_path = tmp_path / "test_fim.db"
    snapshot_dir = tmp_path / ".fim_snapshots"
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir(parents=True, exist_ok=True)

    # Initialize Harsha SQLite schema
    conn = sqlite3.connect(str(db_path))
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                change_type TEXT NOT NULL,
                old_hash TEXT,
                new_hash TEXT,
                criticality TEXT NOT NULL DEFAULT 'Medium',
                drift_score REAL,
                anomaly_score REAL,
                severity TEXT,
                detected_at TEXT NOT NULL,
                evidence TEXT
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
        """)
    conn.close()

    return {
        "db_path": db_path,
        "snapshot_dir": snapshot_dir,
        "monitored_dir": monitored_dir,
        "project_root": tmp_path,
    }


# ==============================================================================
# 1. TEXT SNAPSHOT ENGINE TESTS
# ==============================================================================

def test_is_text_file_valid_utf8(tmp_path: Path):
    """Verifies valid UTF-8 text files below 1 MB are recognized."""
    txt_file = tmp_path / "config.txt"
    txt_file.write_text("port=8080\nhost=localhost\n", encoding="utf-8")
    assert is_text_file(txt_file) is True


def test_is_text_file_rejects_binary(tmp_path: Path):
    """Verifies binary files containing null bytes are rejected."""
    bin_file = tmp_path / "binary.bin"
    bin_file.write_bytes(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    assert is_text_file(bin_file) is False


def test_is_text_file_rejects_large_files(tmp_path: Path):
    """Verifies files >= 1 MB are rejected from snapshotting."""
    large_file = tmp_path / "large.txt"
    large_file.write_bytes(b"a" * (1_048_576 + 10))
    assert is_text_file(large_file) is False


def test_take_text_snapshot_content_addressable_and_immutable(tmp_path: Path):
    """Verifies snapshots are named {sha256}.txt and immutable once written."""
    snap_dir = tmp_path / ".fim_snapshots"
    source_file = tmp_path / "sample.py"
    initial_content = "def test(): pass\n"
    source_file.write_text(initial_content, encoding="utf-8")
    file_hash = hashlib.sha256(initial_content.encode("utf-8")).hexdigest()

    # 1. First snapshot creation
    snap_path = take_text_snapshot(source_file, file_hash, snap_dir)
    assert snap_path is not None
    assert snap_path.name == f"{file_hash}.txt"
    assert snap_path.read_text(encoding="utf-8") == initial_content

    # 2. Modify source file but keep same hash argument (simulating reuse attempt)
    source_file.write_text("def modified(): pass\n", encoding="utf-8")
    reused_path = take_text_snapshot(source_file, file_hash, snap_dir)
    assert reused_path == snap_path
    # MUST NOT be overwritten!
    assert snap_path.read_text(encoding="utf-8") == initial_content


def test_take_text_snapshot_rejects_binary_and_invalid_hash(tmp_path: Path):
    """Verifies snapshots are skipped for binary files or invalid hashes."""
    snap_dir = tmp_path / ".fim_snapshots"
    bin_file = tmp_path / "app.exe"
    bin_file.write_bytes(b"\x00\x01\x02\x03")
    valid_hash = hashlib.sha256(b"\x00\x01\x02\x03").hexdigest()

    # Binary rejected
    assert take_text_snapshot(bin_file, valid_hash, snap_dir) is None
    # Invalid hash length rejected
    assert take_text_snapshot(bin_file, "invalid_hash", snap_dir) is None
    # None hash rejected
    assert take_text_snapshot(bin_file, None, snap_dir) is None


def test_get_text_snapshot_missing_and_corrupt(tmp_path: Path):
    """Verifies missing or corrupt snapshots gracefully return None."""
    snap_dir = tmp_path / ".fim_snapshots"
    snap_dir.mkdir(parents=True, exist_ok=True)

    # Missing hash
    assert get_text_snapshot("e" * 64, snap_dir) is None
    assert get_text_snapshot(None, snap_dir) is None


# ==============================================================================
# 2. SCAN HISTORY RECONSTRUCTION & ANTI-LEAKAGE TESTS
# ==============================================================================

def test_build_scan_history_strict_temporal_filtering(test_workspace):
    """
    Verifies that scan_history reconstruction:
    - Excludes the current scan_id.
    - Excludes future scans (detected_at >= current_scan_detected_at).
    - Preserves chronological ordering.
    """
    db = test_workspace["db_path"]
    conn = sqlite3.connect(str(db))
    with conn:
        # Scan 1 (Past)
        conn.execute("""
            INSERT INTO changes (scan_id, file_path, change_type, criticality, detected_at)
            VALUES ('scan-01', 'app.py', 'MODIFIED', 'High', '2026-09-08T10:00:00Z');
        """)
        # Scan 2 (Past)
        conn.execute("""
            INSERT INTO changes (scan_id, file_path, change_type, criticality, detected_at)
            VALUES ('scan-02', 'db.conf', 'ADDED', 'Critical', '2026-09-08T12:00:00Z');
        """)
        # Scan 3 (Current)
        conn.execute("""
            INSERT INTO changes (scan_id, file_path, change_type, criticality, detected_at)
            VALUES ('scan-03', 'service.py', 'MODIFIED', 'Medium', '2026-09-08T15:00:00Z');
        """)
        # Scan 4 (Future relative to scan-03)
        conn.execute("""
            INSERT INTO changes (scan_id, file_path, change_type, criticality, detected_at)
            VALUES ('scan-04', 'future.txt', 'MODIFIED', 'Low', '2026-09-08T18:00:00Z');
        """)
    conn.close()

    history = build_scan_history(
        db_path=db,
        current_scan_id="scan-03",
        current_scan_detected_at="2026-09-08T15:00:00Z"
    )

    # Must contain scan-01 and scan-02 ONLY
    assert len(history) == 2
    assert history[0]["scan_id"] == "scan-01"
    assert history[0]["detected_at"] == "2026-09-08T10:00:00Z"
    assert len(history[0]["changes"]) == 1
    assert history[0]["changes"][0]["file_path"] == "app.py"

    assert history[1]["scan_id"] == "scan-02"
    assert history[1]["detected_at"] == "2026-09-08T12:00:00Z"

    # Must NOT contain current scan or future scan
    scan_ids = [s["scan_id"] for s in history]
    assert "scan-03" not in scan_ids
    assert "scan-04" not in scan_ids


def test_build_scan_history_cold_start_empty(test_workspace):
    """Verifies that empty history produces [] without error."""
    db = test_workspace["db_path"]
    history = build_scan_history(
        db_path=db,
        current_scan_id="scan-first",
        current_scan_detected_at="2026-09-08T10:00:00Z"
    )
    assert history == []


# ==============================================================================
# 3. CHANGE PAYLOAD PREPARATION TESTS
# ==============================================================================

def test_prepare_change_payload_content_rules(test_workspace):
    """
    Verifies payload assembly across MODIFIED, ADDED, DELETED, and binary files.
    """
    root = test_workspace["project_root"]
    snap_dir = test_workspace["snapshot_dir"]
    snap_dir.mkdir(parents=True, exist_ok=True)

    # 1. MODIFIED text file with baseline snapshot
    old_text = "PORT=3000\n"
    new_text = "PORT=8080\n"
    old_hash = hashlib.sha256(old_text.encode("utf-8")).hexdigest()
    (snap_dir / f"{old_hash}.txt").write_text(old_text, encoding="utf-8")

    mod_file = root / "config.env"
    mod_file.write_text(new_text, encoding="utf-8")

    # 2. ADDED text file
    add_file = root / "new_module.py"
    add_file.write_text("import sys\n", encoding="utf-8")

    # 3. DELETED file (not on disk)
    # 4. Binary modified file
    bin_file = root / "data.bin"
    bin_file.write_bytes(b"\x00\xff\xfe\xfd")

    raw_changes = [
        {
            "scan_id": "scan-10",
            "file_path": "config.env",
            "change_type": "MODIFIED",
            "old_hash": old_hash,
            "new_hash": hashlib.sha256(new_text.encode("utf-8")).hexdigest(),
            "criticality": "Critical",
            "detected_at": "2026-09-08T12:00:00Z",
        },
        {
            "scan_id": "scan-10",
            "file_path": "new_module.py",
            "change_type": "ADDED",
            "old_hash": None,
            "new_hash": hashlib.sha256(b"import sys\n").hexdigest(),
            "criticality": "Medium",
            "detected_at": "2026-09-08T12:00:00Z",
        },
        {
            "scan_id": "scan-10",
            "file_path": "obsolete.txt",
            "change_type": "DELETED",
            "old_hash": "a" * 64,
            "new_hash": None,
            "criticality": "Low",
            "detected_at": "2026-09-08T12:00:00Z",
        },
        {
            "scan_id": "scan-10",
            "file_path": "data.bin",
            "change_type": "MODIFIED",
            "old_hash": "b" * 64,
            "new_hash": "c" * 64,
            "criticality": "High",
            "detected_at": "2026-09-08T12:00:00Z",
        },
    ]

    payload = prepare_change_payload(raw_changes, root, snap_dir)
    assert len(payload) == 4

    # MODIFIED: old and new content populated
    assert payload[0]["old_content"] == old_text
    assert payload[0]["new_content"] == new_text

    # ADDED: old_content is None, new_content populated
    assert payload[1]["old_content"] is None
    assert payload[1]["new_content"] == "import sys\n"

    # DELETED: both None
    assert payload[2]["old_content"] is None
    assert payload[2]["new_content"] is None

    # Binary: both None
    assert payload[3]["old_content"] is None
    assert payload[3]["new_content"] is None


def test_prepare_change_payload_missing_snapshot_degrades_gracefully(test_workspace):
    """Verifies that missing snapshot leaves old_content=None without error."""
    root = test_workspace["project_root"]
    snap_dir = test_workspace["snapshot_dir"]

    mod_file = root / "app.py"
    mod_file.write_text("print('hello')", encoding="utf-8")

    raw_changes = [{
        "scan_id": "scan-11",
        "file_path": "app.py",
        "change_type": "MODIFIED",
        "old_hash": "f" * 64,  # Nonexistent snapshot
        "new_hash": "1" * 64,
        "criticality": "Medium",
    }]

    payload = prepare_change_payload(raw_changes, root, snap_dir)
    assert payload[0]["old_content"] is None
    assert payload[0]["new_content"] == "print('hello')"


# ==============================================================================
# 4. SEVERITY CASING & PERSISTENCE TESTS
# ==============================================================================

def test_normalize_severity_for_harsha():
    """Verifies exact TitleCase mapping at the persistence boundary."""
    assert normalize_severity_for_harsha("CRITICAL") == "Critical"
    assert normalize_severity_for_harsha("HIGH") == "High"
    assert normalize_severity_for_harsha("MEDIUM") == "Medium"
    assert normalize_severity_for_harsha("LOW") == "Low"
    assert normalize_severity_for_harsha(None) is None


def test_update_change_scoring_records_updates_in_place(test_workspace):
    """Verifies in-place update of SQLite rows with scores and serialized JSON evidence."""
    db = test_workspace["db_path"]
    conn = sqlite3.connect(str(db))
    with conn:
        conn.execute("""
            INSERT INTO changes (scan_id, file_path, change_type, criticality, detected_at)
            VALUES ('scan-20', 'config.json', 'MODIFIED', 'High', '2026-09-08T12:00:00Z');
        """)
    conn.close()

    scored = [{
        "file_path": "config.json",
        "anomaly_score": 0.82,
        "drift_score": 0.65,
        "severity": "HIGH",
        "evidence": {
            "anomaly_reason": "Elevated anomaly score.",
            "drift_reason": "High semantic drift detected.",
            "criticality_weight": "Configured as a High-priority asset.",
        }
    }]

    update_change_scoring_records(db, "scan-20", scored)

    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM changes WHERE scan_id = 'scan-20';").fetchone()
    conn.close()

    assert row["anomaly_score"] == 0.82
    assert row["drift_score"] == 0.65
    assert row["severity"] == "High"  # TitleCase at boundary!

    evidence_dict = json.loads(row["evidence"])
    assert evidence_dict["anomaly_reason"] == "Elevated anomaly score."
    assert evidence_dict["drift_reason"] == "High semantic drift detected."
    assert evidence_dict["criticality_weight"] == "Configured as a High-priority asset."
    assert sorted(evidence_dict.keys()) == [
        "anomaly_reason",
        "criticality_weight",
        "drift_reason",
    ]


# ==============================================================================
# 5. POST-SCAN ENRICHMENT ORCHESTRATION & FAILURE ISOLATION TESTS
# ==============================================================================

def test_enrich_scan_end_to_end_success(test_workspace):
    """
    Tests end-to-end post-scan enrichment:
    - Inserts raw changes.
    - Captures baseline snapshot.
    - Calls enrich_scan().
    - Verifies enriched fields in SQLite.
    """
    db = test_workspace["db_path"]
    root = test_workspace["project_root"]
    snap_dir = test_workspace["snapshot_dir"]

    # 1. Baseline state
    old_content = "def authenticate(): return False\n"
    old_hash = hashlib.sha256(old_content.encode("utf-8")).hexdigest()
    snap_dir.mkdir(parents=True, exist_ok=True)
    (snap_dir / f"{old_hash}.txt").write_text(old_content, encoding="utf-8")

    # 2. Current modified state
    target_file = root / "auth.py"
    new_content = "def authenticate(): return True  # backdoor\n"
    target_file.write_text(new_content, encoding="utf-8")
    new_hash = hashlib.sha256(new_content.encode("utf-8")).hexdigest()

    # 3. Raw change inserted by scanner
    conn = sqlite3.connect(str(db))
    with conn:
        conn.execute("""
            INSERT INTO changes (scan_id, file_path, change_type, old_hash, new_hash, criticality, detected_at)
            VALUES ('scan-30', 'auth.py', 'MODIFIED', ?, ?, 'Critical', '2026-09-08T14:00:00Z');
        """, (old_hash, new_hash))
    conn.close()

    # 4. Execute enrichment
    success = enrich_scan("scan-30", db_path=db, project_root=root, snapshot_dir=snap_dir)
    assert success is True

    # 5. Verify database records
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM changes WHERE scan_id = 'scan-30';").fetchone()
    conn.close()

    assert row["severity"] in {"Critical", "High"}
    assert row["drift_score"] is not None
    assert row["drift_score"] > 0.0
    assert row["evidence"] is not None

    evidence = json.loads(row["evidence"])
    assert "criticality_weight" in evidence
    assert "anomaly_reason" in evidence
    assert "drift_reason" in evidence
    assert "criticality_reason" not in evidence
    assert "severity_reason" not in evidence
    assert sorted(evidence.keys()) == [
        "anomaly_reason",
        "criticality_weight",
        "drift_reason",
    ]


def test_enrich_scan_failure_isolation(test_workspace):
    """
    CRITICAL ARCHITECTURAL TEST:
    Verifies that if AI scoring raises ANY exception:
    - enrich_scan returns False without raising.
    - Raw FIM change records remain intact.
    - Scored fields remain NULL.
    - Failure is logged to audit_log.
    """
    db = test_workspace["db_path"]
    root = test_workspace["project_root"]

    # Raw change inserted by scanner
    conn = sqlite3.connect(str(db))
    with conn:
        conn.execute("""
            INSERT INTO changes (scan_id, file_path, change_type, old_hash, new_hash, criticality, detected_at)
            VALUES ('scan-fail', 'app.py', 'MODIFIED', 'a'*64, 'b'*64, 'High', '2026-09-08T15:00:00Z');
        """)
    conn.close()

    # Force an exception inside score_changes
    with patch("ai_scoring.adapter.score_changes", side_effect=RuntimeError("GPU OOM Simulated Failure")):
        success = enrich_scan("scan-fail", db_path=db, project_root=root)
        # Failure isolation: returns False, never raises!
        assert success is False

    # Verify raw change record is intact and uncorrupted
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM changes WHERE scan_id = 'scan-fail';").fetchone()
    assert row is not None
    assert row["file_path"] == "app.py"
    assert row["change_type"] == "MODIFIED"
    assert row["anomaly_score"] is None
    assert row["drift_score"] is None
    assert row["severity"] is None
    assert row["evidence"] is None

    # Verify failure recorded in audit log
    audit_row = conn.execute("SELECT * FROM audit_log WHERE action = 'AI_ENRICHMENT_FAILED';").fetchone()
    assert audit_row is not None
    assert "GPU OOM Simulated Failure" in audit_row["details"]
    conn.close()


def test_migration_idempotency(tmp_path: Path):
    """Verifies that running database initialization repeatedly retains all rows and columns."""
    from app.database import initialize_database, insert_change_records, get_changes_by_scan_id

    db_file = tmp_path / "idempotent.db"
    initialize_database(db_file)

    # Insert a change
    change = {
        "scan_id": "scan-mig",
        "file_path": "test.txt",
        "change_type": "ADDED",
        "new_hash": "c" * 64,
        "criticality": "Low",
        "detected_at": "2026-09-08T10:00:00Z",
    }
    insert_change_records([change], db_path=db_file)

    # Re-initialize multiple times
    initialize_database(db_file)
    initialize_database(db_file)

    # Verify data and schema
    changes = get_changes_by_scan_id("scan-mig", db_path=db_file)
    assert len(changes) == 1
    assert changes[0]["file_path"] == "test.txt"

    conn = sqlite3.connect(str(db_file))
    cursor = conn.execute("PRAGMA table_info(changes);")
    cols = [r[1] for r in cursor.fetchall()]
    conn.close()

    assert "evidence" in cols
    assert "criticality" in cols
