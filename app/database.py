"""SQLite database access layer for FIM+.

Provides connection management, schema initialization, and CRUD operations
for baselines, changes, audit_log, and scan_reports using standard sqlite3.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from typing import Any, Dict, Generator, List, Optional

# Default database location in pydrip/data/fim.db
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "fim.db"


def get_current_iso_timestamp() -> str:
    """Return the current UTC timestamp formatted as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def get_db_connection(db_path: Optional[Path] = None) -> Generator[sqlite3.Connection, None, None]:
    """Provide a transactional SQLite connection context with Row factory."""
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def initialize_database(db_path: Optional[Path] = None) -> None:
    """Initialize SQLite database schema if tables do not exist.

    Safe to run repeatedly without destroying existing records.
    """
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    with get_db_connection(path) as conn:
        cursor = conn.cursor()

        # 1. baselines table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS baselines (
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
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_baselines_scan_id ON baselines (scan_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_baselines_file_path ON baselines (file_path);")

        # 2. changes table (AI / scoring fields nullable per shared contract)
        cursor.execute(
            """
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
                detected_at TEXT NOT NULL
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_changes_scan_id ON changes (scan_id);")

        # Ensure criticality column exists in changes table if table was created in earlier phase
        cursor.execute("PRAGMA table_info(changes);")
        columns = [col["name"] for col in cursor.fetchall()]
        if "criticality" not in columns:
            cursor.execute("ALTER TABLE changes ADD COLUMN criticality TEXT NOT NULL DEFAULT 'Medium';")

        # 3. audit_log table (append-only)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            """
        )

        # 4. scan_reports table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                report_text TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_reports_scan_id ON scan_reports (scan_id);")


# Ensure default database is initialized when module is imported
initialize_database(DEFAULT_DB_PATH)


# ==============================================================================
# BASELINES ACCESS
# ==============================================================================

def insert_baseline_records(
    records: List[Dict[str, Any]],
    db_path: Optional[Path] = None
) -> None:
    """Insert a batch of baseline records."""
    if not records:
        return

    query = """
        INSERT INTO baselines (
            scan_id, file_path, sha256, size_bytes, mtime, criticality, created_at
        ) VALUES (
            :scan_id, :file_path, :sha256, :size_bytes, :mtime, :criticality, :created_at
        );
    """
    with get_db_connection(db_path) as conn:
        conn.executemany(query, records)


def get_baselines_by_scan_id(
    scan_id: str,
    db_path: Optional[Path] = None
) -> List[Dict[str, Any]]:
    """Retrieve all baseline records for a specific baseline scan_id."""
    query = """
        SELECT id, scan_id, file_path, sha256, size_bytes, mtime, criticality, created_at
        FROM baselines
        WHERE scan_id = ?
        ORDER BY file_path ASC;
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.execute(query, (scan_id,))
        return [dict(row) for row in cursor.fetchall()]


def get_latest_baseline_scan_id(db_path: Optional[Path] = None) -> Optional[str]:
    """Retrieve the scan_id of the most recently created baseline."""
    query = """
        SELECT scan_id
        FROM baselines
        ORDER BY id DESC
        LIMIT 1;
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.execute(query)
        row = cursor.fetchone()
        return row["scan_id"] if row else None


def get_latest_baseline(db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Retrieve all records comprising the latest baseline."""
    latest_scan_id = get_latest_baseline_scan_id(db_path)
    if not latest_scan_id:
        return []
    return get_baselines_by_scan_id(latest_scan_id, db_path)


# ==============================================================================
# CHANGES ACCESS
# ==============================================================================

def insert_change_records(
    changes: List[Dict[str, Any]],
    db_path: Optional[Path] = None
) -> None:
    """Insert a batch of detected change records."""
    if not changes:
        return

    # Ensure criticality default is populated if omitted from dict
    normalized_changes = [
        {
            "criticality": "Medium",
            **change,
        }
        for change in changes
    ]

    query = """
        INSERT INTO changes (
            scan_id, file_path, change_type, old_hash, new_hash, criticality,
            drift_score, anomaly_score, severity, detected_at
        ) VALUES (
            :scan_id, :file_path, :change_type, :old_hash, :new_hash, :criticality,
            :drift_score, :anomaly_score, :severity, :detected_at
        );
    """
    with get_db_connection(db_path) as conn:
        conn.executemany(query, normalized_changes)


def get_changes_by_scan_id(
    scan_id: str,
    db_path: Optional[Path] = None
) -> List[Dict[str, Any]]:
    """Retrieve changes for a given scan_id matching the fields of the shared JSON contract."""
    query = """
        SELECT scan_id, file_path, change_type, old_hash, new_hash, criticality,
               drift_score, anomaly_score, severity, detected_at
        FROM changes
        WHERE scan_id = ?
        ORDER BY id ASC;
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.execute(query, (scan_id,))
        return [dict(row) for row in cursor.fetchall()]


# ==============================================================================
# AUDIT LOG ACCESS (APPEND-ONLY)
# ==============================================================================

def append_audit_log(
    action: str,
    details: str,
    timestamp: Optional[str] = None,
    db_path: Optional[Path] = None
) -> int:
    """Append a new audit log record. NEVER updates or overwrites historical entries.

    Returns:
        The generated integer primary key `id` of the audit record.
    """
    ts = timestamp or get_current_iso_timestamp()
    query = """
        INSERT INTO audit_log (action, details, timestamp)
        VALUES (?, ?, ?);
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.execute(query, (action, details, ts))
        return cursor.lastrowid


def get_audit_history(db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Retrieve the complete audit history ordered chronologically."""
    query = """
        SELECT id, action, details, timestamp
        FROM audit_log
        ORDER BY id ASC;
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.execute(query)
        return [dict(row) for row in cursor.fetchall()]


# ==============================================================================
# SCAN REPORTS ACCESS
# ==============================================================================

def insert_scan_report(
    scan_id: str,
    report_text: str,
    created_at: Optional[str] = None,
    db_path: Optional[Path] = None
) -> int:
    """Insert a scan report record."""
    ts = created_at or get_current_iso_timestamp()
    query = """
        INSERT INTO scan_reports (scan_id, report_text, created_at)
        VALUES (?, ?, ?);
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.execute(query, (scan_id, report_text, ts))
        return cursor.lastrowid


def get_scan_report_by_scan_id(
    scan_id: str,
    db_path: Optional[Path] = None
) -> Optional[Dict[str, Any]]:
    """Retrieve scan report by scan_id."""
    query = """
        SELECT id, scan_id, report_text, created_at
        FROM scan_reports
        WHERE scan_id = ?
        ORDER BY id DESC
        LIMIT 1;
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.execute(query, (scan_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
