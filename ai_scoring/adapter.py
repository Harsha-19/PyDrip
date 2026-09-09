"""
Integration Adapter Layer for Phase 12.

Bridges Harsha's Core FIM Engine (filesystem scanning, SHA-256 baselining, SQLite persistence)
and Rohith's locked AI/ML scoring pipeline:
    score_changes(change_list, scan_history) -> list[dict]

Design Invariants:
1. SHA-256 FIM detection is authoritative; AI/ML is an enrichment layer.
2. AI failure must never break core FIM scans (failure isolation).
3. Text snapshots are content-addressable (.fim_snapshots/{sha256}.txt) and strictly immutable.
4. Scan history reconstruction strictly prevents future-data leakage (detected_at < current_scan_detected_at).
5. Severity casing is normalized (CRITICAL -> Critical) strictly at the Harsha persistence boundary.
6. Phases 1-11 scoring modules remain untouched and locked.
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ai_scoring.scorer import score_changes

logger = logging.getLogger("pydrip.adapter")

# Default snapshot directory relative to project root
DEFAULT_SNAPSHOT_DIR_NAME = ".fim_snapshots"
MAX_SNAPSHOT_FILE_SIZE = 1_048_576  # 1 MB


# ==============================================================================
# 1. IMMUTABLE TEXT SNAPSHOT ENGINE
# ==============================================================================

def is_text_file(file_path: Path, max_bytes: int = MAX_SNAPSHOT_FILE_SIZE) -> bool:
    """
    Determines whether a file is an eligible UTF-8 text file and strictly < max_bytes.
    
    Checks:
    - File exists and is a regular file.
    - Size is strictly less than max_bytes (< 1 MB).
    - First 8 KB does not contain null byte b"\\x00" and decodes cleanly as UTF-8.
    """
    try:
        if not file_path.is_file():
            return False

        stat_info = file_path.stat()
        if stat_info.st_size >= max_bytes:
            return False

        with file_path.open("rb") as f:
            chunk = f.read(8192)

        # Null bytes indicate binary formats
        if b"\x00" in chunk:
            return False

        # Must decode cleanly as UTF-8
        chunk.decode("utf-8")
        return True
    except Exception:
        return False


def take_text_snapshot(
    file_path: Path,
    sha256_hash: str,
    snapshot_dir: Path,
    max_bytes: int = MAX_SNAPSHOT_FILE_SIZE
) -> Optional[Path]:
    """
    Creates an immutable content-addressable text snapshot of a baseline file.
    
    Saved as: {snapshot_dir}/{sha256_hash.lower()}.txt
    
    Rules:
    - If snapshot already exists, it is NEVER overwritten (immutability).
    - Only text files strictly < max_bytes are snapshotted.
    - Binary files are rejected.
    - Returns Path to snapshot file if created or reused, else None.
    """
    if not sha256_hash or not isinstance(sha256_hash, str):
        return None

    clean_hash = sha256_hash.strip().lower()
    if len(clean_hash) != 64:
        return None

    snapshot_dir.mkdir(parents=True, exist_ok=True)
    snapshot_path = snapshot_dir / f"{clean_hash}.txt"

    # Immutability: reuse existing snapshot without overwriting
    if snapshot_path.exists():
        return snapshot_path

    if not is_text_file(file_path, max_bytes=max_bytes):
        return None

    try:
        content = file_path.read_text(encoding="utf-8", errors="strict")
        snapshot_path.write_text(content, encoding="utf-8")
        return snapshot_path
    except Exception as exc:
        logger.warning("Failed to take text snapshot for %s: %s", file_path, exc)
        return None


def get_text_snapshot(
    sha256_hash: Optional[str],
    snapshot_dir: Path
) -> Optional[str]:
    """
    Retrieves stored text content for a given SHA-256 digest.
    
    Returns:
    - Text string if snapshot exists and is readable.
    - None if hash is null, missing, or snapshot file is corrupted.
    """
    if not sha256_hash or not isinstance(sha256_hash, str):
        return None

    clean_hash = sha256_hash.strip().lower()
    snapshot_path = snapshot_dir / f"{clean_hash}.txt"

    if not snapshot_path.exists() or not snapshot_path.is_file():
        return None

    try:
        return snapshot_path.read_text(encoding="utf-8")
    except Exception as exc:
        logger.warning("Failed to read snapshot %s: %s", snapshot_path, exc)
        return None


# ==============================================================================
# 2. SCAN HISTORY RECONSTRUCTION (STRICT WALK-FORWARD / NO-LEAKAGE)
# ==============================================================================

def build_scan_history(
    db_path: Path,
    current_scan_id: str,
    current_scan_detected_at: str
) -> List[Dict[str, Any]]:
    """
    Reconstructs scan_history for Rohith's Isolation Forest anomaly detector.
    
    Guarantees:
    - Strictly excludes current_scan_id.
    - Strictly excludes future scans (detected_at < current_scan_detected_at).
    - Orders scans chronologically (detected_at ASC).
    - Preserves contract shape: [{"scan_id": ..., "detected_at": ..., "changes": [...]}, ...]
    """
    query = """
        SELECT scan_id, detected_at, file_path, change_type, criticality
        FROM changes
        WHERE scan_id != ?
          AND detected_at < ?
        ORDER BY detected_at ASC, id ASC;
    """

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.execute(query, (current_scan_id, current_scan_detected_at))
        rows = cursor.fetchall()
    finally:
        conn.close()

    # Group changes by scan_id preserving temporal order
    scans_map: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        s_id = row["scan_id"]
        if s_id not in scans_map:
            scans_map[s_id] = {
                "scan_id": s_id,
                "detected_at": row["detected_at"],
                "changes": []
            }
        scans_map[s_id]["changes"].append({
            "file_path": row["file_path"],
            "change_type": row["change_type"],
            "criticality": row["criticality"]
        })

    return list(scans_map.values())


# ==============================================================================
# 3. CHANGE PAYLOAD PREPARATION (OLD_CONTENT & NEW_CONTENT)
# ==============================================================================

def prepare_change_payload(
    raw_changes: List[Dict[str, Any]],
    project_root: Path,
    snapshot_dir: Path
) -> List[Dict[str, Any]]:
    """
    Prepares raw Harsha change records into the contract expected by score_changes().
    
    Content Extraction Rules:
    - MODIFIED (Text): old_content loaded from snapshot; new_content read from disk.
    - ADDED: old_content=None; new_content read from disk if text.
    - DELETED: old_content=None; new_content=None.
    - Binary / Non-Text: old_content=None; new_content=None.
    """
    payload: List[Dict[str, Any]] = []

    for change in raw_changes:
        file_path_str = change["file_path"]
        change_type = change["change_type"]
        criticality = change.get("criticality")
        detected_at = change.get("detected_at")
        old_hash = change.get("old_hash")
        new_hash = change.get("new_hash")

        # Resolve path on disk
        target_path = Path(file_path_str)
        if not target_path.is_absolute():
            target_path = (project_root / target_path).resolve()

        old_content: Optional[str] = None
        new_content: Optional[str] = None

        if change_type == "MODIFIED":
            # Attempt to retrieve baseline snapshot
            old_content = get_text_snapshot(old_hash, snapshot_dir)
            # Read current content if valid text file
            if target_path.exists() and is_text_file(target_path):
                try:
                    new_content = target_path.read_text(encoding="utf-8")
                except Exception:
                    new_content = None

        elif change_type == "ADDED":
            old_content = None
            if target_path.exists() and is_text_file(target_path):
                try:
                    new_content = target_path.read_text(encoding="utf-8")
                except Exception:
                    new_content = None

        elif change_type == "DELETED":
            old_content = None
            new_content = None

        # Assemble contract record
        record: Dict[str, Any] = {
            "file_path": file_path_str,
            "change_type": change_type,
            "criticality": criticality,
            "detected_at": detected_at,
            "old_hash": old_hash,
            "new_hash": new_hash,
            "old_content": old_content,
            "new_content": new_content,
        }
        # Retain scan_id if present in original record
        if "scan_id" in change:
            record["scan_id"] = change["scan_id"]

        payload.append(record)

    return payload


# ==============================================================================
# 4. SEVERITY CASING & PERSISTENCE
# ==============================================================================

def normalize_severity_for_harsha(severity: Optional[str]) -> Optional[str]:
    """
    Normalizes severity casing strictly at the Harsha boundary.
    
    CRITICAL -> Critical
    HIGH     -> High
    MEDIUM   -> Medium
    LOW      -> Low
    """
    if not severity or not isinstance(severity, str):
        return None
    return severity.capitalize()


def update_change_scoring_records(
    db_path: Path,
    scan_id: str,
    scored_changes: List[Dict[str, Any]]
) -> None:
    """
    Persists AI-enriched scores and evidence into Harsha's SQLite changes table in-place.
    
    Fields updated:
    - anomaly_score: REAL
    - drift_score: REAL
    - severity: TEXT (TitleCase)
    - evidence: TEXT (serialized JSON string)
    """
    if not scored_changes:
        return

    update_query = """
        UPDATE changes
        SET anomaly_score = ?,
            drift_score = ?,
            severity = ?,
            evidence = ?
        WHERE scan_id = ? AND file_path = ?;
    """

    params = []
    for ch in scored_changes:
        anomaly_score = ch.get("anomaly_score")
        drift_score = ch.get("drift_score")
        severity_title = normalize_severity_for_harsha(ch.get("severity"))

        evidence_val = ch.get("evidence")
        evidence_json = json.dumps(evidence_val) if evidence_val is not None else None

        params.append((
            anomaly_score,
            drift_score,
            severity_title,
            evidence_json,
            scan_id,
            ch["file_path"]
        ))

    conn = sqlite3.connect(str(db_path))
    try:
        with conn:
            conn.executemany(update_query, params)
    finally:
        conn.close()


# ==============================================================================
# 5. POST-SCAN ENRICHMENT ORCHESTRATOR (FAILURE ISOLATION)
# ==============================================================================

def enrich_scan(
    scan_id: str,
    db_path: Path,
    project_root: Optional[Path] = None,
    snapshot_dir: Optional[Path] = None
) -> bool:
    """
    Orchestrates post-scan AI enrichment for a given scan_id.
    
    Failure Isolation Invariant:
    - Wrapped completely in try/except.
    - If ANY failure occurs (model exception, memory limit, I/O error):
      - Raw changes remain persisted in SQLite.
      - Error is logged and optionally recorded in audit_log.
      - Scored fields remain NULL.
      - Returns False without raising, so core FIM scan endpoint never fails.
    """
    try:
        resolved_root = project_root or Path.cwd()
        resolved_snapshot_dir = snapshot_dir or (resolved_root / DEFAULT_SNAPSHOT_DIR_NAME)

        # 1. Fetch raw changes for current scan from database
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute(
                "SELECT scan_id, file_path, change_type, old_hash, new_hash, criticality, detected_at "
                "FROM changes WHERE scan_id = ? ORDER BY id ASC;",
                (scan_id,)
            )
            raw_rows = [dict(r) for r in cursor.fetchall()]
        finally:
            conn.close()

        if not raw_rows:
            logger.info("No change records found to score for scan_id=%s", scan_id)
            return True

        current_detected_at = raw_rows[0].get("detected_at") or datetime.now(timezone.utc).isoformat()

        # 2. Reconstruct historical scan baseline (walk-forward, no-leakage)
        scan_history = build_scan_history(
            db_path=db_path,
            current_scan_id=scan_id,
            current_scan_detected_at=current_detected_at
        )

        # 3. Prepare payload with text content from snapshots and disk
        change_payload = prepare_change_payload(
            raw_changes=raw_rows,
            project_root=resolved_root,
            snapshot_dir=resolved_snapshot_dir
        )

        # 4. Execute Rohith's locked scoring pipeline
        scored_results = score_changes(
            change_list=change_payload,
            scan_history=scan_history
        )

        # 5. Persist enriched scores and evidence back into SQLite
        update_change_scoring_records(
            db_path=db_path,
            scan_id=scan_id,
            scored_changes=scored_results
        )

        logger.info("Successfully enriched scan_id=%s with %d scored changes", scan_id, len(scored_results))
        return True

    except Exception as exc:
        logger.exception("AI enrichment failed for scan_id=%s: %s", scan_id, exc)
        # Attempt to record failure in audit_log without throwing
        try:
            conn = sqlite3.connect(str(db_path))
            with conn:
                conn.execute(
                    "INSERT INTO audit_log (action, details, timestamp) VALUES (?, ?, ?);",
                    (
                        "AI_ENRICHMENT_FAILED",
                        f"scan_id={scan_id}, error={str(exc)}",
                        datetime.now(timezone.utc).isoformat()
                    )
                )
            conn.close()
        except Exception:
            pass

        # Failure isolation: returns False, never raises
        return False
