"""Scan and diff engine for FIM+.

Compares the latest stored baseline against current filesystem state,
classifies changes (ADDED, DELETED, MODIFIED), and persists change records in SQLite.
"""

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import uuid

from app.config import load_config
from app.core.baseline import MonitoredPathNotFoundError, resolve_criticality
from app.core.hasher import calculate_sha256
from app.database import (
    append_audit_log,
    get_changes_by_scan_id,
    get_latest_baseline,
    get_latest_baseline_scan_id,
    insert_change_records,
)
from app.models import AppConfig, ChangeType, Criticality, ScanSummaryResponse


class ScanError(Exception):
    """Base exception for scan and diff operations."""
    pass


class NoBaselineFoundError(ScanError):
    """Raised when scan is triggered but no baseline snapshot exists in the database."""
    pass


def run_scan(
    config: Optional[AppConfig] = None,
    config_path: Optional[Union[str, Path]] = None,
    db_path: Optional[Path] = None,
    base_dir: Optional[Path] = None,
    baseline_scan_id: Optional[str] = None,
    auto_enrich: Optional[bool] = None,
) -> ScanSummaryResponse:
    """Execute filesystem scan and diff against the latest baseline.

    Flow:
    1. Retrieve latest baseline from database (or specific baseline_scan_id if provided).
    2. Raise NoBaselineFoundError if no baseline exists.
    3. Load active configuration.
    4. Discover current filesystem files and compute current SHA-256 digests.
    5. Perform set diffing on normalized file paths:
       - ADDED: in current files, not in baseline (old_hash=None, new_hash=current_hash).
       - DELETED: in baseline, not in current files (old_hash=base_hash, new_hash=None).
       - MODIFIED: in both, but base_hash != current_hash (old_hash=base_hash, new_hash=current_hash).
       - UNCHANGED: in both, base_hash == current_hash (no change record inserted).
    6. Persist change records into SQLite changes table with null AI/scoring fields.
    7. Append audit record to audit_log.
    8. Return ScanSummaryResponse.

    Args:
        config: Optional pre-loaded AppConfig.
        config_path: Optional path to YAML config file.
        db_path: Optional SQLite database file path.
        base_dir: Optional base directory to resolve relative paths against.
        baseline_scan_id: Optional specific baseline scan_id to compare against.

    Returns:
        ScanSummaryResponse with change counts and metadata.

    Raises:
        NoBaselineFoundError: If no baseline exists in the database.
        MonitoredPathNotFoundError: If a configured monitored path does not exist.
        ScanError: If filesystem or database operations fail.
    """
    # 1. Retrieve latest baseline records
    target_baseline_id = baseline_scan_id or get_latest_baseline_scan_id(db_path=db_path)
    if not target_baseline_id:
        raise NoBaselineFoundError(
            "No baseline found in database. You must create a baseline with /baseline before running a scan."
        )

    baseline_records = get_latest_baseline(db_path=db_path) if not baseline_scan_id else []
    if baseline_scan_id:
        from app.database import get_baselines_by_scan_id
        baseline_records = get_baselines_by_scan_id(baseline_scan_id, db_path=db_path)

    if not baseline_records:
        raise NoBaselineFoundError(
            f"No baseline records found for scan_id '{target_baseline_id}'."
        )

    # Build baseline dictionary keyed by normalized relative file path
    baseline_map: Dict[str, Dict[str, Any]] = {
        rec["file_path"]: rec for rec in baseline_records
    }

    # 2. Load configuration and discover current filesystem state
    cfg = config or load_config(config_path)
    project_root = base_dir or Path(__file__).resolve().parent.parent.parent
    scan_id = f"scan-{uuid.uuid4().hex[:12]}"
    detected_at = datetime.now(timezone.utc).isoformat()

    current_files_map: Dict[str, Dict[str, Any]] = {}

    for monitored in cfg.monitored_paths:
        raw_path = Path(monitored.path)
        target_dir = raw_path if raw_path.is_absolute() else (project_root / raw_path).resolve()

        if not target_dir.exists():
            raise MonitoredPathNotFoundError(
                f"Configured monitored path does not exist: {monitored.path} (resolved: {target_dir})"
            )

        if target_dir.is_file():
            discovered_files = [target_dir]
        else:
            discovered_files = [
                Path(root) / f
                for root, _, files in os.walk(target_dir)
                for f in files
            ]

        for file_path in discovered_files:
            try:
                sha256_hash = calculate_sha256(file_path)
                criticality = resolve_criticality(
                    file_path=file_path,
                    path_default_criticality=monitored.criticality,
                    extension_rules=cfg.criticality_rules.extensions,
                )

                try:
                    stored_path = str(file_path.relative_to(project_root)).replace("\\", "/")
                except ValueError:
                    stored_path = str(file_path).replace("\\", "/")

                current_files_map[stored_path] = {
                    "file_path": stored_path,
                    "sha256": sha256_hash,
                    "criticality": criticality.value,
                }
            except Exception as exc:
                raise ScanError(f"Error scanning file {file_path}: {exc}") from exc

    # 3. Perform Set Diffing
    baseline_paths = set(baseline_map.keys())
    current_paths = set(current_files_map.keys())

    added_paths = current_paths - baseline_paths
    deleted_paths = baseline_paths - current_paths
    common_paths = current_paths & baseline_paths

    change_records: List[Dict[str, Any]] = []
    added_count = 0
    deleted_count = 0
    modified_count = 0

    # Process ADDED files
    for path_str in sorted(added_paths):
        curr = current_files_map[path_str]
        change_records.append({
            "scan_id": scan_id,
            "file_path": path_str,
            "change_type": ChangeType.ADDED.value,
            "old_hash": None,
            "new_hash": curr["sha256"],
            "criticality": curr["criticality"],
            "drift_score": None,
            "anomaly_score": None,
            "severity": None,
            "detected_at": detected_at,
        })
        added_count += 1

    # Process DELETED files (criticality retained from baseline record)
    for path_str in sorted(deleted_paths):
        base = baseline_map[path_str]
        change_records.append({
            "scan_id": scan_id,
            "file_path": path_str,
            "change_type": ChangeType.DELETED.value,
            "old_hash": base["sha256"],
            "new_hash": None,
            "criticality": base["criticality"],
            "drift_score": None,
            "anomaly_score": None,
            "severity": None,
            "detected_at": detected_at,
        })
        deleted_count += 1

    # Process MODIFIED or UNCHANGED files
    for path_str in sorted(common_paths):
        base = baseline_map[path_str]
        curr = current_files_map[path_str]

        if base["sha256"] != curr["sha256"]:
            change_records.append({
                "scan_id": scan_id,
                "file_path": path_str,
                "change_type": ChangeType.MODIFIED.value,
                "old_hash": base["sha256"],
                "new_hash": curr["sha256"],
                "criticality": curr["criticality"],
                "drift_score": None,
                "anomaly_score": None,
                "severity": None,
                "detected_at": detected_at,
            })
            modified_count += 1
        # If hashes match, file is UNCHANGED -> no change record created

    total_changes = added_count + deleted_count + modified_count

    # 4. Persist changes to database if any were detected
    if change_records:
        insert_change_records(change_records, db_path=db_path)
        # Post-scan AI enrichment (strict failure isolation)
        should_enrich = auto_enrich if auto_enrich is not None else (os.environ.get("FIM_AUTO_ENRICH", "0") == "1")
        if should_enrich:
            try:
                from ai_scoring.adapter import enrich_scan
                resolved_db = Path(db_path) if db_path else (project_root / "data" / "fim.db")
                snapshot_dir = project_root / ".fim_snapshots"
                enrich_scan(
                    scan_id=scan_id,
                    db_path=resolved_db,
                    project_root=project_root,
                    snapshot_dir=snapshot_dir
                )
            except Exception:
                pass

    # 5. Append audit log entry
    append_audit_log(
        action="SCAN_COMPLETED",
        details=f"scan_id={scan_id}, baseline_scan_id={target_baseline_id}, changes={total_changes} (added={added_count}, deleted={deleted_count}, modified={modified_count})",
        timestamp=detected_at,
        db_path=db_path,
    )

    return ScanSummaryResponse(
        scan_id=scan_id,
        baseline_scan_id=target_baseline_id,
        added_count=added_count,
        deleted_count=deleted_count,
        modified_count=modified_count,
        total_changes=total_changes,
        scanned_at=detected_at,
    )
