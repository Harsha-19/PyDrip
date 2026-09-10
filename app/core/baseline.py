"""Baseline creation engine for FIM+.

Walks configured monitored paths, computes SHA-256 digests, extracts filesystem metadata,
determines criticality, and persists snapshot records in SQLite.
"""

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import uuid

from app.config import DEFAULT_CONFIG_PATH, load_config
from app.core.hasher import calculate_sha256
from app.database import (
    DEFAULT_DB_PATH,
    append_audit_log,
    get_baselines_by_scan_id,
    insert_baseline_records,
)
from app.models import AppConfig, BaselineSummaryResponse, Criticality


class BaselineError(Exception):
    """Base exception for baseline creation errors."""
    pass


class MonitoredPathNotFoundError(BaselineError):
    """Raised when a configured monitored path does not exist on disk."""
    pass


def resolve_criticality(
    file_path: Path,
    path_default_criticality: Criticality,
    extension_rules: Dict[str, Criticality]
) -> Criticality:
    """Determine file criticality using extension matching rules with fallback to path default.

    Args:
        file_path: Path to the target file.
        path_default_criticality: Fallback criticality for the monitored directory.
        extension_rules: Mapping of file extensions (e.g. '.env') to Criticality.

    Returns:
        Matched or fallback Criticality enum.
    """
    file_name = file_path.name.lower()

    # 1. Exact full filename match (e.g. '.env')
    if file_name in extension_rules:
        return extension_rules[file_name]

    # 2. Standard suffix match (e.g. '.py', '.conf', '.cfg', '.txt')
    ext = file_path.suffix.lower()
    if ext in extension_rules:
        return extension_rules[ext]

    # 3. Handle dotfile variants like '.env.auth', '.env.local', '.env.production'
    # Check if any rule key appears as prefix/base (e.g. file starts with '.env.')
    for rule_key, crit in extension_rules.items():
        if rule_key.startswith(".") and file_name.startswith(f"{rule_key}."):
            return crit

    return path_default_criticality


def create_baseline(
    config: Optional[AppConfig] = None,
    config_path: Optional[Union[str, Path]] = None,
    db_path: Optional[Path] = None,
    base_dir: Optional[Path] = None
) -> BaselineSummaryResponse:
    """Create a baseline snapshot for all configured monitored files.

    Flow:
    1. Load active YAML configuration if not passed directly.
    2. Generate unique scan_id.
    3. For each configured monitored path, discover all regular files.
    4. Compute SHA-256 hash using streaming hasher.
    5. Extract file metadata: size_bytes, mtime, and resolved criticality.
    6. Persist baseline records to SQLite baselines table.
    7. Record operation in append-only audit_log.
    8. Return summary response.

    Args:
        config: Optional pre-loaded AppConfig.
        config_path: Optional path to YAML config file.
        db_path: Optional SQLite database file path.
        base_dir: Optional base directory to resolve relative monitored paths against.

    Returns:
        BaselineSummaryResponse with scan_id, file count, and timestamp.

    Raises:
        MonitoredPathNotFoundError: If a configured monitored path is missing.
        BaselineError: If database or filesystem operations fail.
    """
    cfg = config or load_config(config_path)
    scan_id = f"base-{uuid.uuid4().hex[:12]}"
    created_at = datetime.now(timezone.utc).isoformat()
    project_root = base_dir or Path(__file__).resolve().parent.parent.parent

    baseline_records: List[Dict[str, Any]] = []

    for monitored in cfg.monitored_paths:
        raw_path = Path(monitored.path)
        # If relative, resolve relative to project_root
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
                stat_info = file_path.stat()
                sha256_hash = calculate_sha256(file_path)
                criticality = resolve_criticality(
                    file_path=file_path,
                    path_default_criticality=monitored.criticality,
                    extension_rules=cfg.criticality_rules.extensions,
                )

                # Store relative path if under project_root, else absolute string representation
                try:
                    stored_path = str(file_path.relative_to(project_root)).replace("\\", "/")
                except ValueError:
                    stored_path = str(file_path).replace("\\", "/")

                # Content-addressable immutable text snapshot for semantic drift analysis
                try:
                    from ai_scoring.adapter import take_text_snapshot
                    snapshot_dir = project_root / ".fim_snapshots"
                    take_text_snapshot(file_path, sha256_hash, snapshot_dir)
                except Exception:
                    pass

                baseline_records.append({
                    "scan_id": scan_id,
                    "file_path": stored_path,
                    "sha256": sha256_hash,
                    "size_bytes": stat_info.st_size,
                    "mtime": stat_info.st_mtime,
                    "criticality": criticality.value,
                    "created_at": created_at,
                })
            except Exception as exc:
                raise BaselineError(f"Error creating baseline for file {file_path}: {exc}") from exc

    # Persist batch of baseline records to SQLite
    insert_baseline_records(baseline_records, db_path=db_path)

    # Record baseline creation in append-only audit_log
    append_audit_log(
        action="BASELINE_CREATED",
        details=f"scan_id={scan_id}, files_indexed={len(baseline_records)}",
        timestamp=created_at,
        db_path=db_path,
    )

    return BaselineSummaryResponse(
        scan_id=scan_id,
        files_indexed=len(baseline_records),
        created_at=created_at,
        status="success",
    )
