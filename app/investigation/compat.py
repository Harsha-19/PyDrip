"""
Compatibility helper bridging Paritosh unit tests to Harsha's authoritative SHA-256 baseline & hasher.
Provides FileHasher, FileIdentity, IntegrityResult, and IntegrityEngine without touching Harsha's core files.
"""

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Optional

from app.core.hasher import calculate_sha256


@dataclass
class FileIdentity:
    name: str
    path: str
    type: str
    size: int
    sha256: str


@dataclass
class IntegrityResult:
    file: FileIdentity
    baseline_hash: Optional[str]
    current_hash: Optional[str]
    integrity_status: str
    error_message: Optional[str] = None


class FileHasher:
    """Helper class providing hash_file dict interface for Paritosh tests."""
    def hash_file(self, file_path: str) -> dict:
        p = Path(file_path)
        if not p.exists():
            return {"success": False, "sha256": None, "error": f"File {file_path} does not exist"}
        try:
            h = calculate_sha256(p)
            return {"success": True, "sha256": h, "error": None}
        except Exception as exc:
            return {"success": False, "sha256": None, "error": str(exc)}


class IntegrityEngine:
    """
    Paritosh test adapter implementing create_baseline and check_integrity
    using Harsha's SHA-256 calculation.
    """
    def __init__(self, store=None):
        self.store = store or {}

    def _get_file_identity(self, file_path: str, file_hash: str) -> FileIdentity:
        name = os.path.basename(file_path)
        ext = os.path.splitext(name)[1] or "unknown"
        try:
            size = os.path.getsize(file_path)
        except OSError:
            size = 0
        return FileIdentity(
            name=name,
            path=file_path,
            type=ext,
            size=size,
            sha256=file_hash
        )

    def create_baseline(self, file_path: str) -> IntegrityResult:
        p = Path(file_path)
        if not p.exists():
            dummy = FileIdentity(name=os.path.basename(file_path), path=file_path, type="unknown", size=0, sha256="")
            return IntegrityResult(
                file=dummy,
                baseline_hash=None,
                current_hash=None,
                integrity_status="ERROR",
                error_message=f"File {file_path} does not exist"
            )
        try:
            curr_hash = calculate_sha256(p)
            self.store[file_path] = curr_hash
            identity = self._get_file_identity(file_path, curr_hash)
            return IntegrityResult(
                file=identity,
                baseline_hash=curr_hash,
                current_hash=curr_hash,
                integrity_status="UNCHANGED"
            )
        except Exception as exc:
            dummy = FileIdentity(name=os.path.basename(file_path), path=file_path, type="unknown", size=0, sha256="")
            msg = str(exc)
            return IntegrityResult(
                file=dummy,
                baseline_hash=None,
                current_hash=None,
                integrity_status="ERROR",
                error_message=msg.lower() if "permission denied" in msg.lower() else msg
            )

    def check_integrity(self, file_path: str) -> IntegrityResult:
        p = Path(file_path)
        base_hash = self.store.get(file_path)
        if not base_hash:
            dummy = FileIdentity(name=os.path.basename(file_path), path=file_path, type="unknown", size=0, sha256="")
            return IntegrityResult(
                file=dummy,
                baseline_hash=None,
                current_hash=None,
                integrity_status="ERROR",
                error_message="Baseline missing for this file."
            )

        if not p.exists():
            dummy = FileIdentity(name=os.path.basename(file_path), path=file_path, type="unknown", size=0, sha256="")
            return IntegrityResult(
                file=dummy,
                baseline_hash=base_hash,
                current_hash=None,
                integrity_status="ERROR",
                error_message="File does not exist."
            )

        try:
            curr_hash = calculate_sha256(p)
            identity = self._get_file_identity(file_path, curr_hash)
            status = "UNCHANGED" if curr_hash == base_hash else "MODIFIED"
            return IntegrityResult(
                file=identity,
                baseline_hash=base_hash,
                current_hash=curr_hash,
                integrity_status=status
            )
        except Exception as exc:
            dummy = FileIdentity(name=os.path.basename(file_path), path=file_path, type="unknown", size=0, sha256="")
            return IntegrityResult(
                file=dummy,
                baseline_hash=base_hash,
                current_hash=None,
                integrity_status="ERROR",
                error_message=str(exc)
            )
