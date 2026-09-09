import os
from .models import FileIdentity, IntegrityResult
from .hashing import FileHasher
from .storage import BaselineStore, InMemoryBaselineStore

class IntegrityEngine:
    """
    Core File Integrity Engine.
    Handles establishing baselines and comparing file integrity status deterministically.
    """
    def __init__(self, store: BaselineStore | None = None):
        self.hasher = FileHasher()
        self.store = store or InMemoryBaselineStore()

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
        hash_res = self.hasher.hash_file(file_path)
        
        if not hash_res["success"]:
            dummy_id = FileIdentity(name=os.path.basename(file_path), path=file_path, type="unknown", size=0, sha256="")
            return IntegrityResult(
                file=dummy_id, 
                baseline_hash=None, 
                current_hash=None, 
                integrity_status="ERROR", 
                error_message=hash_res["error"]
            )

        current_hash = hash_res["sha256"]
        self.store.save_baseline(file_path, current_hash)
        
        identity = self._get_file_identity(file_path, current_hash)
        return IntegrityResult(
            file=identity,
            baseline_hash=current_hash,
            current_hash=current_hash,
            integrity_status="UNCHANGED"
        )

    def check_integrity(self, file_path: str) -> IntegrityResult:
        baseline_hash = self.store.get_baseline(file_path)
        if not baseline_hash:
            dummy_id = FileIdentity(name=os.path.basename(file_path), path=file_path, type="unknown", size=0, sha256="")
            return IntegrityResult(
                file=dummy_id, 
                baseline_hash=None, 
                current_hash=None, 
                integrity_status="ERROR", 
                error_message="Baseline missing for this file."
            )

        hash_res = self.hasher.hash_file(file_path)
        if not hash_res["success"]:
            dummy_id = FileIdentity(name=os.path.basename(file_path), path=file_path, type="unknown", size=0, sha256="")
            return IntegrityResult(
                file=dummy_id, 
                baseline_hash=baseline_hash, 
                current_hash=None, 
                integrity_status="ERROR", 
                error_message=hash_res["error"]
            )

        current_hash = hash_res["sha256"]
        identity = self._get_file_identity(file_path, current_hash)
        
        status = "UNCHANGED" if current_hash == baseline_hash else "MODIFIED"
        
        return IntegrityResult(
            file=identity,
            baseline_hash=baseline_hash,
            current_hash=current_hash,
            integrity_status=status
        )
