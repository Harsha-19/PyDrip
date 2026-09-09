import os
import hashlib

class FileHasher:
    """
    Robust SHA-256 hashing service.
    """
    CHUNK_SIZE = 65536 # 64KB

    def hash_file(self, file_path: str) -> dict:
        """
        Hashes a file using chunked binary reads.
        Returns a dict: {"file_path": str, "sha256": str|None, "success": bool, "error": str|None}
        """
        if not os.path.exists(file_path):
            return {"file_path": file_path, "sha256": None, "success": False, "error": "Unable to calculate SHA-256: file does not exist."}
            
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(self.CHUNK_SIZE), b""):
                    sha256_hash.update(byte_block)
            return {"file_path": file_path, "sha256": sha256_hash.hexdigest(), "success": True, "error": None}
        except PermissionError:
            return {"file_path": file_path, "sha256": None, "success": False, "error": "Unable to calculate SHA-256: permission denied."}
        except Exception as e:
            return {"file_path": file_path, "sha256": None, "success": False, "error": f"Unable to calculate SHA-256: {str(e)}"}
