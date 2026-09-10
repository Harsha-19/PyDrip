"""SHA-256 Hashing Engine for FIM+.

Provides streaming SHA-256 calculation for files using Python standard library hashlib.
"""

import hashlib
from pathlib import Path
from typing import Union

# Default chunk size: 64 KB (streaming read for low memory footprint)
DEFAULT_CHUNK_SIZE = 64 * 1024


class HashingError(Exception):
    """Base exception for hashing operations."""
    pass


class FileNotFoundError(HashingError):
    """Raised when the target file does not exist."""
    pass


class IsADirectoryError(HashingError):
    """Raised when the path points to a directory rather than a file."""
    pass


class FileAccessError(HashingError):
    """Raised when a file cannot be read due to permissions or OS errors."""
    pass


def calculate_sha256(
    file_path: Union[str, Path],
    chunk_size: int = DEFAULT_CHUNK_SIZE
) -> str:
    """Calculate the hexadecimal SHA-256 digest of a file using streaming binary reads.

    Args:
        file_path: Path to the target file.
        chunk_size: Number of bytes to read per iteration (default 64 KB). Must be > 0.

    Returns:
        64-character lowercase hexadecimal SHA-256 digest string.

    Raises:
        ValueError: If chunk_size <= 0.
        FileNotFoundError: If the file does not exist.
        IsADirectoryError: If the path is a directory.
        FileAccessError: If reading the file fails due to permissions or OS errors.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer greater than 0.")

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if path.is_dir():
        raise IsADirectoryError(f"Path is a directory, not a file: {path}")

    sha256_hash = hashlib.sha256()

    try:
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                sha256_hash.update(chunk)
    except PermissionError as exc:
        raise FileAccessError(f"Permission denied accessing file: {path}") from exc
    except OSError as exc:
        raise FileAccessError(f"OS error occurred while reading file: {path}") from exc
    except Exception as exc:
        raise FileAccessError(f"Unexpected error while hashing file: {path}") from exc

    return sha256_hash.hexdigest()
