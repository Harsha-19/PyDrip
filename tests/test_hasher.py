"""Unit tests for SHA-256 hashing engine (Phase 4)."""

import hashlib
from pathlib import Path
from unittest.mock import patch
import pytest

from app.core.hasher import (
    DEFAULT_CHUNK_SIZE,
    FileAccessError,
    FileNotFoundError,
    HashingError,
    IsADirectoryError,
    calculate_sha256,
)


def test_known_string_sha256(tmp_path: Path):
    """Verify known string 'hello world' produces the exact standard SHA-256 digest."""
    test_file = tmp_path / "hello.txt"
    test_file.write_bytes(b"hello world")

    # Known SHA-256 for b"hello world": b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    expected_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    digest = calculate_sha256(test_file)
    assert digest == expected_hash


def test_empty_file_sha256(tmp_path: Path):
    """Verify empty file produces standard SHA-256 for empty bytes."""
    empty_file = tmp_path / "empty.txt"
    empty_file.write_bytes(b"")

    expected_hash = hashlib.sha256(b"").hexdigest()  # e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    digest = calculate_sha256(empty_file)
    assert digest == expected_hash
    assert digest == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_hashing_determinism_same_content(tmp_path: Path):
    """Verify identical content produces the exact same hash across multiple calls."""
    f1 = tmp_path / "file1.txt"
    f2 = tmp_path / "file2.txt"
    content = b"Deterministic FIM+ Integrity Test Payload 12345"
    f1.write_bytes(content)
    f2.write_bytes(content)

    hash1 = calculate_sha256(f1)
    hash2 = calculate_sha256(f2)
    assert hash1 == hash2
    assert hash1 == hashlib.sha256(content).hexdigest()


def test_different_content_different_hash(tmp_path: Path):
    """Verify different file content results in distinct SHA-256 hashes."""
    f1 = tmp_path / "file1.txt"
    f2 = tmp_path / "file2.txt"
    f1.write_bytes(b"Original file content")
    f2.write_bytes(b"Modified file content")

    hash1 = calculate_sha256(f1)
    hash2 = calculate_sha256(f2)
    assert hash1 != hash2


def test_binary_file_hashing(tmp_path: Path):
    """Verify binary data (non-text bytes with null bytes) hashes properly."""
    binary_file = tmp_path / "binary.dat"
    binary_data = bytes(range(256)) * 10
    binary_file.write_bytes(binary_data)

    expected_hash = hashlib.sha256(binary_data).hexdigest()
    digest = calculate_sha256(binary_file)
    assert digest == expected_hash


def test_missing_file_raises_file_not_found(tmp_path: Path):
    """Verify attempting to hash a non-existent file raises FileNotFoundError."""
    missing = tmp_path / "does_not_exist.bin"
    with pytest.raises(FileNotFoundError) as exc_info:
        calculate_sha256(missing)
    assert "not found" in str(exc_info.value).lower()


def test_directory_path_raises_is_a_directory_error(tmp_path: Path):
    """Verify attempting to hash a directory raises IsADirectoryError."""
    test_dir = tmp_path / "somedir"
    test_dir.mkdir()
    with pytest.raises(IsADirectoryError) as exc_info:
        calculate_sha256(test_dir)
    assert "directory" in str(exc_info.value).lower()


def test_file_access_permission_error(tmp_path: Path):
    """Verify OS/permission errors raise FileAccessError."""
    protected_file = tmp_path / "protected.txt"
    protected_file.write_bytes(b"secret")

    with patch("builtins.open", side_effect=PermissionError("Access denied")):
        with pytest.raises(FileAccessError) as exc_info:
            calculate_sha256(protected_file)
        assert "permission denied" in str(exc_info.value).lower()


def test_streaming_chunked_reads(tmp_path: Path):
    """Verify streaming reads process file in chunks without reading all bytes in one go."""
    large_file = tmp_path / "large_file.bin"
    # Create 256 KB file
    data = b"X" * (256 * 1024)
    large_file.write_bytes(data)

    # Use small chunk size (16 KB) -> exactly 16 reads of 16KB + 1 EOF read
    chunk_size = 16 * 1024
    digest = calculate_sha256(large_file, chunk_size=chunk_size)
    assert digest == hashlib.sha256(data).hexdigest()
