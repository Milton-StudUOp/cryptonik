"""Streaming file hashing and constant-time checksum comparison."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

from cryptosuite.core.hashing import HashAlgorithm
from cryptosuite.utils.exceptions import ValidationError


def hash_file(path: Path, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> str:
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValidationError(f"Path must be a regular, non-symlink file: {path}")
    try:
        hasher = hashlib.new(HashAlgorithm(algorithm).value)
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except OSError as exc:
        raise ValidationError(f"Unable to hash file: {path}") from exc


def verify_file_hash(path: Path, expected: str, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> bool:
    normalized = expected.strip().casefold()
    try:
        bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValidationError("Expected checksum is not valid hexadecimal.") from exc
    return hmac.compare_digest(hash_file(path, algorithm), normalized)

