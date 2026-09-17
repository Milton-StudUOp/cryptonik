"""Production hash functions backed by Python's OpenSSL integration."""

from __future__ import annotations

import hashlib
import hmac
from enum import StrEnum

from cryptosuite.utils.exceptions import ValidationError


class HashAlgorithm(StrEnum):
    """Hash algorithms approved for production operations."""

    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
    SHA3_256 = "sha3_256"
    SHA3_512 = "sha3_512"
    BLAKE2B = "blake2b"
    BLAKE2S = "blake2s"


def digest(data: bytes, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> bytes:
    """Hash an in-memory byte string with a production algorithm."""
    _require_bytes(data, "Data")
    selected = _coerce_algorithm(algorithm)
    return hashlib.new(selected.value, data).digest()


def hexdigest(data: bytes, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> str:
    """Return a lowercase hexadecimal hash digest."""
    return digest(data, algorithm).hex()


def compare_hashes(first: str, second: str) -> bool:
    """Validate and compare two hexadecimal digests in constant time."""
    if not isinstance(first, str) or not isinstance(second, str):
        raise ValidationError("Hashes must be hexadecimal text.")
    normalized_first = first.strip().casefold()
    normalized_second = second.strip().casefold()
    try:
        bytes.fromhex(normalized_first)
        bytes.fromhex(normalized_second)
    except ValueError as exc:
        raise ValidationError("Hashes must be valid hexadecimal.") from exc
    return hmac.compare_digest(normalized_first, normalized_second)


def _coerce_algorithm(algorithm: HashAlgorithm) -> HashAlgorithm:
    try:
        return HashAlgorithm(algorithm)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"Unsupported hash algorithm: {algorithm!s}.") from exc


def _require_bytes(value: bytes, label: str) -> None:
    if not isinstance(value, bytes):
        raise ValidationError(f"{label} must be bytes.")
