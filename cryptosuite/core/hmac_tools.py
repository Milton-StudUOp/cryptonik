"""HMAC generation and constant-time verification."""

from __future__ import annotations

import hashlib
import hmac
from enum import StrEnum

from cryptosuite.utils.exceptions import ValidationError


class HMACAlgorithm(StrEnum):
    """Supported HMAC algorithms."""

    SHA256 = "sha256"
    SHA512 = "sha512"


def generate_hmac(
    key: bytes, data: bytes, algorithm: HMACAlgorithm = HMACAlgorithm.SHA256
) -> bytes:
    """Generate an HMAC tag using a non-empty secret key."""
    _validate_inputs(key, data)
    selected = _coerce_algorithm(algorithm)
    return hmac.new(key, data, getattr(hashlib, selected.value)).digest()


def verify_hmac(
    key: bytes,
    data: bytes,
    expected_tag: bytes,
    algorithm: HMACAlgorithm = HMACAlgorithm.SHA256,
) -> bool:
    """Verify an HMAC tag using constant-time comparison."""
    if not isinstance(expected_tag, bytes):
        raise ValidationError("Expected HMAC tag must be bytes.")
    calculated = generate_hmac(key, data, algorithm)
    return hmac.compare_digest(calculated, expected_tag)


def _validate_inputs(key: bytes, data: bytes) -> None:
    if not isinstance(key, bytes) or not key:
        raise ValidationError("HMAC key must be non-empty bytes.")
    if not isinstance(data, bytes):
        raise ValidationError("Data must be bytes.")


def _coerce_algorithm(algorithm: HMACAlgorithm) -> HMACAlgorithm:
    try:
        return HMACAlgorithm(algorithm)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"Unsupported HMAC algorithm: {algorithm!s}.") from exc

