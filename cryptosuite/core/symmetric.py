"""Authenticated in-memory symmetric encryption using established libraries."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from nacl import bindings
from nacl.exceptions import CryptoError

from cryptosuite.core.random_generator import random_bytes
from cryptosuite.utils.exceptions import AuthenticationError, ValidationError

KEY_LENGTH = 32


class SymmetricAlgorithm(StrEnum):
    """Supported authenticated-encryption algorithms."""

    AES_256_GCM = "aes-256-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"
    XCHACHA20_POLY1305 = "xchacha20-poly1305"


NONCE_LENGTHS = {
    SymmetricAlgorithm.AES_256_GCM: 12,
    SymmetricAlgorithm.CHACHA20_POLY1305: 12,
    SymmetricAlgorithm.XCHACHA20_POLY1305: 24,
}


@dataclass(frozen=True, slots=True)
class EncryptedData:
    """Authenticated ciphertext and the unique nonce needed to decrypt it."""

    algorithm: SymmetricAlgorithm
    nonce: bytes
    ciphertext: bytes


def generate_key() -> bytes:
    """Generate a new 256-bit symmetric key."""
    return random_bytes(KEY_LENGTH)


def encrypt(
    plaintext: bytes,
    key: bytes,
    algorithm: SymmetricAlgorithm = SymmetricAlgorithm.AES_256_GCM,
    *,
    associated_data: bytes | None = None,
    nonce: bytes | None = None,
) -> EncryptedData:
    """Encrypt bytes with AEAD, authenticating optional associated data."""
    selected = _coerce_algorithm(algorithm)
    _validate_common(plaintext, key, associated_data, "Plaintext")
    nonce_value = (
        random_bytes(NONCE_LENGTHS[selected]) if nonce is None else nonce
    )
    _validate_nonce(nonce_value, selected)
    if selected is SymmetricAlgorithm.AES_256_GCM:
        ciphertext = AESGCM(key).encrypt(nonce_value, plaintext, associated_data)
    elif selected is SymmetricAlgorithm.CHACHA20_POLY1305:
        ciphertext = ChaCha20Poly1305(key).encrypt(
            nonce_value, plaintext, associated_data
        )
    else:
        ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, associated_data, nonce_value, key
        )
    return EncryptedData(selected, nonce_value, ciphertext)


def decrypt(
    encrypted: EncryptedData,
    key: bytes,
    *,
    associated_data: bytes | None = None,
) -> bytes:
    """Authenticate and decrypt bytes, raising on any verification failure."""
    if not isinstance(encrypted, EncryptedData):
        raise ValidationError("Encrypted input must be an EncryptedData object.")
    selected = _coerce_algorithm(encrypted.algorithm)
    _validate_common(encrypted.ciphertext, key, associated_data, "Ciphertext")
    _validate_nonce(encrypted.nonce, selected)
    try:
        if selected is SymmetricAlgorithm.AES_256_GCM:
            return AESGCM(key).decrypt(
                encrypted.nonce, encrypted.ciphertext, associated_data
            )
        if selected is SymmetricAlgorithm.CHACHA20_POLY1305:
            return ChaCha20Poly1305(key).decrypt(
                encrypted.nonce, encrypted.ciphertext, associated_data
            )
        return bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            encrypted.ciphertext, associated_data, encrypted.nonce, key
        )
    except (InvalidTag, CryptoError) as exc:
        raise AuthenticationError(
            "Unable to decrypt: authentication failed or data is corrupted."
        ) from exc


def _validate_common(
    data: bytes, key: bytes, associated_data: bytes | None, label: str
) -> None:
    if not isinstance(data, bytes):
        raise ValidationError(f"{label} must be bytes.")
    if not isinstance(key, bytes) or len(key) != KEY_LENGTH:
        raise ValidationError("Symmetric key must contain exactly 32 bytes.")
    if associated_data is not None and not isinstance(associated_data, bytes):
        raise ValidationError("Associated data must be bytes or None.")


def _validate_nonce(nonce: bytes, algorithm: SymmetricAlgorithm) -> None:
    expected = NONCE_LENGTHS[algorithm]
    if not isinstance(nonce, bytes) or len(nonce) != expected:
        raise ValidationError(
            f"Nonce for {algorithm.value} must contain exactly {expected} bytes."
        )


def _coerce_algorithm(algorithm: SymmetricAlgorithm) -> SymmetricAlgorithm:
    try:
        return SymmetricAlgorithm(algorithm)
    except (TypeError, ValueError) as exc:
        raise ValidationError(
            f"Unsupported symmetric algorithm: {algorithm!s}."
        ) from exc
