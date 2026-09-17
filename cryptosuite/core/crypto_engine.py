"""Stable facade shared by the CLI and future desktop interface."""

from __future__ import annotations

from cryptosuite.core.hashing import HashAlgorithm, digest
from cryptosuite.core.hmac_tools import HMACAlgorithm, generate_hmac, verify_hmac
from cryptosuite.core.kdf import Argon2idParameters, derive_key, generate_salt
from cryptosuite.core.symmetric import (
    EncryptedData,
    SymmetricAlgorithm,
    decrypt,
    encrypt,
    generate_key,
)


class CryptoEngine:
    """Stateless entry point for production cryptographic operations."""

    hash = staticmethod(digest)
    generate_hmac = staticmethod(generate_hmac)
    verify_hmac = staticmethod(verify_hmac)
    derive_key = staticmethod(derive_key)
    generate_salt = staticmethod(generate_salt)
    generate_symmetric_key = staticmethod(generate_key)
    encrypt = staticmethod(encrypt)
    decrypt = staticmethod(decrypt)


__all__ = [
    "Argon2idParameters",
    "CryptoEngine",
    "EncryptedData",
    "HMACAlgorithm",
    "HashAlgorithm",
    "SymmetricAlgorithm",
]

