"""Production public/private key generation and serialization."""

from __future__ import annotations

import hashlib
from enum import StrEnum

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519

from cryptosuite.utils.exceptions import KeyManagementError, ValidationError


class KeyAlgorithm(StrEnum):
    ED25519 = "ed25519"
    X25519 = "x25519"
    EC_P256 = "ec-p256"
    RSA_3072 = "rsa-3072"


def generate_private_key(algorithm: KeyAlgorithm):
    """Generate a private key for one explicit cryptographic purpose."""
    selected = _coerce_algorithm(algorithm)
    if selected is KeyAlgorithm.ED25519:
        return ed25519.Ed25519PrivateKey.generate()
    if selected is KeyAlgorithm.X25519:
        return x25519.X25519PrivateKey.generate()
    if selected is KeyAlgorithm.EC_P256:
        return ec.generate_private_key(ec.SECP256R1())
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def serialize_private_key(private_key, password: str | bytes) -> bytes:
    """Serialize a private key as encrypted PKCS#8 PEM."""
    password_bytes = _password_bytes(password)
    try:
        return private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password_bytes),
        )
    except (TypeError, ValueError) as exc:
        raise KeyManagementError("Unable to serialize private key.") from exc


def serialize_public_key(public_key) -> bytes:
    """Serialize a public key as SubjectPublicKeyInfo PEM."""
    try:
        return public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except (TypeError, ValueError) as exc:
        raise KeyManagementError("Unable to serialize public key.") from exc


def load_private_key(data: bytes, password: str | bytes | None):
    """Load a PEM private key; stored/exported keys remain encrypted by default."""
    if not isinstance(data, bytes):
        raise ValidationError("Private key data must be bytes.")
    password_bytes = (
        None if password is None or password in {"", b""} else _password_bytes(password)
    )
    try:
        return serialization.load_pem_private_key(data, password_bytes)
    except (TypeError, ValueError) as exc:
        raise KeyManagementError("Unable to load private key.") from exc


def load_public_key(data: bytes):
    """Load a PEM public key."""
    if not isinstance(data, bytes):
        raise ValidationError("Public key data must be bytes.")
    try:
        return serialization.load_pem_public_key(data)
    except (TypeError, ValueError) as exc:
        raise KeyManagementError("Unable to load public key.") from exc


def public_fingerprint(public_key) -> str:
    """Return the SHA-256 fingerprint of canonical public-key bytes."""
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return ":".join(f"{byte:02X}" for byte in hashlib.sha256(der).digest())


def key_id(public_key) -> str:
    """Return a compact non-secret identifier derived from the fingerprint."""
    compact = public_fingerprint(public_key).replace(":", "")
    return "-".join((compact[:4], compact[4:8], compact[8:12]))


def algorithm_of(key) -> KeyAlgorithm:
    public = key.public_key() if hasattr(key, "public_key") else key
    if isinstance(public, ed25519.Ed25519PublicKey):
        return KeyAlgorithm.ED25519
    if isinstance(public, x25519.X25519PublicKey):
        return KeyAlgorithm.X25519
    if isinstance(public, ec.EllipticCurvePublicKey) and isinstance(
        public.curve, ec.SECP256R1
    ):
        return KeyAlgorithm.EC_P256
    if isinstance(public, rsa.RSAPublicKey) and public.key_size >= 3072:
        return KeyAlgorithm.RSA_3072
    raise KeyManagementError("Unsupported or insecure key type.")


def _password_bytes(password: str | bytes) -> bytes:
    value = password.encode("utf-8") if isinstance(password, str) else password
    if not isinstance(value, bytes) or not value:
        raise ValidationError("Key protection password must not be empty.")
    if len(value) > 1024:
        raise ValidationError("Key protection password is too long.")
    return value


def _coerce_algorithm(algorithm: KeyAlgorithm) -> KeyAlgorithm:
    try:
        return KeyAlgorithm(algorithm)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"Unsupported key algorithm: {algorithm!s}.") from exc
