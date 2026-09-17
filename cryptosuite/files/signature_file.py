"""Versioned, streaming detached file signatures."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

from cryptosuite.core.signatures import sign, verify
from cryptosuite.keys.key_generator import algorithm_of, public_fingerprint
from cryptosuite.utils.exceptions import FileFormatError, ValidationError
from cryptosuite.utils.secure_io import atomic_write_bytes

MAGIC = b"CRYPTSIG\x01"
DOMAIN = b"CryptoSuite streaming file signature v1\x00"
MAX_SIGNATURE_FILE_SIZE = 32 * 1024


def sign_file(
    document: Path,
    private_key,
    destination: Path | None = None,
    *,
    overwrite: bool = False,
) -> Path:
    """Hash a file incrementally and sign the domain-separated SHA-512 digest."""
    document = _regular_file(document)
    destination = Path(destination) if destination else Path(f"{document}.sig")
    digest = _streaming_digest(document)
    signed_value = DOMAIN + digest
    payload = {
        "algorithm": algorithm_of(private_key).value,
        "digest": base64.b64encode(digest).decode("ascii"),
        "digest_algorithm": "sha512",
        "fingerprint": public_fingerprint(private_key.public_key()),
        "signature": base64.b64encode(sign(signed_value, private_key)).decode("ascii"),
    }
    encoded = MAGIC + json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    atomic_write_bytes(destination, encoded, overwrite=overwrite, mode=0o644)
    return destination


def verify_file(document: Path, signature_file: Path, public_key) -> bool:
    """Verify a streaming detached signature and its signer fingerprint."""
    document = _regular_file(document)
    signature_file = _regular_file(signature_file)
    if signature_file.stat().st_size > MAX_SIGNATURE_FILE_SIZE:
        raise FileFormatError("Signature file is too large.")
    raw = signature_file.read_bytes()
    if not raw.startswith(MAGIC):
        raise FileFormatError("Invalid signature file magic or version.")
    try:
        payload = json.loads(raw[len(MAGIC) :].decode("ascii"))
        required = {"algorithm", "digest", "digest_algorithm", "fingerprint", "signature"}
        if set(payload) != required or payload["digest_algorithm"] != "sha512":
            raise ValueError
        if payload["algorithm"] != algorithm_of(public_key).value:
            return False
        if payload["fingerprint"] != public_fingerprint(public_key):
            return False
        recorded_digest = base64.b64decode(payload["digest"], validate=True)
        signature = base64.b64decode(payload["signature"], validate=True)
        if len(recorded_digest) != 64:
            raise ValueError
    except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise FileFormatError("Malformed signature file.") from exc
    calculated = _streaming_digest(document)
    if not hmac.compare_digest(recorded_digest, calculated):
        return False
    return verify(DOMAIN + calculated, signature, public_key)


def _streaming_digest(path: Path) -> bytes:
    hasher = hashlib.sha512()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
    except OSError as exc:
        raise ValidationError(f"Unable to read file: {path}") from exc
    return hasher.digest()


def _regular_file(path: Path) -> Path:
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValidationError(f"Path must be a regular, non-symlink file: {path}")
    return path
