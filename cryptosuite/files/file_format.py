"""Strict, versioned CRYPTX container framing."""

from __future__ import annotations

import base64
import json
import struct
from dataclasses import asdict, dataclass
from typing import Any, BinaryIO

from cryptosuite.core.kdf import Argon2idParameters
from cryptosuite.core.symmetric import NONCE_LENGTHS, SymmetricAlgorithm
from cryptosuite.utils.exceptions import FileFormatError

MAGIC = b"CRYPTX"
VERSION = 1
PREFIX = struct.Struct(">6sBI")
MAX_HEADER_SIZE = 16 * 1024
MIN_CHUNK_SIZE = 64 * 1024
MAX_CHUNK_SIZE = 16 * 1024 * 1024
MAX_FILE_SIZE = (1 << 63) - 1


@dataclass(frozen=True, slots=True)
class CryptxHeader:
    """Authenticated metadata for a password-encrypted file."""

    algorithm: SymmetricAlgorithm
    salt: bytes
    nonce_prefix: bytes
    kdf: Argon2idParameters
    chunk_size: int
    plaintext_size: int

    @property
    def chunk_count(self) -> int:
        if self.plaintext_size == 0:
            return 1
        return (self.plaintext_size + self.chunk_size - 1) // self.chunk_size


def serialize_header(header: CryptxHeader) -> bytes:
    """Serialize and validate a canonical JSON header with a binary prefix."""
    _validate_header(header)
    payload = {
        "algorithm": header.algorithm.value,
        "chunk_size": header.chunk_size,
        "kdf": "argon2id",
        "kdf_parameters": asdict(header.kdf),
        "nonce_prefix": base64.b64encode(header.nonce_prefix).decode("ascii"),
        "plaintext_size": header.plaintext_size,
        "salt": base64.b64encode(header.salt).decode("ascii"),
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    if len(encoded) > MAX_HEADER_SIZE:
        raise FileFormatError("CRYPTX header is too large.")
    return PREFIX.pack(MAGIC, VERSION, len(encoded)) + encoded


def read_header(stream: BinaryIO) -> tuple[CryptxHeader, bytes]:
    """Read a CRYPTX header and return both parsed and authenticated forms."""
    prefix = stream.read(PREFIX.size)
    if len(prefix) != PREFIX.size:
        raise FileFormatError("Truncated CRYPTX header.")
    magic, version, length = PREFIX.unpack(prefix)
    if magic != MAGIC:
        raise FileFormatError("Not a CRYPTX file.")
    if version != VERSION:
        raise FileFormatError(f"Unsupported CRYPTX version: {version}.")
    if not 1 <= length <= MAX_HEADER_SIZE:
        raise FileFormatError("Invalid CRYPTX header length.")
    encoded = stream.read(length)
    if len(encoded) != length:
        raise FileFormatError("Truncated CRYPTX header payload.")
    try:
        payload = json.loads(encoded.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise FileFormatError("Invalid CRYPTX header encoding.") from exc
    header = _parse_payload(payload)
    return header, prefix + encoded


def chunk_nonce(prefix: bytes, counter: int, algorithm: SymmetricAlgorithm) -> bytes:
    """Build a unique per-chunk nonce from a random prefix and counter."""
    if not 0 <= counter < 2**64:
        raise FileFormatError("CRYPTX chunk counter is out of range.")
    expected_prefix = NONCE_LENGTHS[algorithm] - 8
    if len(prefix) != expected_prefix:
        raise FileFormatError("Invalid CRYPTX nonce prefix.")
    return prefix + counter.to_bytes(8, "big")


def chunk_aad(serialized_header: bytes, counter: int) -> bytes:
    """Bind every encrypted chunk to its header and exact position."""
    return serialized_header + counter.to_bytes(8, "big")


def _parse_payload(payload: Any) -> CryptxHeader:
    required = {
        "algorithm",
        "chunk_size",
        "kdf",
        "kdf_parameters",
        "nonce_prefix",
        "plaintext_size",
        "salt",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise FileFormatError("CRYPTX header fields are invalid.")
    if payload["kdf"] != "argon2id":
        raise FileFormatError("Unsupported CRYPTX KDF.")
    try:
        algorithm = SymmetricAlgorithm(payload["algorithm"])
        salt = base64.b64decode(payload["salt"], validate=True)
        nonce_prefix = base64.b64decode(payload["nonce_prefix"], validate=True)
        params_data = payload["kdf_parameters"]
        if not isinstance(params_data, dict):
            raise TypeError
        kdf = Argon2idParameters(**params_data)
        header = CryptxHeader(
            algorithm=algorithm,
            salt=salt,
            nonce_prefix=nonce_prefix,
            kdf=kdf,
            chunk_size=payload["chunk_size"],
            plaintext_size=payload["plaintext_size"],
        )
        _validate_header(header)
        return header
    except (KeyError, TypeError, ValueError) as exc:
        raise FileFormatError("CRYPTX header values are invalid.") from exc


def _validate_header(header: CryptxHeader) -> None:
    if not isinstance(header.algorithm, SymmetricAlgorithm):
        raise FileFormatError("Invalid CRYPTX algorithm.")
    if not isinstance(header.salt, bytes) or not 16 <= len(header.salt) <= 1024:
        raise FileFormatError("Invalid CRYPTX salt.")
    expected_prefix = NONCE_LENGTHS[header.algorithm] - 8
    if not isinstance(header.nonce_prefix, bytes) or len(header.nonce_prefix) != expected_prefix:
        raise FileFormatError("Invalid CRYPTX nonce prefix.")
    if isinstance(header.chunk_size, bool) or not isinstance(header.chunk_size, int):
        raise FileFormatError("Invalid CRYPTX chunk size.")
    if not MIN_CHUNK_SIZE <= header.chunk_size <= MAX_CHUNK_SIZE:
        raise FileFormatError("CRYPTX chunk size is outside safe limits.")
    if isinstance(header.plaintext_size, bool) or not isinstance(header.plaintext_size, int):
        raise FileFormatError("Invalid CRYPTX plaintext size.")
    if not 0 <= header.plaintext_size <= MAX_FILE_SIZE:
        raise FileFormatError("CRYPTX plaintext size is outside safe limits.")

