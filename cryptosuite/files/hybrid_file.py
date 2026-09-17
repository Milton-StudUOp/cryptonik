"""Streaming multi-recipient hybrid file encryption."""

from __future__ import annotations

import base64
import json
import os
import re
import struct
import tempfile
from pathlib import Path

from cryptosuite.core.asymmetric import (
    MAX_RECIPIENTS,
    RecipientEnvelope,
    _unwrap_key,
    _wrap_key,
)
from cryptosuite.core.random_generator import random_bytes
from cryptosuite.core.symmetric import (
    EncryptedData,
    SymmetricAlgorithm,
    decrypt,
    encrypt,
    generate_key,
)
from cryptosuite.files.encrypt_file import ProgressCallback
from cryptosuite.files.file_format import MAX_CHUNK_SIZE, MIN_CHUNK_SIZE
from cryptosuite.keys.key_generator import key_id
from cryptosuite.utils.exceptions import (
    AuthenticationError,
    FileFormatError,
    ValidationError,
)
from cryptosuite.utils.secure_io import publish_temporary

MAGIC = b"CRYPTH"
VERSION = 1
PREFIX = struct.Struct(">6sBI")
LENGTH = struct.Struct(">I")
MAX_HEADER_SIZE = 256 * 1024
MAX_FILE_SIZE = (1 << 63) - 1
ALGORITHM = SymmetricAlgorithm.XCHACHA20_POLY1305


def encrypt_file_for_recipients(
    source: Path,
    recipient_public_keys: list,
    destination: Path | None = None,
    *,
    chunk_size: int = 1024 * 1024,
    overwrite: bool = False,
    progress: ProgressCallback | None = None,
) -> Path:
    """Encrypt a file once and wrap its random key for every recipient."""
    source = Path(source)
    destination = Path(destination) if destination else Path(f"{source}.crypth")
    _validate_paths(source, destination, overwrite)
    if not 1 <= len(recipient_public_keys) <= MAX_RECIPIENTS:
        raise ValidationError(f"Recipient count must be between 1 and {MAX_RECIPIENTS}.")
    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise ValidationError("Chunk size is outside safe limits.")
    size = source.stat().st_size
    if size > MAX_FILE_SIZE:
        raise ValidationError("Source file is too large.")
    data_key = generate_key()
    recipients = tuple(_wrap_key(data_key, key) for key in recipient_public_keys)
    nonce_prefix = random_bytes(16)
    serialized = _serialize_header(recipients, nonce_prefix, chunk_size, size)
    chunk_count = max(1, (size + chunk_size - 1) // chunk_size)
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
        temporary = Path(name)
        with source.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
            writer.write(serialized)
            processed = 0
            for counter in range(chunk_count):
                plaintext = reader.read(chunk_size)
                sealed = encrypt(
                    plaintext,
                    data_key,
                    ALGORITHM,
                    nonce=nonce_prefix + counter.to_bytes(8, "big"),
                    associated_data=serialized + counter.to_bytes(8, "big"),
                ).ciphertext
                writer.write(LENGTH.pack(len(sealed)))
                writer.write(sealed)
                processed += len(plaintext)
                if progress:
                    progress(processed, size)
            if processed != size or reader.read(1):
                raise ValidationError("Source file changed while it was encrypted.")
            writer.flush()
            os.fsync(writer.fileno())
        publish_temporary(temporary, destination, overwrite=overwrite)
        return destination
    finally:
        data_key = bytes(len(data_key))
        if temporary is not None and temporary.exists():
            temporary.unlink(missing_ok=True)


def decrypt_file_for_recipient(
    source: Path,
    recipient_private_key,
    destination: Path | None = None,
    *,
    overwrite: bool = False,
    progress: ProgressCallback | None = None,
) -> Path:
    """Stream-decrypt a hybrid file for one authorized recipient."""
    source = Path(source)
    destination = Path(destination) if destination else _default_destination(source)
    _validate_paths(source, destination, overwrite)
    temporary: Path | None = None
    data_key = b""
    try:
        with source.open("rb") as reader:
            recipients, nonce_prefix, chunk_size, size, serialized = _read_header(reader)
            identifier = key_id(recipient_private_key.public_key())
            recipient = next((item for item in recipients if item.key_id == identifier), None)
            if recipient is None:
                raise AuthenticationError("Private key is not a recipient of this file.")
            data_key = _unwrap_key(recipient, recipient_private_key)
            descriptor, name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
            temporary = Path(name)
            chunk_count = max(1, (size + chunk_size - 1) // chunk_size)
            processed = 0
            with os.fdopen(descriptor, "wb") as writer:
                for counter in range(chunk_count):
                    framing = reader.read(LENGTH.size)
                    if len(framing) != LENGTH.size:
                        raise FileFormatError("Truncated hybrid chunk framing.")
                    length = LENGTH.unpack(framing)[0]
                    expected = min(chunk_size, size - processed) if size else 0
                    if length != expected + 16:
                        raise FileFormatError("Invalid hybrid chunk length.")
                    ciphertext = reader.read(length)
                    if len(ciphertext) != length:
                        raise FileFormatError("Truncated hybrid encrypted chunk.")
                    plaintext = decrypt(
                        EncryptedData(ALGORITHM, nonce_prefix + counter.to_bytes(8, "big"), ciphertext),
                        data_key,
                        associated_data=serialized + counter.to_bytes(8, "big"),
                    )
                    writer.write(plaintext)
                    processed += len(plaintext)
                    if progress:
                        progress(processed, size)
                if reader.read(1):
                    raise FileFormatError("Hybrid file contains trailing data.")
                if processed != size:
                    raise FileFormatError("Hybrid plaintext size does not match header.")
                writer.flush()
                os.fsync(writer.fileno())
        publish_temporary(temporary, destination, overwrite=overwrite)
        return destination
    finally:
        data_key = bytes(len(data_key))
        if temporary is not None and temporary.exists():
            temporary.unlink(missing_ok=True)


def _serialize_header(
    recipients: tuple[RecipientEnvelope, ...], nonce_prefix: bytes, chunk_size: int, size: int
) -> bytes:
    payload = {
        "algorithm": ALGORITHM.value,
        "chunk_size": chunk_size,
        "nonce_prefix": _b64(nonce_prefix),
        "plaintext_size": size,
        "recipients": [_recipient_payload(item) for item in recipients],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(encoded) > MAX_HEADER_SIZE:
        raise ValidationError("Hybrid header is too large.")
    return PREFIX.pack(MAGIC, VERSION, len(encoded)) + encoded


def _read_header(stream):
    prefix = stream.read(PREFIX.size)
    if len(prefix) != PREFIX.size:
        raise FileFormatError("Truncated hybrid header.")
    magic, version, length = PREFIX.unpack(prefix)
    if magic != MAGIC or version != VERSION or not 1 <= length <= MAX_HEADER_SIZE:
        raise FileFormatError("Invalid or unsupported hybrid header.")
    encoded = stream.read(length)
    if len(encoded) != length:
        raise FileFormatError("Truncated hybrid header payload.")
    try:
        payload = json.loads(encoded.decode("ascii"))
        required = {"algorithm", "chunk_size", "nonce_prefix", "plaintext_size", "recipients"}
        if set(payload) != required or payload["algorithm"] != ALGORITHM.value:
            raise ValueError
        chunk_size = payload["chunk_size"]
        size = payload["plaintext_size"]
        nonce_prefix = _unb64(payload["nonce_prefix"])
        raw_recipients = payload["recipients"]
        if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
            raise TypeError
        if isinstance(size, bool) or not isinstance(size, int):
            raise TypeError
        if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
            raise ValueError
        if not 0 <= size <= MAX_FILE_SIZE or len(nonce_prefix) != 16:
            raise ValueError
        if not 1 <= len(raw_recipients) <= MAX_RECIPIENTS:
            raise ValueError
        recipients = tuple(_parse_recipient(item) for item in raw_recipients)
        return recipients, nonce_prefix, chunk_size, size, prefix + encoded
    except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise FileFormatError("Malformed hybrid header.") from exc


def _recipient_payload(item: RecipientEnvelope) -> dict[str, str]:
    payload = {"algorithm": item.algorithm, "key_id": item.key_id, "wrapped_key": _b64(item.wrapped_key)}
    if item.ephemeral_public_key is not None:
        payload["ephemeral_public_key"] = _b64(item.ephemeral_public_key)
    if item.nonce is not None:
        payload["nonce"] = _b64(item.nonce)
    return payload


def _parse_recipient(item) -> RecipientEnvelope:
    if not isinstance(item, dict):
        raise TypeError
    allowed = {"algorithm", "key_id", "wrapped_key", "ephemeral_public_key", "nonce"}
    if not {"algorithm", "key_id", "wrapped_key"} <= set(item) <= allowed:
        raise ValueError
    algorithm = item["algorithm"]
    identifier = item["key_id"]
    if algorithm not in {"x25519", "rsa-oaep-sha256"}:
        raise ValueError
    if not isinstance(identifier, str) or not re.fullmatch(
        r"[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}", identifier
    ):
        raise ValueError
    recipient = RecipientEnvelope(
        key_id=identifier,
        algorithm=algorithm,
        wrapped_key=_unb64(item["wrapped_key"]),
        ephemeral_public_key=_unb64(item["ephemeral_public_key"]) if "ephemeral_public_key" in item else None,
        nonce=_unb64(item["nonce"]) if "nonce" in item else None,
    )
    if algorithm == "x25519":
        if (
            recipient.ephemeral_public_key is None
            or len(recipient.ephemeral_public_key) != 32
            or recipient.nonce is None
            or len(recipient.nonce) != 12
            or len(recipient.wrapped_key) != 48
        ):
            raise ValueError
    elif recipient.ephemeral_public_key is not None or recipient.nonce is not None:
        raise ValueError
    return recipient


def _validate_paths(source: Path, destination: Path, overwrite: bool) -> None:
    if not source.is_file() or source.is_symlink():
        raise ValidationError(f"Source must be a regular, non-symlink file: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.resolve() == destination.resolve():
        raise ValidationError("Source and destination must be different files.")
    if destination.is_symlink():
        raise ValidationError("Destination must not be a symbolic link.")
    if destination.exists() and not overwrite:
        raise ValidationError(f"Destination already exists: {destination}")


def _default_destination(source: Path) -> Path:
    if source.suffix.casefold() != ".crypth":
        raise ValidationError("An output path is required for files without .crypth.")
    return source.with_suffix("")


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)
