"""Streaming password-based file encryption into CRYPTX containers."""

from __future__ import annotations

import os
import struct
import tempfile
from collections.abc import Callable
from pathlib import Path

from cryptosuite.core.kdf import Argon2idParameters, derive_key, generate_salt
from cryptosuite.core.random_generator import random_bytes
from cryptosuite.core.symmetric import NONCE_LENGTHS, SymmetricAlgorithm, encrypt
from cryptosuite.files.file_format import (
    CryptxHeader,
    chunk_aad,
    chunk_nonce,
    serialize_header,
)
from cryptosuite.utils.exceptions import ValidationError
from cryptosuite.utils.secure_io import publish_temporary

ProgressCallback = Callable[[int, int], None]
LENGTH = struct.Struct(">I")


def encrypt_file(
    source: Path,
    password: str | bytes,
    destination: Path | None = None,
    *,
    algorithm: SymmetricAlgorithm = SymmetricAlgorithm.XCHACHA20_POLY1305,
    kdf_parameters: Argon2idParameters | None = None,
    chunk_size: int = 1024 * 1024,
    overwrite: bool = False,
    progress: ProgressCallback | None = None,
) -> Path:
    """Encrypt a regular file without loading it entirely into memory."""
    source = Path(source)
    destination = Path(destination) if destination else Path(f"{source}.cryptx")
    _validate_paths(source, destination, overwrite)
    size = source.stat().st_size
    params = kdf_parameters or Argon2idParameters()
    salt = generate_salt()
    key = derive_key(password, salt, params)
    prefix = random_bytes(NONCE_LENGTHS[algorithm] - 8)
    header = CryptxHeader(algorithm, salt, prefix, params, chunk_size, size)
    serialized = serialize_header(header)
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=destination.parent
        )
        temporary = Path(name)
        with source.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
            writer.write(serialized)
            processed = 0
            for counter in range(header.chunk_count):
                plaintext = reader.read(chunk_size)
                sealed = encrypt(
                    plaintext,
                    key,
                    algorithm,
                    nonce=chunk_nonce(prefix, counter, algorithm),
                    associated_data=chunk_aad(serialized, counter),
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
    except OSError as exc:
        raise ValidationError(f"Unable to encrypt file: {source}") from exc
    finally:
        key = bytes(len(key))
        if temporary is not None and temporary.exists():
            temporary.unlink(missing_ok=True)


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
