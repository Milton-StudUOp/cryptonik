"""Authenticated streaming decryption for CRYPTX containers."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from cryptosuite.core.kdf import derive_key
from cryptosuite.core.symmetric import EncryptedData, decrypt
from cryptosuite.files.encrypt_file import LENGTH, ProgressCallback
from cryptosuite.files.file_format import chunk_aad, chunk_nonce, read_header
from cryptosuite.utils.exceptions import FileFormatError, ValidationError
from cryptosuite.utils.secure_io import publish_temporary


def decrypt_file(
    source: Path,
    password: str | bytes,
    destination: Path | None = None,
    *,
    overwrite: bool = False,
    progress: ProgressCallback | None = None,
) -> Path:
    """Authenticate every chunk and atomically publish the decrypted file."""
    source = Path(source)
    destination = Path(destination) if destination else _default_destination(source)
    _validate_paths(source, destination, overwrite)
    temporary: Path | None = None
    key = b""
    try:
        with source.open("rb") as reader:
            header, serialized = read_header(reader)
            key = derive_key(password, header.salt, header.kdf)
            descriptor, name = tempfile.mkstemp(
                prefix=f".{destination.name}.", dir=destination.parent
            )
            temporary = Path(name)
            processed = 0
            with os.fdopen(descriptor, "wb") as writer:
                for counter in range(header.chunk_count):
                    raw_length = reader.read(LENGTH.size)
                    if len(raw_length) != LENGTH.size:
                        raise FileFormatError("Truncated CRYPTX chunk framing.")
                    length = LENGTH.unpack(raw_length)[0]
                    expected_plain = min(
                        header.chunk_size, header.plaintext_size - processed
                    )
                    if header.plaintext_size == 0:
                        expected_plain = 0
                    if length != expected_plain + 16:
                        raise FileFormatError("Invalid CRYPTX encrypted chunk length.")
                    ciphertext = reader.read(length)
                    if len(ciphertext) != length:
                        raise FileFormatError("Truncated CRYPTX encrypted chunk.")
                    plaintext = decrypt(
                        EncryptedData(
                            header.algorithm,
                            chunk_nonce(header.nonce_prefix, counter, header.algorithm),
                            ciphertext,
                        ),
                        key,
                        associated_data=chunk_aad(serialized, counter),
                    )
                    writer.write(plaintext)
                    processed += len(plaintext)
                    if progress:
                        progress(processed, header.plaintext_size)
                if reader.read(1):
                    raise FileFormatError("CRYPTX file contains trailing data.")
                if processed != header.plaintext_size:
                    raise FileFormatError("CRYPTX plaintext size does not match header.")
                writer.flush()
                os.fsync(writer.fileno())
        publish_temporary(temporary, destination, overwrite=overwrite)
        return destination
    except OSError as exc:
        raise ValidationError(f"Unable to decrypt file: {source}") from exc
    finally:
        key = bytes(len(key))
        if temporary is not None and temporary.exists():
            temporary.unlink(missing_ok=True)


def _default_destination(source: Path) -> Path:
    if source.suffix.casefold() != ".cryptx":
        raise ValidationError("An output path is required for files without .cryptx.")
    return source.with_suffix("")


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
