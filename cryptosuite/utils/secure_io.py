"""Atomic publication helpers resistant to accidental overwrite."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from cryptosuite.utils.exceptions import ValidationError


def publish_temporary(temporary: Path, destination: Path, *, overwrite: bool) -> None:
    """Publish a same-directory temporary file atomically when supported."""
    try:
        if overwrite:
            os.replace(temporary, destination)
        else:
            os.link(temporary, destination)
            temporary.unlink()
    except FileExistsError as exc:
        raise ValidationError(f"Destination already exists: {destination}") from exc
    except OSError as exc:
        raise ValidationError(f"Unable to publish output: {destination}") from exc


def atomic_write_bytes(
    destination: Path, data: bytes, *, overwrite: bool = False, mode: int = 0o600
) -> Path:
    """Write bytes to a same-directory temporary file and publish safely."""
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise ValidationError("Destination must not be a symbolic link.")
    descriptor, name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        publish_temporary(temporary, destination, overwrite=overwrite)
        return destination
    finally:
        temporary.unlink(missing_ok=True)
