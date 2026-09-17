"""Best-effort file overwrite with explicit modern-storage limitations."""

from __future__ import annotations

import os
from pathlib import Path

from cryptosuite.core.random_generator import random_bytes
from cryptosuite.utils.exceptions import ValidationError

SECURE_DELETE_WARNING = (
    "Best-effort overwrite cannot guarantee erasure on SSDs, copy-on-write or "
    "journaled filesystems, snapshots, backups, or synchronized storage."
)


def best_effort_secure_delete(path: Path, *, passes: int = 1) -> None:
    """Overwrite a regular file and unlink it without claiming guaranteed erasure."""
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValidationError(f"Path must be a regular, non-symlink file: {path}")
    if isinstance(passes, bool) or not isinstance(passes, int) or not 1 <= passes <= 7:
        raise ValidationError("Overwrite passes must be between 1 and 7.")
    size = path.stat().st_size
    try:
        with path.open("r+b", buffering=0) as handle:
            for _ in range(passes):
                handle.seek(0)
                remaining = size
                while remaining:
                    length = min(1024 * 1024, remaining)
                    handle.write(random_bytes(length))
                    remaining -= length
                handle.flush()
                os.fsync(handle.fileno())
        path.unlink()
    except OSError as exc:
        raise ValidationError(f"Unable to overwrite and delete file: {path}") from exc
