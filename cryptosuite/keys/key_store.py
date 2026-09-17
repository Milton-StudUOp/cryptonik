"""Local encrypted private-key store with atomic metadata updates."""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptosuite.keys.key_generator import (
    KeyAlgorithm,
    algorithm_of,
    generate_private_key,
    key_id,
    load_private_key,
    public_fingerprint,
    serialize_private_key,
    serialize_public_key,
)
from cryptosuite.utils.exceptions import KeyManagementError, ValidationError

NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,63}$")


@dataclass(frozen=True, slots=True)
class KeyRecord:
    id: str
    name: str
    algorithm: str
    purpose: str
    created: str
    fingerprint: str
    status: str = "active"


class KeyStore:
    """Store encrypted PKCS#8 keys and public metadata under one directory."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def generate(
        self,
        name: str,
        algorithm: KeyAlgorithm,
        purpose: str,
        password: str | bytes,
    ) -> KeyRecord:
        _validate_name(name)
        _validate_purpose(algorithm, purpose)
        private = generate_private_key(algorithm)
        public = private.public_key()
        record = KeyRecord(
            id=key_id(public),
            name=name,
            algorithm=algorithm_of(public).value,
            purpose=purpose,
            created=datetime.now(UTC).isoformat(),
            fingerprint=public_fingerprint(public),
        )
        directory = self.root / record.id
        if directory.exists():
            raise KeyManagementError("A key with this identifier already exists.")
        directory.mkdir(parents=True, mode=0o700)
        try:
            _atomic_write(directory / "private.pem", serialize_private_key(private, password), 0o600)
            _atomic_write(directory / "public.pem", serialize_public_key(public), 0o644)
            _atomic_write(
                directory / "metadata.json",
                (json.dumps(asdict(record), indent=2, sort_keys=True) + "\n").encode(),
                0o600,
            )
        except Exception:
            for path in directory.iterdir():
                path.unlink(missing_ok=True)
            directory.rmdir()
            raise
        return record

    def import_private(
        self,
        name: str,
        purpose: str,
        pem_data: bytes,
        current_password: str | bytes,
        storage_password: str | bytes,
    ) -> KeyRecord:
        """Import a supported encrypted private key and re-protect it for storage."""
        _validate_name(name)
        private = load_private_key(pem_data, current_password)
        algorithm = algorithm_of(private)
        _validate_purpose(algorithm, purpose)
        public = private.public_key()
        record = KeyRecord(
            id=key_id(public),
            name=name,
            algorithm=algorithm.value,
            purpose=purpose,
            created=datetime.now(UTC).isoformat(),
            fingerprint=public_fingerprint(public),
        )
        self._store_record(record, private, storage_password)
        return record

    def import_public(
        self, name: str, purpose: str, pem_data: bytes
    ) -> KeyRecord:
        """Import a supported public-only key, such as a recipient key."""
        from cryptosuite.keys.key_generator import load_public_key

        _validate_name(name)
        public = load_public_key(pem_data)
        algorithm = algorithm_of(public)
        _validate_purpose(algorithm, purpose)
        record = KeyRecord(
            id=key_id(public),
            name=name,
            algorithm=algorithm.value,
            purpose=purpose,
            created=datetime.now(UTC).isoformat(),
            fingerprint=public_fingerprint(public),
            status="public-only",
        )
        directory = self.root / record.id
        if directory.exists():
            raise KeyManagementError("A key with this identifier already exists.")
        directory.mkdir(parents=True, mode=0o700)
        try:
            _atomic_write(directory / "public.pem", serialize_public_key(public), 0o644)
            _atomic_write(
                directory / "metadata.json",
                (json.dumps(asdict(record), indent=2, sort_keys=True) + "\n").encode(),
                0o600,
            )
        except Exception:
            for path in directory.iterdir():
                path.unlink(missing_ok=True)
            directory.rmdir()
            raise
        return record

    def list(self) -> list[KeyRecord]:
        if not self.root.exists():
            return []
        records = []
        for path in sorted(self.root.glob("*/metadata.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                records.append(KeyRecord(**data))
            except (OSError, ValueError, TypeError) as exc:
                raise KeyManagementError(f"Invalid key metadata: {path}") from exc
        return records

    def public_key(self, identifier: str):
        from cryptosuite.keys.key_generator import load_public_key

        return load_public_key((self._record_path(identifier) / "public.pem").read_bytes())

    def private_key(self, identifier: str, password: str | bytes):
        path = self._record_path(identifier) / "private.pem"
        if not path.is_file():
            raise KeyManagementError("This record contains a public key only.")
        return load_private_key(path.read_bytes(), password)

    def export_public(self, identifier: str) -> bytes:
        return (self._record_path(identifier) / "public.pem").read_bytes()

    def export_private(self, identifier: str) -> bytes:
        """Return the already encrypted PKCS#8 representation for explicit export."""
        path = self._record_path(identifier) / "private.pem"
        if not path.is_file():
            raise KeyManagementError("This record contains a public key only.")
        return path.read_bytes()

    def info(self, identifier: str) -> KeyRecord:
        """Return validated metadata for one key."""
        path = self._record_path(identifier) / "metadata.json"
        try:
            return KeyRecord(**json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError) as exc:
            raise KeyManagementError(f"Invalid key metadata: {path}") from exc

    def change_password(
        self, identifier: str, old_password: str | bytes, new_password: str | bytes
    ) -> None:
        """Re-encrypt a stored private key under a new password."""
        directory = self._record_path(identifier)
        if not (directory / "private.pem").is_file():
            raise KeyManagementError("This record contains a public key only.")
        private = load_private_key((directory / "private.pem").read_bytes(), old_password)
        _atomic_write(
            directory / "private.pem", serialize_private_key(private, new_password), 0o600
        )

    def delete(self, identifier: str) -> None:
        """Delete one key record after validating its identifier."""
        directory = self._record_path(identifier)
        for name in ("private.pem", "public.pem", "metadata.json"):
            (directory / name).unlink(missing_ok=True)
        try:
            directory.rmdir()
        except OSError as exc:
            raise KeyManagementError(f"Unable to delete key: {identifier}") from exc

    def backup(self, identifier: str, destination: Path) -> Path:
        """Create a password-protected private-key backup without overwriting."""
        destination = Path(destination)
        if destination.exists() or destination.is_symlink():
            raise ValidationError(f"Backup destination already exists: {destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        data = self.export_private(identifier)
        _atomic_write(destination, data, 0o600)
        return destination

    def _record_path(self, identifier: str) -> Path:
        if not re.fullmatch(r"[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}", identifier):
            raise ValidationError("Invalid key identifier.")
        path = self.root / identifier
        if not path.is_dir():
            raise KeyManagementError(f"Unknown key: {identifier}")
        return path

    def _store_record(
        self, record: KeyRecord, private_key, password: str | bytes
    ) -> None:
        directory = self.root / record.id
        if directory.exists():
            raise KeyManagementError("A key with this identifier already exists.")
        directory.mkdir(parents=True, mode=0o700)
        try:
            _atomic_write(
                directory / "private.pem",
                serialize_private_key(private_key, password),
                0o600,
            )
            _atomic_write(
                directory / "public.pem",
                serialize_public_key(private_key.public_key()),
                0o644,
            )
            _atomic_write(
                directory / "metadata.json",
                (json.dumps(asdict(record), indent=2, sort_keys=True) + "\n").encode(),
                0o600,
            )
        except Exception:
            for path in directory.iterdir():
                path.unlink(missing_ok=True)
            directory.rmdir()
            raise


def _validate_name(name: str) -> None:
    if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
        raise ValidationError("Key name contains invalid characters or is too long.")


def _validate_purpose(algorithm: KeyAlgorithm, purpose: str) -> None:
    if purpose not in {"signing", "key-exchange", "encryption"}:
        raise ValidationError("Invalid key purpose.")
    if algorithm in {KeyAlgorithm.ED25519, KeyAlgorithm.EC_P256} and purpose != "signing":
        raise ValidationError(f"{algorithm.value} keys may only be used for signing.")
    if algorithm is KeyAlgorithm.X25519 and purpose != "key-exchange":
        raise ValidationError("X25519 keys may only be used for key exchange.")


def _atomic_write(target: Path, data: bytes, mode: int) -> None:
    descriptor, name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
