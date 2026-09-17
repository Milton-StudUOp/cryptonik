"""Small local vault encrypted as one authenticated document."""

from __future__ import annotations

import base64
import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptosuite.core.kdf import Argon2idParameters, derive_key, generate_salt
from cryptosuite.core.symmetric import (
    EncryptedData,
    SymmetricAlgorithm,
    decrypt,
    encrypt,
)
from cryptosuite.utils.exceptions import FileFormatError, ValidationError, VaultError
from cryptosuite.utils.secure_io import atomic_write_bytes

MAGIC = b"CRYPTVAULT\x01"
MAX_VAULT_SIZE = 32 * 1024 * 1024
MAX_ENTRIES = 10_000


@dataclass(frozen=True, slots=True)
class VaultEntry:
    id: str
    kind: str
    name: str
    value: str
    updated: str


class Vault:
    """Unlocked in-memory vault; callers should discard it to lock."""

    def __init__(
        self,
        path: Path,
        password: str | bytes,
        entries: list[VaultEntry] | None = None,
        *,
        auto_lock_seconds: float | None = None,
    ):
        self.path = Path(path)
        self._password = password
        self._entries = entries or []
        if auto_lock_seconds is not None and auto_lock_seconds <= 0:
            raise ValidationError("Auto-lock timeout must be positive.")
        self._auto_lock_seconds = auto_lock_seconds
        self._last_access = time.monotonic()
        self._locked = False

    @classmethod
    def create(
        cls,
        path: Path,
        password: str | bytes,
        *,
        auto_lock_seconds: float | None = None,
    ) -> Vault:
        vault = cls(path, password, auto_lock_seconds=auto_lock_seconds)
        vault.save()
        return vault

    @classmethod
    def open(
        cls,
        path: Path,
        password: str | bytes,
        *,
        auto_lock_seconds: float | None = None,
    ) -> Vault:
        path = Path(path)
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise VaultError(f"Unable to read vault: {path}") from exc
        if len(raw) > MAX_VAULT_SIZE or not raw.startswith(MAGIC):
            raise FileFormatError("Invalid or oversized vault file.")
        try:
            container = json.loads(raw[len(MAGIC) :].decode("ascii"))
            params = Argon2idParameters(**container["kdf"])
            salt = _decode(container["salt"])
            nonce = _decode(container["nonce"])
            ciphertext = _decode(container["ciphertext"])
            key = derive_key(password, salt, params)
            plaintext = decrypt(
                EncryptedData(SymmetricAlgorithm.XCHACHA20_POLY1305, nonce, ciphertext),
                key,
                associated_data=MAGIC,
            )
            payload = json.loads(plaintext.decode("utf-8"))
            if payload.get("version") != 1 or len(payload["entries"]) > MAX_ENTRIES:
                raise ValueError
            entries = [VaultEntry(**item) for item in payload["entries"]]
            return cls(
                path,
                password,
                entries,
                auto_lock_seconds=auto_lock_seconds,
            )
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise FileFormatError("Malformed vault file.") from exc

    def list_entries(self) -> tuple[VaultEntry, ...]:
        self._ensure_unlocked()
        return tuple(self._entries)

    @property
    def is_locked(self) -> bool:
        """Return whether the vault is manually or automatically locked."""
        if (
            not self._locked
            and self._auto_lock_seconds is not None
            and time.monotonic() - self._last_access >= self._auto_lock_seconds
        ):
            self.lock()
        return self._locked

    def lock(self) -> None:
        """Forget the in-memory password and prevent further operations."""
        self._password = b""
        self._locked = True

    def get(self, identifier: str) -> VaultEntry:
        """Return one entry by opaque identifier."""
        self._ensure_unlocked()
        for entry in self._entries:
            if entry.id == identifier:
                return entry
        raise VaultError(f"Unknown vault entry: {identifier}")

    def add(self, kind: str, name: str, value: str) -> VaultEntry:
        self._ensure_unlocked()
        if kind not in {"note", "password", "api-key", "token", "key", "small-file"}:
            raise ValidationError("Invalid vault entry kind.")
        if not isinstance(name, str) or not name.strip() or len(name) > 128:
            raise ValidationError("Vault entry name must contain 1 to 128 characters.")
        if not isinstance(value, str) or len(value.encode("utf-8")) > 8 * 1024 * 1024:
            raise ValidationError("Vault entry value is invalid or too large.")
        if len(self._entries) >= MAX_ENTRIES:
            raise VaultError("Vault entry limit reached.")
        entry = VaultEntry(
            id=os.urandom(16).hex(),
            kind=kind,
            name=name,
            value=value,
            updated=datetime.now(UTC).isoformat(),
        )
        self._entries.append(entry)
        return entry

    def add_file(self, path: Path, name: str | None = None) -> VaultEntry:
        """Store a small file as authenticated Base64 content."""
        self._ensure_unlocked()
        path = Path(path)
        if not path.is_file() or path.is_symlink():
            raise ValidationError(f"Path must be a regular, non-symlink file: {path}")
        if path.stat().st_size > 8 * 1024 * 1024:
            raise ValidationError("Vault file entries are limited to 8 MiB.")
        try:
            encoded = base64.b64encode(path.read_bytes()).decode("ascii")
        except OSError as exc:
            raise VaultError(f"Unable to read vault input file: {path}") from exc
        return self.add("small-file", name or path.name, encoded)

    def extract_file(
        self, identifier: str, destination: Path, *, overwrite: bool = False
    ) -> Path:
        """Atomically extract one small-file entry."""
        entry = self.get(identifier)
        if entry.kind != "small-file":
            raise VaultError("Vault entry is not a file.")
        try:
            data = base64.b64decode(entry.value, validate=True)
        except ValueError as exc:
            raise VaultError("Stored vault file is malformed.") from exc
        return atomic_write_bytes(destination, data, overwrite=overwrite)

    def delete(self, identifier: str) -> bool:
        self._ensure_unlocked()
        before = len(self._entries)
        self._entries = [entry for entry in self._entries if entry.id != identifier]
        return len(self._entries) != before

    def save(self, parameters: Argon2idParameters | None = None) -> None:
        self._ensure_unlocked()
        params = parameters or Argon2idParameters()
        payload = json.dumps(
            {"entries": [asdict(item) for item in self._entries], "version": 1},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(payload) > MAX_VAULT_SIZE:
            raise VaultError("Vault is too large.")
        salt = generate_salt()
        key = derive_key(self._password, salt, params)
        sealed = encrypt(
            payload,
            key,
            SymmetricAlgorithm.XCHACHA20_POLY1305,
            associated_data=MAGIC,
        )
        container = {
            "ciphertext": _encode(sealed.ciphertext),
            "kdf": asdict(params),
            "nonce": _encode(sealed.nonce),
            "salt": _encode(salt),
        }
        encoded = MAGIC + json.dumps(container, sort_keys=True, separators=(",", ":")).encode("ascii")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)

    def change_master_password(
        self,
        new_password: str | bytes,
        parameters: Argon2idParameters | None = None,
    ) -> None:
        """Re-encrypt the vault using a new master password and fresh salt."""
        self._ensure_unlocked()
        if not new_password:
            raise ValidationError("New master password must not be empty.")
        old_password = self._password
        self._password = new_password
        try:
            self.save(parameters)
        except Exception:
            self._password = old_password
            raise

    def backup(self, destination: Path) -> Path:
        """Atomically copy the encrypted vault without exposing its contents."""
        self._ensure_unlocked()
        try:
            data = self.path.read_bytes()
        except OSError as exc:
            raise VaultError(f"Unable to read vault for backup: {self.path}") from exc
        return atomic_write_bytes(destination, data, mode=0o600)

    def _ensure_unlocked(self) -> None:
        if self.is_locked:
            raise VaultError("Vault is locked. Reopen it with the master password.")
        self._last_access = time.monotonic()


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: str) -> bytes:
    return base64.b64decode(value, validate=True)
