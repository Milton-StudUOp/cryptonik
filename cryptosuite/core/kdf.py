"""Password-based key derivation using Argon2id."""

from __future__ import annotations

from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw

from cryptosuite.core.random_generator import random_bytes
from cryptosuite.utils.exceptions import ValidationError

MIN_SALT_LENGTH = 16
MAX_PASSWORD_LENGTH = 1024


@dataclass(frozen=True, slots=True)
class Argon2idParameters:
    """Validated Argon2id cost parameters.

    ``memory_cost_kib`` is expressed in KiB, as required by argon2-cffi.
    """

    time_cost: int = 3
    memory_cost_kib: int = 65_536
    parallelism: int = 4
    key_length: int = 32

    def __post_init__(self) -> None:
        _bounded_int("time_cost", self.time_cost, 1, 10)
        _bounded_int("memory_cost_kib", self.memory_cost_kib, 8_192, 262_144)
        _bounded_int("parallelism", self.parallelism, 1, 64)
        _bounded_int("key_length", self.key_length, 16, 64)
        if self.memory_cost_kib < 8 * self.parallelism:
            raise ValidationError(
                "Argon2id memory cost must be at least 8 KiB per parallel lane."
            )


def generate_salt(length: int = MIN_SALT_LENGTH) -> bytes:
    """Generate a new Argon2id salt. Salts are public and must be unique."""
    if isinstance(length, bool) or not isinstance(length, int):
        raise ValidationError("Salt length must be an integer.")
    if not MIN_SALT_LENGTH <= length <= 1024:
        raise ValidationError("Salt length must be between 16 and 1024 bytes.")
    return random_bytes(length)


def derive_key(
    password: str | bytes,
    salt: bytes,
    parameters: Argon2idParameters | None = None,
) -> bytes:
    """Derive a key from a password using Argon2id."""
    password_bytes = _password_bytes(password)
    if not isinstance(salt, bytes) or len(salt) < MIN_SALT_LENGTH:
        raise ValidationError("Argon2id salt must contain at least 16 bytes.")
    params = parameters or Argon2idParameters()
    if not isinstance(params, Argon2idParameters):
        raise ValidationError("Invalid Argon2id parameters.")
    return hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost_kib,
        parallelism=params.parallelism,
        hash_len=params.key_length,
        type=Type.ID,
        version=19,
    )


def _password_bytes(password: str | bytes) -> bytes:
    if isinstance(password, str):
        result = password.encode("utf-8")
    elif isinstance(password, bytes):
        result = password
    else:
        raise ValidationError("Password must be text or bytes.")
    if not result:
        raise ValidationError("Password must not be empty.")
    if len(result) > MAX_PASSWORD_LENGTH:
        raise ValidationError(
            f"Encoded password must not exceed {MAX_PASSWORD_LENGTH} bytes."
        )
    return result


def _bounded_int(name: str, value: int, minimum: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{name} must be an integer.")
    if not minimum <= value <= maximum:
        raise ValidationError(f"{name} must be between {minimum} and {maximum}.")
