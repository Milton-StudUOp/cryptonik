"""Tests for Argon2id password-based key derivation."""

import pytest

from cryptosuite.core.kdf import Argon2idParameters, derive_key, generate_salt
from cryptosuite.utils.exceptions import ValidationError

TEST_PARAMETERS = Argon2idParameters(
    time_cost=1, memory_cost_kib=8_192, parallelism=1, key_length=32
)


def test_argon2id_is_deterministic_for_same_password_and_salt():
    salt = bytes(range(16))
    first = derive_key("correct horse battery staple", salt, TEST_PARAMETERS)
    second = derive_key("correct horse battery staple", salt, TEST_PARAMETERS)
    assert first == second
    assert len(first) == 32


def test_argon2id_changes_with_password_or_salt():
    salt = bytes(range(16))
    baseline = derive_key("password one", salt, TEST_PARAMETERS)
    assert derive_key("password two", salt, TEST_PARAMETERS) != baseline
    assert derive_key("password one", bytes(range(1, 17)), TEST_PARAMETERS) != baseline


def test_generated_salts_are_unique():
    first = generate_salt()
    second = generate_salt()
    assert len(first) == len(second) == 16
    assert first != second


@pytest.mark.parametrize(
    "parameters",
    [
        {"time_cost": 0},
        {"memory_cost_kib": 1024},
        {"parallelism": 0},
        {"key_length": 8},
    ],
)
def test_unsafe_argon2id_parameters_are_rejected(parameters):
    with pytest.raises(ValidationError):
        Argon2idParameters(**parameters)


def test_empty_password_and_short_salt_are_rejected():
    with pytest.raises(ValidationError, match="empty"):
        derive_key("", bytes(16), TEST_PARAMETERS)
    with pytest.raises(ValidationError, match="at least 16"):
        derive_key("password", bytes(15), TEST_PARAMETERS)

