"""Tests for CSPRNG helpers."""

import pytest

from cryptosuite.core.random_generator import (
    random_base64,
    random_bytes,
    random_hex,
    random_urlsafe,
    random_uuid,
)
from cryptosuite.utils.exceptions import ValidationError


def test_random_bytes_have_requested_length_and_differ():
    first = random_bytes(32)
    second = random_bytes(32)
    assert len(first) == 32
    assert len(second) == 32
    assert first != second


def test_encoded_random_values():
    assert len(random_hex(16)) == 32
    assert len(random_urlsafe(16)) >= 16
    assert len(random_base64(16)) == 24
    assert random_uuid()[14] == "4"


@pytest.mark.parametrize("length", [0, -1, True, 1_048_577])
def test_invalid_random_length_is_rejected(length):
    with pytest.raises(ValidationError):
        random_bytes(length)
