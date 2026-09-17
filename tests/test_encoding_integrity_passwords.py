"""Tests for encoding, integrity, passwords, and measured benchmarks."""

import string

import pytest

from cryptosuite.core.benchmark import run_benchmark
from cryptosuite.core.encoding import Encoding, decode, encode
from cryptosuite.core.passwords import estimated_entropy_bits, generate_password
from cryptosuite.files.integrity import hash_file, verify_file_hash
from cryptosuite.lab.analysis import byte_distribution
from cryptosuite.utils.exceptions import ValidationError


@pytest.mark.parametrize("encoding", list(Encoding))
def test_encoding_round_trip(encoding):
    value = b"encoding is not encryption\x00\xff"
    assert decode(encode(value, encoding), encoding) == value


def test_invalid_encoding_is_rejected():
    with pytest.raises(ValidationError):
        decode("%%%", Encoding.BASE64)


def test_streaming_file_integrity(tmp_path):
    path = tmp_path / "data.bin"
    path.write_bytes(b"abc")
    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert hash_file(path) == expected
    assert verify_file_hash(path, expected.upper())
    assert not verify_file_hash(path, "00" * 32)


def test_password_generator_includes_selected_sets():
    password = generate_password(64)
    assert len(password) == 64
    assert any(char in string.ascii_uppercase for char in password)
    assert any(char in string.ascii_lowercase for char in password)
    assert any(char in string.digits for char in password)
    assert any(char not in string.ascii_letters + string.digits for char in password)
    assert estimated_entropy_bits(16, 2) == 16


def test_benchmark_measures_current_machine():
    results = run_benchmark(data_size=1024, rounds=1)
    assert len(results) == 5
    assert all(result.mebibytes_per_second > 0 for result in results)


def test_byte_distribution_covers_all_byte_values():
    distribution = byte_distribution(b"AAB")
    assert len(distribution) == 256
    assert distribution[ord("A")] == 2
    assert distribution[ord("B")] == 1
