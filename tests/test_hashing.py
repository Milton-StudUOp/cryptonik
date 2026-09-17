"""Known-answer and validation tests for hashing."""

import pytest

from cryptosuite.core.hashing import HashAlgorithm, compare_hashes, digest, hexdigest
from cryptosuite.utils.exceptions import ValidationError


@pytest.mark.parametrize(
    ("algorithm", "expected"),
    [
        (
            HashAlgorithm.SHA256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            HashAlgorithm.SHA512,
            (
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            ),
        ),
        (
            HashAlgorithm.BLAKE2B,
            (
                "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
            ),
        ),
        (
            HashAlgorithm.BLAKE2S,
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
        ),
    ],
)
def test_known_answer_for_abc(algorithm, expected):
    assert hexdigest(b"abc", algorithm) == expected
    assert digest(b"abc", algorithm).hex() == expected


def test_hash_rejects_text_and_unknown_algorithm():
    with pytest.raises(ValidationError, match="bytes"):
        digest("abc")  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="Unsupported"):
        digest(b"abc", "md5")  # type: ignore[arg-type]


def test_hash_comparison_is_case_insensitive_and_validated():
    assert compare_hashes("A0B1", "a0b1")
    assert not compare_hashes("a0b1", "a0b2")
    with pytest.raises(ValidationError, match="hexadecimal"):
        compare_hashes("not-a-hash", "a0b1")
