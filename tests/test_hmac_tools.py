"""Known-answer and verification tests for HMAC."""

import pytest

from cryptosuite.core.hmac_tools import HMACAlgorithm, generate_hmac, verify_hmac
from cryptosuite.utils.exceptions import ValidationError


def test_hmac_sha256_rfc_4231_vector():
    key = bytes.fromhex("0b" * 20)
    tag = generate_hmac(key, b"Hi There", HMACAlgorithm.SHA256)
    assert tag.hex() == (
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    )
    assert verify_hmac(key, b"Hi There", tag, HMACAlgorithm.SHA256)


def test_hmac_verification_rejects_modified_data():
    key = b"a sufficiently long test key"
    tag = generate_hmac(key, b"message", HMACAlgorithm.SHA512)
    assert not verify_hmac(key, b"modified", tag, HMACAlgorithm.SHA512)


def test_hmac_rejects_invalid_inputs():
    with pytest.raises(ValidationError, match="non-empty"):
        generate_hmac(b"", b"data")
    with pytest.raises(ValidationError, match="Expected"):
        verify_hmac(b"key", b"data", "tag")  # type: ignore[arg-type]

