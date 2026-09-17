"""Round-trip and tamper-resistance tests for authenticated encryption."""

from dataclasses import replace

import pytest

from cryptosuite.core.symmetric import (
    NONCE_LENGTHS,
    EncryptedData,
    SymmetricAlgorithm,
    decrypt,
    encrypt,
    generate_key,
)
from cryptosuite.utils.exceptions import AuthenticationError, ValidationError


@pytest.mark.parametrize("algorithm", list(SymmetricAlgorithm))
@pytest.mark.parametrize("plaintext", [b"", b"hello\x00world", bytes(range(256))])
def test_authenticated_encryption_round_trip(algorithm, plaintext):
    key = generate_key()
    encrypted = encrypt(plaintext, key, algorithm, associated_data=b"metadata")
    assert encrypted.algorithm is algorithm
    assert len(encrypted.nonce) == NONCE_LENGTHS[algorithm]
    assert encrypted.ciphertext != plaintext
    assert decrypt(encrypted, key, associated_data=b"metadata") == plaintext


@pytest.mark.parametrize("algorithm", list(SymmetricAlgorithm))
def test_modified_ciphertext_fails_authentication(algorithm):
    key = generate_key()
    encrypted = encrypt(b"sensitive content", key, algorithm)
    corrupted = encrypted.ciphertext[:-1] + bytes([encrypted.ciphertext[-1] ^ 1])
    with pytest.raises(AuthenticationError):
        decrypt(replace(encrypted, ciphertext=corrupted), key)


@pytest.mark.parametrize("algorithm", list(SymmetricAlgorithm))
def test_wrong_key_fails_authentication(algorithm):
    encrypted = encrypt(b"sensitive content", generate_key(), algorithm)
    with pytest.raises(AuthenticationError):
        decrypt(encrypted, generate_key())


@pytest.mark.parametrize("algorithm", list(SymmetricAlgorithm))
def test_modified_associated_data_fails_authentication(algorithm):
    key = generate_key()
    encrypted = encrypt(b"content", key, algorithm, associated_data=b"header")
    with pytest.raises(AuthenticationError):
        decrypt(encrypted, key, associated_data=b"changed")


def test_explicit_nonce_is_supported_and_validated():
    key = generate_key()
    nonce = bytes(12)
    encrypted = encrypt(b"data", key, nonce=nonce)
    assert encrypted.nonce == nonce
    with pytest.raises(ValidationError, match="Nonce"):
        encrypt(b"data", key, nonce=bytes(11))
    with pytest.raises(ValidationError, match="Nonce"):
        encrypt(b"data", key, nonce=b"")


def test_invalid_keys_and_structures_are_rejected():
    with pytest.raises(ValidationError, match="32 bytes"):
        encrypt(b"data", bytes(16))
    with pytest.raises(ValidationError, match="EncryptedData"):
        decrypt(b"ciphertext", generate_key())  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="Unsupported"):
        encrypt(b"data", generate_key(), "aes-ecb")  # type: ignore[arg-type]


def test_encrypted_data_rejects_truncated_tag_during_decryption():
    key = generate_key()
    encrypted = encrypt(b"data", key)
    truncated = EncryptedData(
        encrypted.algorithm, encrypted.nonce, encrypted.ciphertext[:-8]
    )
    with pytest.raises(AuthenticationError):
        decrypt(truncated, key)
