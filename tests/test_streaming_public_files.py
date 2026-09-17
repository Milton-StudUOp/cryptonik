"""Streaming and tamper tests for hybrid files and detached signatures."""

import pytest

from cryptosuite.files.hybrid_file import (
    decrypt_file_for_recipient,
    encrypt_file_for_recipients,
)
from cryptosuite.files.signature_file import sign_file, verify_file
from cryptosuite.keys.key_generator import KeyAlgorithm, generate_private_key
from cryptosuite.utils.exceptions import AuthenticationError, FileFormatError


def test_streaming_hybrid_file_multiple_recipients(tmp_path):
    source = tmp_path / "large.bin"
    source.write_bytes(bytes(range(256)) * 9000)
    alice = generate_private_key(KeyAlgorithm.X25519)
    bob = generate_private_key(KeyAlgorithm.RSA_3072)
    encrypted = encrypt_file_for_recipients(
        source,
        [alice.public_key(), bob.public_key()],
        chunk_size=64 * 1024,
    )
    for name, private in (("alice.bin", alice), ("bob.bin", bob)):
        output = tmp_path / name
        decrypt_file_for_recipient(encrypted, private, output)
        assert output.read_bytes() == source.read_bytes()


def test_hybrid_file_tampering_never_publishes_plaintext(tmp_path):
    source = tmp_path / "input.bin"
    source.write_bytes(b"secret" * 20_000)
    recipient = generate_private_key(KeyAlgorithm.X25519)
    encrypted = encrypt_file_for_recipients(source, [recipient.public_key()])
    data = bytearray(encrypted.read_bytes())
    data[-1] ^= 1
    encrypted.write_bytes(data)
    output = tmp_path / "output.bin"
    with pytest.raises(AuthenticationError):
        decrypt_file_for_recipient(encrypted, recipient, output)
    assert not output.exists()


@pytest.mark.parametrize(
    "algorithm",
    [KeyAlgorithm.ED25519, KeyAlgorithm.EC_P256, KeyAlgorithm.RSA_3072],
)
def test_streaming_detached_signature(algorithm, tmp_path):
    document = tmp_path / "document.bin"
    document.write_bytes(bytes(range(256)) * 9000)
    private = generate_private_key(algorithm)
    signature = sign_file(document, private)
    assert verify_file(document, signature, private.public_key())
    with document.open("r+b") as handle:
        handle.seek(-1, 2)
        handle.write(b"X")
    assert not verify_file(document, signature, private.public_key())


def test_signature_file_tampering_is_rejected(tmp_path):
    document = tmp_path / "document.txt"
    document.write_text("document", encoding="utf-8")
    private = generate_private_key(KeyAlgorithm.ED25519)
    signature = sign_file(document, private)
    signature.write_bytes(b"truncated")
    with pytest.raises(FileFormatError):
        verify_file(document, signature, private.public_key())
