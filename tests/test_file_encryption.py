"""Security and streaming tests for CRYPTX file encryption."""


import pytest

from cryptosuite.core.kdf import Argon2idParameters
from cryptosuite.core.symmetric import SymmetricAlgorithm
from cryptosuite.files import decrypt_file, encrypt_file
from cryptosuite.files.file_format import PREFIX
from cryptosuite.files.secure_delete import best_effort_secure_delete
from cryptosuite.utils.exceptions import (
    AuthenticationError,
    FileFormatError,
    ValidationError,
)

FAST_KDF = Argon2idParameters(
    time_cost=1, memory_cost_kib=8_192, parallelism=1, key_length=32
)


@pytest.mark.parametrize("algorithm", list(SymmetricAlgorithm))
@pytest.mark.parametrize(
    "content",
    [b"", b"hello", bytes(range(256)) * 600],
    ids=["empty", "text", "multichunk-binary"],
)
def test_file_round_trip(tmp_path, algorithm, content):
    source = tmp_path / "input.bin"
    encrypted = tmp_path / "input.bin.cryptx"
    restored = tmp_path / "restored.bin"
    source.write_bytes(content)
    result = encrypt_file(
        source,
        "strong test password",
        encrypted,
        algorithm=algorithm,
        kdf_parameters=FAST_KDF,
        chunk_size=64 * 1024,
    )
    assert result == encrypted
    assert encrypted.read_bytes().startswith(b"CRYPTX\x01")
    assert decrypt_file(encrypted, "strong test password", restored) == restored
    assert restored.read_bytes() == content


def test_progress_reports_processed_plaintext(tmp_path):
    source = tmp_path / "input.bin"
    source.write_bytes(b"x" * 100_000)
    updates = []
    encrypted = encrypt_file(
        source,
        "password",
        kdf_parameters=FAST_KDF,
        chunk_size=64 * 1024,
        progress=lambda done, total: updates.append((done, total)),
    )
    assert updates[-1] == (100_000, 100_000)
    decrypt_updates = []
    decrypt_file(
        encrypted,
        "password",
        tmp_path / "output.bin",
        progress=lambda done, total: decrypt_updates.append((done, total)),
    )
    assert decrypt_updates[-1] == (100_000, 100_000)


def test_wrong_password_does_not_publish_plaintext(tmp_path):
    source = tmp_path / "input.txt"
    source.write_text("secret", encoding="utf-8")
    encrypted = encrypt_file(source, "right", kdf_parameters=FAST_KDF)
    output = tmp_path / "output.txt"
    with pytest.raises(AuthenticationError):
        decrypt_file(encrypted, "wrong", output)
    assert not output.exists()


def test_modified_ciphertext_does_not_publish_plaintext(tmp_path):
    source = tmp_path / "input.bin"
    source.write_bytes(b"secret" * 20_000)
    encrypted = encrypt_file(source, "password", kdf_parameters=FAST_KDF)
    data = bytearray(encrypted.read_bytes())
    data[-1] ^= 1
    encrypted.write_bytes(data)
    output = tmp_path / "output.bin"
    with pytest.raises(AuthenticationError):
        decrypt_file(encrypted, "password", output)
    assert not output.exists()


@pytest.mark.parametrize("cut", [0, 3, PREFIX.size, -1, -10])
def test_truncated_files_are_rejected(tmp_path, cut):
    source = tmp_path / "input.bin"
    source.write_bytes(b"secret content")
    encrypted = encrypt_file(source, "password", kdf_parameters=FAST_KDF)
    data = encrypted.read_bytes()
    encrypted.write_bytes(data[:cut])
    output = tmp_path / "output.bin"
    with pytest.raises((FileFormatError, AuthenticationError)):
        decrypt_file(encrypted, "password", output)
    assert not output.exists()


def test_unknown_version_and_trailing_data_are_rejected(tmp_path):
    source = tmp_path / "input.bin"
    source.write_bytes(b"content")
    encrypted = encrypt_file(source, "password", kdf_parameters=FAST_KDF)
    original = encrypted.read_bytes()
    version_changed = bytearray(original)
    version_changed[6] = 99
    encrypted.write_bytes(version_changed)
    with pytest.raises(FileFormatError, match="version"):
        decrypt_file(encrypted, "password", tmp_path / "version.bin")
    encrypted.write_bytes(original + b"trailing")
    with pytest.raises(FileFormatError, match="trailing"):
        decrypt_file(encrypted, "password", tmp_path / "trailing.bin")


def test_existing_output_is_never_overwritten_implicitly(tmp_path):
    source = tmp_path / "input.bin"
    source.write_bytes(b"source")
    destination = tmp_path / "output.cryptx"
    destination.write_bytes(b"existing")
    with pytest.raises(ValidationError, match="exists"):
        encrypt_file(source, "password", destination, kdf_parameters=FAST_KDF)
    assert destination.read_bytes() == b"existing"


def test_symlink_source_is_rejected_when_supported(tmp_path):
    source = tmp_path / "input.bin"
    source.write_bytes(b"source")
    link = tmp_path / "link.bin"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("Creating symlinks is not permitted on this system")
    with pytest.raises(ValidationError, match="non-symlink"):
        encrypt_file(link, "password", kdf_parameters=FAST_KDF)


def test_large_multichunk_file_round_trip(tmp_path):
    source = tmp_path / "large.bin"
    block = bytes(range(256)) * 4096
    with source.open("wb") as handle:
        for _ in range(12):
            handle.write(block)
    encrypted = encrypt_file(
        source,
        "large file password",
        kdf_parameters=FAST_KDF,
        chunk_size=64 * 1024,
    )
    output = tmp_path / "large-restored.bin"
    decrypt_file(encrypted, "large file password", output)
    assert output.read_bytes() == source.read_bytes()


def test_best_effort_secure_delete_removes_regular_file(tmp_path):
    target = tmp_path / "delete-me.bin"
    target.write_bytes(b"sensitive" * 1000)
    best_effort_secure_delete(target)
    assert not target.exists()
