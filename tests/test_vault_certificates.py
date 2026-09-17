"""Tests for the encrypted vault and X.509 services."""

import pytest
from cryptography.hazmat.primitives import serialization

from cryptosuite.certificates import (
    generate_csr,
    generate_self_signed,
    inspect_certificate,
    load_certificate,
    validate_certificate,
)
from cryptosuite.core.kdf import Argon2idParameters
from cryptosuite.keys.key_generator import KeyAlgorithm, generate_private_key
from cryptosuite.utils.exceptions import (
    AuthenticationError,
    FileFormatError,
    VaultError,
)
from cryptosuite.vault import Vault

FAST_KDF = Argon2idParameters(time_cost=1, memory_cost_kib=8192, parallelism=1)


def test_vault_round_trip_and_no_plaintext_on_disk(tmp_path):
    path = tmp_path / "secrets.vault"
    vault = Vault(path, "master password")
    entry = vault.add("api-key", "Example", "super-secret-value")
    vault.save(FAST_KDF)
    raw = path.read_bytes()
    assert b"super-secret-value" not in raw
    reopened = Vault.open(path, "master password")
    assert reopened.list_entries() == (entry,)
    assert reopened.delete(entry.id)
    reopened.save(FAST_KDF)
    assert Vault.open(path, "master password").list_entries() == ()


def test_vault_wrong_password_and_tampering_fail(tmp_path):
    path = tmp_path / "secrets.vault"
    vault = Vault(path, "right")
    vault.add("note", "A note", "private")
    vault.save(FAST_KDF)
    with pytest.raises(AuthenticationError):
        Vault.open(path, "wrong")
    raw = bytearray(path.read_bytes())
    raw[-1] ^= 1
    path.write_bytes(raw)
    with pytest.raises((AuthenticationError, FileFormatError)):
        Vault.open(path, "right")


def test_vault_auto_lock_password_rotation_backup_and_file_entries(tmp_path, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("cryptosuite.vault.vault.time.monotonic", lambda: clock[0])
    path = tmp_path / "secrets.vault"
    vault = Vault(path, "old password", auto_lock_seconds=1.0)
    source = tmp_path / "small.bin"
    source.write_bytes(b"binary\x00content")
    entry = vault.add_file(source)
    vault.save(FAST_KDF)
    extracted = tmp_path / "extracted.bin"
    vault.extract_file(entry.id, extracted)
    assert extracted.read_bytes() == source.read_bytes()
    clock[0] = 2.0
    assert vault.is_locked
    with pytest.raises(VaultError, match="locked"):
        vault.list_entries()

    reopened = Vault.open(path, "old password")
    reopened.change_master_password("new password", FAST_KDF)
    backup = reopened.backup(tmp_path / "backup.vault")
    assert backup.read_bytes() == path.read_bytes()
    with pytest.raises(AuthenticationError):
        Vault.open(path, "old password")
    assert Vault.open(path, "new password").get(entry.id).name == "small.bin"


@pytest.mark.parametrize("algorithm", [KeyAlgorithm.ED25519, KeyAlgorithm.RSA_3072])
def test_certificate_and_csr_generation_and_inspection(algorithm):
    private = generate_private_key(algorithm)
    csr = generate_csr(private, "example.test", ["example.test", "www.example.test"])
    assert csr.is_signature_valid
    certificate = generate_self_signed(
        private, "example.test", days_valid=30, san_names=["example.test"]
    )
    pem = certificate.public_bytes(serialization.Encoding.PEM)
    loaded = load_certificate(pem)
    info = inspect_certificate(loaded)
    assert "CN=example.test" in info.subject
    assert info.subject == info.issuer
    assert info.san == ("example.test",)
    assert len(info.fingerprint_sha256.split(":")) == 32


def test_certificate_hostname_and_explicit_trust_validation():
    private = generate_private_key(KeyAlgorithm.ED25519)
    certificate = generate_self_signed(
        private, "example.test", san_names=["example.test", "*.service.test"]
    )
    valid = validate_certificate(
        certificate, trust_roots=[certificate], hostname="example.test"
    )
    assert valid.valid
    assert valid.chain_length == 1
    wildcard = validate_certificate(
        certificate, trust_roots=[certificate], hostname="api.service.test"
    )
    assert wildcard.valid
    wrong = validate_certificate(
        certificate, trust_roots=[certificate], hostname="other.test"
    )
    assert not wrong.valid
    assert "does not match" in wrong.errors[0]
    untrusted = validate_certificate(certificate)
    assert not untrusted.valid
    assert any("trust root" in error for error in untrusted.errors)
