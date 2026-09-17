"""Tests for key management, signatures, and hybrid encryption."""

from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization

from cryptosuite.core.asymmetric import (
    deserialize_envelope,
    hybrid_decrypt,
    hybrid_encrypt,
    serialize_envelope,
)
from cryptosuite.core.signatures import sign, verify
from cryptosuite.keys import KeyAlgorithm, KeyStore
from cryptosuite.keys.key_generator import (
    generate_private_key,
    load_private_key,
    public_fingerprint,
    serialize_private_key,
    serialize_public_key,
)
from cryptosuite.utils.exceptions import (
    AuthenticationError,
    KeyManagementError,
    ValidationError,
)


@pytest.mark.parametrize("algorithm", list(KeyAlgorithm))
def test_private_key_serialization_is_encrypted(algorithm):
    private = generate_private_key(algorithm)
    encoded = serialize_private_key(private, "protection password")
    assert b"ENCRYPTED PRIVATE KEY" in encoded
    loaded = load_private_key(encoded, "protection password")
    assert public_fingerprint(loaded.public_key()) == public_fingerprint(private.public_key())
    with pytest.raises(KeyManagementError):
        load_private_key(encoded, "wrong password")


def test_key_store_generates_lists_and_loads(tmp_path):
    store = KeyStore(tmp_path / "keys")
    record = store.generate("Alice Signing", KeyAlgorithm.ED25519, "signing", "password")
    assert store.list() == [record]
    assert store.export_public(record.id).startswith(b"-----BEGIN PUBLIC KEY-----")
    assert public_fingerprint(store.private_key(record.id, "password").public_key()) == record.fingerprint
    assert b"ENCRYPTED PRIVATE KEY" in (tmp_path / "keys" / record.id / "private.pem").read_bytes()


def test_key_purpose_separation(tmp_path):
    store = KeyStore(tmp_path)
    with pytest.raises(ValidationError, match="signing"):
        store.generate("Wrong", KeyAlgorithm.ED25519, "encryption", "password")
    with pytest.raises(ValidationError, match="exchange"):
        store.generate("Wrong", KeyAlgorithm.X25519, "signing", "password")


@pytest.mark.parametrize(
    "algorithm",
    [KeyAlgorithm.ED25519, KeyAlgorithm.EC_P256, KeyAlgorithm.RSA_3072],
)
def test_signature_round_trip_and_modified_document(algorithm):
    private = generate_private_key(algorithm)
    signature = sign(b"document", private)
    assert verify(b"document", signature, private.public_key())
    assert not verify(b"modified", signature, private.public_key())


def test_hybrid_multiple_recipients_and_serialization():
    alice = generate_private_key(KeyAlgorithm.X25519)
    bob = generate_private_key(KeyAlgorithm.RSA_3072)
    envelope = hybrid_encrypt(b"shared secret", [alice.public_key(), bob.public_key()])
    restored = deserialize_envelope(serialize_envelope(envelope))
    assert hybrid_decrypt(restored, alice) == b"shared secret"
    assert hybrid_decrypt(restored, bob) == b"shared secret"


def test_hybrid_wrong_recipient_and_tampering_fail():
    alice = generate_private_key(KeyAlgorithm.X25519)
    stranger = generate_private_key(KeyAlgorithm.X25519)
    envelope = hybrid_encrypt(b"secret", [alice.public_key()])
    with pytest.raises(AuthenticationError, match="not a recipient"):
        hybrid_decrypt(envelope, stranger)
    changed = envelope.ciphertext[:-1] + bytes([envelope.ciphertext[-1] ^ 1])
    with pytest.raises(AuthenticationError):
        hybrid_decrypt(replace(envelope, ciphertext=changed), alice)


def test_key_store_password_change_backup_and_delete(tmp_path):
    store = KeyStore(tmp_path / "keys")
    record = store.generate("Alice", KeyAlgorithm.ED25519, "signing", "old")
    store.change_password(record.id, "old", "new")
    assert store.private_key(record.id, "new")
    backup = store.backup(record.id, tmp_path / "backup.pem")
    assert b"ENCRYPTED PRIVATE KEY" in backup.read_bytes()
    store.delete(record.id)
    assert store.list() == []


def test_key_store_import_info_and_exports(tmp_path):
    original = generate_private_key(KeyAlgorithm.X25519)
    pem = serialize_private_key(original, "source password")
    store = KeyStore(tmp_path / "keys")
    record = store.import_private(
        "Imported exchange key",
        "key-exchange",
        pem,
        "source password",
        "storage password",
    )
    assert store.info(record.id) == record
    assert b"PUBLIC KEY" in store.export_public(record.id)
    assert b"ENCRYPTED PRIVATE KEY" in store.export_private(record.id)
    loaded = store.private_key(record.id, "storage password")
    assert public_fingerprint(loaded.public_key()) == record.fingerprint


def test_import_unencrypted_private_key_is_reprotected(tmp_path):
    private = generate_private_key(KeyAlgorithm.ED25519)
    unencrypted = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    store = KeyStore(tmp_path / "keys")
    record = store.import_private(
        "Legacy import", "signing", unencrypted, None, "new protection"
    )
    assert b"ENCRYPTED PRIVATE KEY" in store.export_private(record.id)


def test_import_public_only_key(tmp_path):
    private = generate_private_key(KeyAlgorithm.X25519)
    public_pem = serialize_public_key(private.public_key())
    store = KeyStore(tmp_path / "keys")
    record = store.import_public("Recipient", "key-exchange", public_pem)
    assert record.status == "public-only"
    assert store.export_public(record.id) == public_pem
    with pytest.raises(KeyManagementError, match="public key only"):
        store.export_private(record.id)
