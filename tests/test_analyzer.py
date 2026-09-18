"""Tests for conservative ciphertext and format identification."""

import base64
import datetime
import json

import pytest
from cryptography import x509 as x509_mod
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    pkcs12,
)

from cryptosuite.core.analyzer import (
    MAX_ANALYSIS_BYTES,
    analyze_bytes,
    analyze_text,
)
from cryptosuite.utils.exceptions import ValidationError


def _kinds(value: str) -> set[str]:
    return {candidate.kind for candidate in analyze_text(value).candidates}


def test_identifies_cryptonik_text_token():
    document = {
        "ciphertext": base64.b64encode(b"ciphertext").decode(),
        "nonce": base64.b64encode(b"nonce").decode(),
        "salt": base64.b64encode(b"salt").decode(),
        "version": 1,
    }
    token = base64.urlsafe_b64encode(json.dumps(document).encode()).decode()
    assert "Cryptonik encrypted text token" in _kinds(token)


def test_identifies_cryptx_inside_base64():
    encoded = base64.b64encode(b"CRYPTX\x01payload").decode()
    assert "Cryptonik CRYPTX container" in _kinds(encoded)


def test_identifies_raw_cryptx_file_data():
    result = analyze_bytes(b"CRYPTX\x01payload")
    assert any(item.kind == "Cryptonik CRYPTX container" for item in result.candidates)


def test_openssl_salted_header_precedes_statistical_analysis():
    raw = b"Salted__" + b"12345678" + bytes(range(31))
    result = analyze_text(base64.b64encode(raw).decode())
    assert [item.kind for item in result.candidates[:2]] == [
        "Base64 encoding",
        "OpenSSL salted format",
    ]
    assert result.container is not None
    assert result.container.format == "OpenSSL enc-compatible salted container"
    assert result.container.header == '8 bytes ("Salted__")'
    assert result.container.salt == "present (8 bytes)"
    assert result.cipher == "Unknown"
    assert result.kdf == "Unknown"
    # Entropy is displayed but the assessment warns about small sample.
    assert "Sample too small" in result.statistical_note
    assert not any(
        item.kind == "Binary/randomness characteristics"
        for item in result.candidates
    )


@pytest.mark.parametrize(
    ("data", "kind"),
    [
        (b"PK\x03\x04payload", "ZIP archive"),
        (b"%PDF-1.7\n", "PDF document"),
        (b"\x89PNG\r\n\x1a\npayload", "PNG image"),
        (b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA", "OpenSSH Ed25519 public key"),
        (b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----", "Public key (PEM)"),
    ],
)
def test_known_signatures_are_identified(data, kind):
    result = analyze_bytes(data)
    assert result.candidates[0].kind == kind


def test_binary_analysis_has_a_safety_limit():
    with pytest.raises(ValidationError, match="safety limit"):
        analyze_bytes(b"x" * (MAX_ANALYSIS_BYTES + 1))


def test_hash_length_is_only_a_low_confidence_candidate():
    result = analyze_text("a" * 64)
    candidate = next(
        item for item in result.candidates if item.kind == "hash/HMAC-sized value"
    )
    assert candidate.confidence == "low"
    assert "not proof" in candidate.evidence


def test_jwt_header_is_identified():
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(b'{"sub":"123"}').decode().rstrip("=")
    assert "JSON Web Token (JWT)" in _kinds(f"{header}.{payload}.signature")


def test_empty_analysis_is_rejected():
    with pytest.raises(ValidationError, match="empty"):
        analyze_text("  ")


@pytest.mark.parametrize(
    "value",
    [
        "01110011 01101111 01110101 00100000 01100010 01101111 01101110 01101001 01110100 01101111",
        "73 6f 75 20 62 6f 6e 69 74 6f",
    ],
)
def test_byte_group_representations_take_priority_over_base64(value):
    result = analyze_text(value)
    assert result.decoded_text == "sou bonito"
    assert result.candidates[0].kind != "Base64 encoding"


def test_base64_result_is_analyzed_as_utf8_text():
    result = analyze_text("c291IGJvbml0bw==")
    assert result.candidates[0].kind == "Base64 encoding"
    assert result.decoded_text == "sou bonito"
    assert result.decode_layers == ("Base64", "UTF-8 text")


def test_nested_base64_is_decoded_with_a_depth_bound():
    inner = base64.b64encode(b"sou bonito")
    outer = base64.b64encode(inner).decode()
    result = analyze_text(outer)
    assert result.decoded_text == "sou bonito"
    assert result.decode_layers == (
        "Base64",
        "UTF-8 text",
        "Base64",
        "UTF-8 text",
    )


def test_recursive_decode_does_not_reinterpret_plain_hex_like_text():
    result = analyze_text("313233313233")
    assert result.decoded_text == "123123"
    assert result.decode_layers == ("Hexadecimal", "UTF-8 text")


def test_morse_is_decoded_and_not_treated_as_encryption():
    result = analyze_text("... --- ..- / -... --- -. .. - ---")
    assert result.candidates[0].kind == "Morse code"
    assert result.decoded_text == "SOU BONITO"


def test_dot_separated_segments_are_independently_classified():
    result = analyze_text(
        "cWVyMTIzNTRhbmRm.Ym9uaXRvMTIzNDU2.dGFnMTIzNDU2Nzg="
    )
    assert result.structure is not None
    assert len(result.structure.segments) == 3
    assert result.structure.recognized_standard == "None confirmed"
    assert all(seg.representation == "Base64" for seg in result.structure.segments)


def test_dot_separated_segments_expose_decoded_values():
    result = analyze_text(
        "Zmx1Z2U0Y2g3ag==.b2xhIG1ldQ==.YXV0aHRhZzEyMw=="
    )
    assert result.structure is not None
    assert tuple(segment.value for segment in result.structure.segments) == (
        "fluge4ch7j",
        "ola meu",
        "authtag123",
    )
    assert result.structure.recognized_standard == "None confirmed"


def test_dot_separated_hex_is_not_claimed_as_a_known_standard():
    result = analyze_text("deadbeef.01234567.cafebabe")
    assert result.structure is not None
    assert all(seg.representation == "Hexadecimal" for seg in result.structure.segments)
    assert all(seg.confidence == "certain" for seg in result.structure.segments)
    assert result.structure.recognized_standard == "None confirmed"


def test_classical_cipher_like_text_gets_only_low_confidence_suggestions():
    result = analyze_text("sqv cpniup")
    candidate = next(
        item for item in result.candidates if item.kind == "possible classical-cipher text"
    )
    assert candidate.confidence == "low"
    assert "Crypto Lab" in result.suggestions[-1]


# ── Improvement 1: Recursive segment analysis ──


def test_segment_recursive_decode_shows_decode_path():
    """Nested Base64 within a dot-separated segment exposes decode_path."""
    inner = base64.b64encode(b"hello").decode()
    outer = base64.b64encode(inner.encode()).decode()
    result = analyze_text(f"{outer}.{base64.b64encode(b'world').decode()}")
    assert result.structure is not None
    seg = result.structure.segments[0]
    assert seg.representation == "Base64"
    assert seg.value is not None
    assert "hello" in seg.value
    assert len(seg.decode_path) > 2  # At least Base64 -> UTF-8 text -> Base64 -> UTF-8 text


# ── Improvement 2 & 3: Entropy presentation ──


def test_tiny_sample_entropy_is_suppressed():
    """For a 1-byte input, entropy_bits_per_byte should be None."""
    result = analyze_text("1")
    assert result.entropy_bits_per_byte is None
    assert "too small" in result.statistical_note


def test_small_sample_entropy_shows_sample_limited_maximum():
    """For 16–255 byte samples, sample_limited_max_entropy is set."""
    # 20 distinct hex bytes → 40 chars → 20 bytes decoded
    raw = bytes(range(20))
    encoded = base64.b64encode(raw).decode()
    result = analyze_text(encoded)
    assert result.decoded_bytes is not None
    if 16 <= result.decoded_bytes < 256:
        assert result.sample_limited_max_entropy is not None
        assert result.sample_limited_max_entropy <= 8.0
        assert "Sample too small" in result.statistical_note


def test_large_sample_entropy_has_full_assessment():
    """For samples ≥ 256 bytes, entropy gets a full statistical assessment."""
    data = bytes(range(256)) * 2
    result = analyze_bytes(data)
    assert result.entropy_bits_per_byte is not None
    assert result.sample_limited_max_entropy == 8.0
    assert "Statistical characteristics" in result.statistical_note or "bits/byte" in result.statistical_note


# ── Improvement 4: Cryptographic format intelligence ──


def test_ssh_rsa_public_key_is_identified():
    result = analyze_bytes(b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDuser@host")
    assert any(item.kind == "OpenSSH RSA public key" for item in result.candidates)
    assert result.container is not None
    assert result.container.format == "OpenSSH public-key record"


def test_pgp_message_is_distinguished_from_pem():
    data = b"-----BEGIN PGP MESSAGE-----\nABCDEFG\n-----END PGP MESSAGE-----"
    result = analyze_bytes(data)
    assert result.candidates[0].kind == "OpenPGP encrypted message"
    assert result.container is not None
    assert result.container.format == "OpenPGP ASCII armor (message)"


def test_pgp_public_key_block_is_identified():
    data = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nABCD\n-----END PGP PUBLIC KEY BLOCK-----"
    result = analyze_bytes(data)
    assert result.candidates[0].kind == "OpenPGP public key block"
    assert result.container is not None
    assert "OpenPGP" in result.container.format


def test_pem_certificate_is_specifically_classified():
    data = b"-----BEGIN CERTIFICATE-----\nMIIBmjCC\n-----END CERTIFICATE-----"
    result = analyze_bytes(data)
    assert result.candidates[0].kind == "X.509 certificate (PEM)"
    assert result.container is not None
    assert result.container.format == "PEM-encoded certificate"


def test_pem_private_key_is_specifically_classified():
    data = b"-----BEGIN PRIVATE KEY-----\nMIIBmjCC\n-----END PRIVATE KEY-----"
    result = analyze_bytes(data)
    assert result.candidates[0].kind == "Private key PKCS#8 (PEM)"
    assert result.container is not None
    assert result.container.format == "PEM-encoded private key"


def test_pem_encrypted_private_key_is_identified():
    data = b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIBmjCC\n-----END ENCRYPTED PRIVATE KEY-----"
    result = analyze_bytes(data)
    assert result.candidates[0].kind == "Encrypted private key PKCS#8 (PEM)"
    assert result.container is not None
    assert result.container.format == "PEM-encoded encrypted private key"


def test_openssl_salted_container_has_ciphertext_metadata():
    raw = b"Salted__" + b"12345678" + b"X" * 64
    result = analyze_bytes(raw)
    assert any("Ciphertext body" in meta for meta in result.cryptographic_metadata)
    assert any("Salted__" in meta for meta in result.cryptographic_metadata)


def test_is_crypto_container_returns_false_for_json():
    result = analyze_bytes(b'{"key": "value"}')
    assert result.cipher is None
    assert result.kdf is None


def test_is_crypto_container_returns_true_for_openssl():
    raw = b"Salted__" + b"12345678" + b"X" * 32
    result = analyze_bytes(raw)
    assert result.cipher == "Unknown"
    assert result.kdf == "Unknown"


def test_der_x509_detection():
    """A real DER-encoded X.509 self-signed certificate should be identified."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509_mod.Name([
        x509_mod.NameAttribute(x509_mod.oid.NameOID.COMMON_NAME, "test"),
    ])
    cert = (
        x509_mod.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509_mod.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(Encoding.DER)
    result = analyze_bytes(der)
    assert any("X.509 certificate (DER)" in c.kind for c in result.candidates)
    assert result.container is not None
    assert result.container.format == "DER-encoded X.509 certificate"
    assert any("Public key algorithm" in m for m in result.cryptographic_metadata)


def test_der_pkcs8_private_key_and_subject_public_key_are_distinguished():
    key = ec.generate_private_key(ec.SECP256R1())
    private_der = key.private_bytes(
        Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
    )
    public_der = key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    private_result = analyze_bytes(private_der)
    public_result = analyze_bytes(public_der)
    assert private_result.container is not None
    assert private_result.container.format == "DER-encoded PKCS#8 private key"
    assert public_result.container is not None
    assert public_result.container.format == "DER-encoded SubjectPublicKeyInfo"


def test_encrypted_der_pkcs8_is_identified_without_a_password():
    key = ec.generate_private_key(ec.SECP256R1())
    encrypted = key.private_bytes(
        Encoding.DER,
        PrivateFormat.PKCS8,
        BestAvailableEncryption(b"test-password"),
    )
    result = analyze_bytes(encrypted)
    assert result.container is not None
    assert result.container.format == "DER-encoded encrypted PKCS#8 private key"
    assert any("password" in item.casefold() for item in result.cryptographic_metadata)


def test_unencrypted_pkcs12_is_parsed_as_a_real_container():
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509_mod.Name(
        [x509_mod.NameAttribute(x509_mod.oid.NameOID.COMMON_NAME, "pkcs12.test")]
    )
    cert = (
        x509_mod.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509_mod.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
        )
        .sign(key, hashes.SHA256())
    )
    pfx = pkcs12.serialize_key_and_certificates(
        b"cryptonik", key, cert, None, NoEncryption()
    )
    result = analyze_bytes(pfx)
    assert result.container is not None
    assert result.container.format == "PKCS#12 certificate/key container"
    assert any("certificate" in item for item in result.cryptographic_metadata)


def test_encrypted_pkcs12_is_structurally_identified_without_a_password():
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509_mod.Name(
        [x509_mod.NameAttribute(x509_mod.oid.NameOID.COMMON_NAME, "protected.test")]
    )
    cert = (
        x509_mod.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509_mod.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
        )
        .sign(key, hashes.SHA256())
    )
    pfx = pkcs12.serialize_key_and_certificates(
        b"cryptonik",
        key,
        cert,
        None,
        BestAvailableEncryption(b"test-password"),
    )
    result = analyze_bytes(pfx)
    assert result.container is not None
    assert result.container.format == "PKCS#12 certificate/key container"
    assert any("password" in item.casefold() for item in result.cryptographic_metadata)


def test_jwe_five_segments_identified():
    """A JWE compact serialization with 5 dot-separated segments is classified."""
    header = base64.urlsafe_b64encode(
        b'{"alg":"RSA-OAEP","enc":"A256GCM"}'
    ).decode().rstrip("=")
    parts = [header, "encrypted_key", "init_vector", "ciphertext0", "auth_tag0"]
    assert "JSON Web Encryption (JWE)" in _kinds(".".join(parts))
