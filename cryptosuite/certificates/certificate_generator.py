"""CSR and self-signed certificate generation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from cryptosuite.utils.exceptions import ValidationError


def generate_csr(private_key, common_name: str, san_names: list[str] | None = None) -> x509.CertificateSigningRequest:
    """Generate a CSR with optional DNS subject alternative names."""
    name = _validated_name(common_name)
    builder = x509.CertificateSigningRequestBuilder().subject_name(name)
    if san_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(item) for item in san_names]),
            critical=False,
        )
    return builder.sign(private_key, _signature_hash(private_key))


def generate_self_signed(
    private_key,
    common_name: str,
    *,
    days_valid: int = 365,
    san_names: list[str] | None = None,
) -> x509.Certificate:
    """Generate a non-CA self-signed certificate for local/test use."""
    if (
        isinstance(days_valid, bool)
        or not isinstance(days_valid, int)
        or not 1 <= days_valid <= 825
    ):
        raise ValidationError("Certificate validity must be between 1 and 825 days.")
    name = _validated_name(common_name)
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if san_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(item) for item in san_names]),
            critical=False,
        )
    return builder.sign(private_key, _signature_hash(private_key))


def _validated_name(common_name: str) -> x509.Name:
    if not isinstance(common_name, str) or not common_name.strip() or len(common_name) > 253:
        raise ValidationError("Common name must contain 1 to 253 characters.")
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _signature_hash(private_key):
    return None if isinstance(private_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
