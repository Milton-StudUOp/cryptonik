"""X.509 certificate parsing and structured inspection."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from cryptosuite.utils.exceptions import ValidationError


@dataclass(frozen=True, slots=True)
class CertificateInfo:
    subject: str
    issuer: str
    serial_number: str
    not_valid_before: str
    not_valid_after: str
    public_key_type: str
    signature_algorithm: str
    san: tuple[str, ...]
    key_usage: str | None
    extended_key_usage: tuple[str, ...]
    fingerprint_sha256: str


def load_certificate(data: bytes) -> x509.Certificate:
    if not isinstance(data, bytes) or len(data) > 10 * 1024 * 1024:
        raise ValidationError("Certificate data is invalid or too large.")
    try:
        if b"-----BEGIN CERTIFICATE-----" in data:
            return x509.load_pem_x509_certificate(data)
        return x509.load_der_x509_certificate(data)
    except ValueError as exc:
        raise ValidationError("Unable to parse X.509 certificate.") from exc


def inspect_certificate(certificate: x509.Certificate) -> CertificateInfo:
    san: tuple[str, ...] = ()
    key_usage = None
    extended: tuple[str, ...] = ()
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = tuple(str(name.value) for name in extension.value)
    except x509.ExtensionNotFound:
        pass
    try:
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        key_usage = ", ".join(
            name
            for name in (
                "digital_signature" if usage.digital_signature else "",
                "key_encipherment" if usage.key_encipherment else "",
                "key_agreement" if usage.key_agreement else "",
                "certificate_signing" if usage.key_cert_sign else "",
            )
            if name
        )
    except x509.ExtensionNotFound:
        pass
    try:
        usages = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        extended = tuple(item.dotted_string for item in usages)
    except x509.ExtensionNotFound:
        pass
    der = certificate.public_bytes(serialization.Encoding.DER)
    fingerprint = ":".join(f"{byte:02X}" for byte in hashlib.sha256(der).digest())
    signature = (
        certificate.signature_hash_algorithm.name
        if certificate.signature_hash_algorithm is not None
        else certificate.signature_algorithm_oid.dotted_string
    )
    return CertificateInfo(
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        serial_number=f"{certificate.serial_number:X}",
        not_valid_before=certificate.not_valid_before_utc.isoformat(),
        not_valid_after=certificate.not_valid_after_utc.isoformat(),
        public_key_type=type(certificate.public_key()).__name__,
        signature_algorithm=signature,
        san=san,
        key_usage=key_usage,
        extended_key_usage=extended,
        fingerprint_sha256=fingerprint,
    )

