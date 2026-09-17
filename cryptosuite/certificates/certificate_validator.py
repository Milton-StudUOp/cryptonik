"""Practical offline X.509 validity, hostname, and chain validation."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from cryptosuite.utils.exceptions import ValidationError


@dataclass(frozen=True, slots=True)
class CertificateValidationResult:
    valid: bool
    errors: tuple[str, ...]
    chain_length: int


def validate_certificate(
    certificate: x509.Certificate,
    intermediates: list[x509.Certificate] | None = None,
    trust_roots: list[x509.Certificate] | None = None,
    *,
    hostname: str | None = None,
    moment: datetime | None = None,
) -> CertificateValidationResult:
    """Validate time, optional identity, signatures, CA constraints, and trust root."""
    current = moment or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValidationError("Certificate validation time must be timezone-aware.")
    intermediates = intermediates or []
    trust_roots = trust_roots or []
    errors: list[str] = []
    chain = [certificate]
    _check_time(certificate, current, errors, "Leaf certificate")
    if hostname:
        _check_hostname(certificate, hostname, errors)

    pool = list(intermediates) + list(trust_roots)
    current_cert = certificate
    visited: set[bytes] = set()
    trusted = False
    while True:
        fingerprint = current_cert.fingerprint(hashes.SHA256())
        if fingerprint in visited:
            errors.append("Certificate chain contains a loop.")
            break
        visited.add(fingerprint)
        if any(current_cert == root for root in trust_roots):
            trusted = True
            break
        issuer = next((candidate for candidate in pool if candidate.subject == current_cert.issuer), None)
        if issuer is None:
            errors.append("Certificate chain does not terminate at a supplied trust root.")
            break
        _check_time(issuer, current, errors, "Issuer certificate")
        _check_ca(issuer, errors)
        if not _verify_certificate_signature(current_cert, issuer):
            errors.append("Certificate signature validation failed.")
            break
        chain.append(issuer)
        current_cert = issuer
        if len(chain) > len(pool) + 1:
            errors.append("Certificate chain exceeds supplied certificates.")
            break
    if not trust_roots:
        errors.append("No trust roots were supplied.")
    elif not trusted and not any("trust root" in error for error in errors):
        errors.append("Certificate is not anchored in a supplied trust root.")
    return CertificateValidationResult(not errors, tuple(errors), len(chain))


def _check_time(
    certificate: x509.Certificate,
    moment: datetime,
    errors: list[str],
    label: str,
) -> None:
    if moment < certificate.not_valid_before_utc:
        errors.append(f"{label} is not yet valid.")
    if moment > certificate.not_valid_after_utc:
        errors.append(f"{label} has expired.")


def _check_hostname(
    certificate: x509.Certificate, hostname: str, errors: list[str]
) -> None:
    try:
        extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        try:
            address = ipaddress.ip_address(hostname)
            values = extension.get_values_for_type(x509.IPAddress)
            matched = address in values
        except ValueError:
            values = extension.get_values_for_type(x509.DNSName)
            matched = any(_dns_match(hostname, value) for value in values)
        if not matched:
            errors.append(f"Certificate does not match hostname: {hostname}")
    except x509.ExtensionNotFound:
        errors.append("Certificate has no Subject Alternative Name extension.")


def _dns_match(hostname: str, pattern: str) -> bool:
    hostname = hostname.rstrip(".").casefold()
    pattern = pattern.rstrip(".").casefold()
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return hostname.endswith(suffix) and hostname.count(".") == pattern.count(".")
    return hostname == pattern


def _check_ca(certificate: x509.Certificate, errors: list[str]) -> None:
    try:
        constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        if not constraints.ca:
            errors.append("Issuer certificate is not authorized as a CA.")
    except x509.ExtensionNotFound:
        errors.append("Issuer certificate lacks Basic Constraints.")


def _verify_certificate_signature(
    certificate: x509.Certificate, issuer: x509.Certificate
) -> bool:
    public_key = issuer.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(certificate.signature_hash_algorithm),
            )
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(
                certificate.signature, certificate.tbs_certificate_bytes
            )
        else:
            return False
    except (InvalidSignature, ValueError):
        return False
    return True
