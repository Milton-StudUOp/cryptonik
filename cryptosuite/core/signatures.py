"""Detached Ed25519 and RSA-PSS signatures."""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from cryptosuite.utils.exceptions import ValidationError


def sign(data: bytes, private_key) -> bytes:
    """Create a signature with a signing-capable private key."""
    if not isinstance(data, bytes):
        raise ValidationError("Data to sign must be bytes.")
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return private_key.sign(data)
    if isinstance(private_key, ec.EllipticCurvePrivateKey) and isinstance(
        private_key.curve, ec.SECP256R1
    ):
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    if isinstance(private_key, rsa.RSAPrivateKey) and private_key.key_size >= 3072:
        return private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
    raise ValidationError("Key is not supported for digital signatures.")


def verify(data: bytes, signature: bytes, public_key) -> bool:
    """Verify a signature without raising for an invalid signature."""
    if not isinstance(data, bytes) or not isinstance(signature, bytes):
        raise ValidationError("Signed data and signature must be bytes.")
    try:
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, data)
        elif isinstance(public_key, ec.EllipticCurvePublicKey) and isinstance(
            public_key.curve, ec.SECP256R1
        ):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        elif isinstance(public_key, rsa.RSAPublicKey) and public_key.key_size >= 3072:
            public_key.verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
                hashes.SHA256(),
            )
        else:
            raise ValidationError("Key is not supported for digital signatures.")
    except InvalidSignature:
        return False
    return True
