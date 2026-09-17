"""Hybrid authenticated encryption for one or more recipients."""

from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptosuite.core.random_generator import random_bytes
from cryptosuite.core.symmetric import (
    EncryptedData,
    SymmetricAlgorithm,
    decrypt,
    encrypt,
    generate_key,
)
from cryptosuite.keys.key_generator import key_id
from cryptosuite.utils.exceptions import (
    AuthenticationError,
    FileFormatError,
    ValidationError,
)

MAX_RECIPIENTS = 100


@dataclass(frozen=True, slots=True)
class RecipientEnvelope:
    key_id: str
    algorithm: str
    wrapped_key: bytes
    ephemeral_public_key: bytes | None = None
    nonce: bytes | None = None


@dataclass(frozen=True, slots=True)
class HybridEnvelope:
    recipients: tuple[RecipientEnvelope, ...]
    nonce: bytes
    ciphertext: bytes
    algorithm: str = SymmetricAlgorithm.XCHACHA20_POLY1305.value


def hybrid_encrypt(data: bytes, recipient_public_keys: list) -> HybridEnvelope:
    """Encrypt bytes once and wrap the data key for every recipient."""
    if not isinstance(data, bytes):
        raise ValidationError("Data must be bytes.")
    if not 1 <= len(recipient_public_keys) <= MAX_RECIPIENTS:
        raise ValidationError(f"Recipient count must be between 1 and {MAX_RECIPIENTS}.")
    data_key = generate_key()
    recipients = tuple(_wrap_key(data_key, key) for key in recipient_public_keys)
    aad = _recipient_aad(recipients)
    sealed = encrypt(
        data,
        data_key,
        SymmetricAlgorithm.XCHACHA20_POLY1305,
        associated_data=aad,
    )
    return HybridEnvelope(recipients, sealed.nonce, sealed.ciphertext)


def hybrid_decrypt(envelope: HybridEnvelope, recipient_private_key) -> bytes:
    """Recover and use the data key belonging to one recipient."""
    if not isinstance(envelope, HybridEnvelope):
        raise ValidationError("Invalid hybrid envelope.")
    identifier = key_id(recipient_private_key.public_key())
    recipient = next((item for item in envelope.recipients if item.key_id == identifier), None)
    if recipient is None:
        raise AuthenticationError("Private key is not a recipient of this envelope.")
    data_key = _unwrap_key(recipient, recipient_private_key)
    algorithm = SymmetricAlgorithm(envelope.algorithm)
    return decrypt(
        EncryptedData(algorithm, envelope.nonce, envelope.ciphertext),
        data_key,
        associated_data=_recipient_aad(envelope.recipients),
    )


def serialize_envelope(envelope: HybridEnvelope) -> bytes:
    """Serialize a bounded hybrid envelope as canonical JSON."""
    payload = {
        "algorithm": envelope.algorithm,
        "ciphertext": _b64(envelope.ciphertext),
        "nonce": _b64(envelope.nonce),
        "recipients": [
            {
                key: (_b64(value) if isinstance(value, bytes) else value)
                for key, value in asdict(recipient).items()
                if value is not None
            }
            for recipient in envelope.recipients
        ],
        "version": 1,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")


def deserialize_envelope(data: bytes) -> HybridEnvelope:
    """Parse an untrusted serialized hybrid envelope."""
    if not isinstance(data, bytes) or len(data) > 64 * 1024 * 1024:
        raise FileFormatError("Hybrid envelope is invalid or too large.")
    try:
        payload = json.loads(data.decode("ascii"))
        if set(payload) != {"algorithm", "ciphertext", "nonce", "recipients", "version"}:
            raise ValueError
        if payload["version"] != 1 or not 1 <= len(payload["recipients"]) <= MAX_RECIPIENTS:
            raise ValueError
        recipients = tuple(
            RecipientEnvelope(
                key_id=item["key_id"],
                algorithm=item["algorithm"],
                wrapped_key=_unb64(item["wrapped_key"]),
                ephemeral_public_key=_unb64(item["ephemeral_public_key"])
                if "ephemeral_public_key" in item
                else None,
                nonce=_unb64(item["nonce"]) if "nonce" in item else None,
            )
            for item in payload["recipients"]
        )
        algorithm = SymmetricAlgorithm(payload["algorithm"])
        nonce = _unb64(payload["nonce"])
        ciphertext = _unb64(payload["ciphertext"])
        if len(nonce) != 24 or len(ciphertext) < 16:
            raise ValueError
        return HybridEnvelope(recipients, nonce, ciphertext, algorithm.value)
    except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise FileFormatError("Malformed hybrid envelope.") from exc


def _wrap_key(data_key: bytes, public_key) -> RecipientEnvelope:
    identifier = key_id(public_key)
    if isinstance(public_key, x25519.X25519PublicKey):
        ephemeral = x25519.X25519PrivateKey.generate()
        shared = ephemeral.exchange(public_key)
        wrapping_key = _exchange_key(shared, identifier)
        nonce = random_bytes(12)
        wrapped = encrypt(
            data_key,
            wrapping_key,
            SymmetricAlgorithm.CHACHA20_POLY1305,
            nonce=nonce,
            associated_data=identifier.encode(),
        ).ciphertext
        ephemeral_bytes = ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return RecipientEnvelope(identifier, "x25519", wrapped, ephemeral_bytes, nonce)
    if isinstance(public_key, rsa.RSAPublicKey) and public_key.key_size >= 3072:
        wrapped = public_key.encrypt(
            data_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=b"CryptoSuite hybrid key v1",
            ),
        )
        return RecipientEnvelope(identifier, "rsa-oaep-sha256", wrapped)
    raise ValidationError("Recipient key must be X25519 or RSA-3072+.")


def _unwrap_key(recipient: RecipientEnvelope, private_key) -> bytes:
    try:
        if recipient.algorithm == "x25519" and isinstance(private_key, x25519.X25519PrivateKey):
            if recipient.ephemeral_public_key is None or recipient.nonce is None:
                raise ValueError
            ephemeral = x25519.X25519PublicKey.from_public_bytes(recipient.ephemeral_public_key)
            wrapping_key = _exchange_key(private_key.exchange(ephemeral), recipient.key_id)
            return decrypt(
                EncryptedData(
                    SymmetricAlgorithm.CHACHA20_POLY1305,
                    recipient.nonce,
                    recipient.wrapped_key,
                ),
                wrapping_key,
                associated_data=recipient.key_id.encode(),
            )
        if recipient.algorithm == "rsa-oaep-sha256" and isinstance(private_key, rsa.RSAPrivateKey):
            return private_key.decrypt(
                recipient.wrapped_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=b"CryptoSuite hybrid key v1",
                ),
            )
    except (ValueError, AuthenticationError) as exc:
        raise AuthenticationError("Unable to recover hybrid data key.") from exc
    raise AuthenticationError("Recipient key type does not match the envelope.")


def _exchange_key(shared: bytes, identifier: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"CryptoSuite X25519 wrapping v1|" + identifier.encode(),
    ).derive(shared)


def _recipient_aad(recipients: tuple[RecipientEnvelope, ...]) -> bytes:
    return b"CryptoSuite recipients v1|" + b"|".join(
        item.key_id.encode() for item in recipients
    )


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)
