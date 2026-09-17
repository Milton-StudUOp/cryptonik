"""Encoding helpers. Encoding is not encryption."""

from __future__ import annotations

import base64
import binascii
from enum import StrEnum

from cryptosuite.utils.exceptions import ValidationError


class Encoding(StrEnum):
    BASE64 = "base64"
    BASE64URL = "base64url"
    BASE32 = "base32"
    HEX = "hex"


def encode(data: bytes, encoding: Encoding) -> str:
    if not isinstance(data, bytes):
        raise ValidationError("Data must be bytes.")
    selected = Encoding(encoding)
    if selected is Encoding.BASE64:
        return base64.b64encode(data).decode("ascii")
    if selected is Encoding.BASE64URL:
        return base64.urlsafe_b64encode(data).decode("ascii")
    if selected is Encoding.BASE32:
        return base64.b32encode(data).decode("ascii")
    return data.hex()


def decode(data: str, encoding: Encoding) -> bytes:
    if not isinstance(data, str):
        raise ValidationError("Encoded data must be text.")
    try:
        selected = Encoding(encoding)
        if selected is Encoding.BASE64:
            return base64.b64decode(data, validate=True)
        if selected is Encoding.BASE64URL:
            return base64.b64decode(data, altchars=b"-_", validate=True)
        if selected is Encoding.BASE32:
            return base64.b32decode(data, casefold=True)
        return bytes.fromhex(data)
    except (ValueError, binascii.Error) as exc:
        raise ValidationError("Invalid encoded data.") from exc

