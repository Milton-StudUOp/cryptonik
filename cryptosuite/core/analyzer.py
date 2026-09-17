"""Forensic identification of representations, formats, and ciphertext-like data."""

from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse
from dataclasses import asdict, dataclass
from math import log2

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from cryptosuite.lab.analysis import shannon_entropy
from cryptosuite.utils.exceptions import ValidationError

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_BINARY_GROUPS = re.compile(r"^[01]{8}(?:\s+[01]{8})+$")
_HEX_GROUPS = re.compile(r"^[0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})+$")
_BASE64 = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]*={0,2}$")
_BASE32 = re.compile(r"^[A-Z2-7]*={0,6}$", re.IGNORECASE)
_PEM_BEGIN = re.compile(rb"^-----BEGIN ([A-Z0-9 ]+)-----")
_MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", "-----": "0",
}
_MAGIC = (
    (b"Salted__", "OpenSSL salted format", "OpenSSL enc-compatible salted container"),
    (b"CRYPTSIG", "Cryptonik detached signature", "Cryptonik detached signature"),
    (b"CRYPTX", "Cryptonik CRYPTX container", "Cryptonik CRYPTX container"),
    (b"CRYPTH", "Cryptonik CRYPTH multi-recipient container", "Cryptonik CRYPTH container"),
    (b"PK\x03\x04", "ZIP archive", "ZIP archive"),
    (b"%PDF", "PDF document", "PDF document"),
    (b"\x89PNG\r\n\x1a\n", "PNG image", "PNG image"),
)
_SSH_PREFIXES = (
    (b"ssh-ed25519 ", "OpenSSH Ed25519 public key"),
    (b"ssh-rsa ", "OpenSSH RSA public key"),
    (b"ssh-ed448 ", "OpenSSH Ed448 public key"),
    (b"ssh-dss ", "OpenSSH DSA public key"),
    (b"ecdsa-sha2-nistp256 ", "OpenSSH ECDSA-P256 public key"),
    (b"ecdsa-sha2-nistp384 ", "OpenSSH ECDSA-P384 public key"),
    (b"ecdsa-sha2-nistp521 ", "OpenSSH ECDSA-P521 public key"),
)
_CRYPTO_CONTAINER_FORMATS = frozenset({
    "OpenSSL enc-compatible salted container",
    "Cryptonik CRYPTX container",
    "Cryptonik CRYPTH container",
    "Cryptonik detached signature",
    "Cryptonik encrypted text token",
    "PEM-encoded certificate",
    "PEM-encoded public key",
    "PEM-encoded private key",
    "PEM-encoded encrypted private key",
    "PEM-encoded RSA private key",
    "PEM-encoded EC private key",
    "PEM-encoded certificate request",
    "PEM/PGP textual container",
    "OpenPGP ASCII armor (message)",
    "OpenPGP ASCII armor (public key)",
    "OpenPGP ASCII armor (private key)",
    "OpenPGP ASCII armor (signature)",
    "OpenSSH public-key record",
    "DER-encoded X.509 certificate",
    "DER-encoded PKCS#8 private key",
    "DER-encoded PKCS#8 public key",
    "DER-encoded ASN.1 structure",
})
MAX_ANALYSIS_BYTES = 16 * 1024 * 1024
MIN_STATISTICAL_SAMPLE = 256
MIN_DISPLAYED_ENTROPY_SAMPLE = 16
MAX_DECODE_DEPTH = 4
_CIPHER_WARNING = (
    "A representation or format header does not establish an encryption algorithm. "
    "AES, DES, ChaCha20, compressed data, and random bytes cannot be reliably "
    "distinguished from ciphertext alone without authenticated metadata."
)


@dataclass(frozen=True, slots=True)
class Identification:
    kind: str
    confidence: str
    evidence: str


@dataclass(frozen=True, slots=True)
class ContainerDetails:
    format: str
    header: str
    salt: str | None = None


@dataclass(frozen=True, slots=True)
class SegmentDetails:
    representation: str
    confidence: str
    decoded_type: str | None = None
    value: str | None = None
    decode_path: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class StructureDetails:
    kind: str
    segments: tuple[SegmentDetails, ...]
    recognized_standard: str


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    input_characters: int
    decoded_bytes: int | None
    entropy_bits_per_byte: float | None
    candidates: tuple[Identification, ...]
    container: ContainerDetails | None
    structure: StructureDetails | None
    decoded_text: str | None
    decode_layers: tuple[str, ...]
    cipher: str | None
    kdf: str | None
    cryptographic_metadata: tuple[str, ...]
    statistical_note: str
    sample_limited_max_entropy: float | None
    classification: tuple[str, ...]
    suggestions: tuple[str, ...]
    warning: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def analyze_text(value: str) -> AnalysisResult:
    """Classify representation before decoding and structural inspection."""
    text = value.strip()
    if not text:
        raise ValidationError("Analysis input cannot be empty.")
    candidates: list[Identification] = []
    decoded: bytes | None = None
    decoded_text: str | None = None
    layers: list[str] = []
    structure = _dot_structure(text, candidates)

    if _BINARY_GROUPS.fullmatch(text):
        decoded = bytes(int(group, 2) for group in text.split())
        candidates.append(
            Identification(
                "binary byte groups", "certain", "8-bit groups separated by spaces"
            )
        )
        layers.append("Binary byte groups")
    elif _HEX_GROUPS.fullmatch(text):
        decoded = bytes.fromhex(text)
        candidates.append(
            Identification(
                "space-separated hexadecimal bytes",
                "certain",
                "Two hexadecimal digits per byte",
            )
        )
        layers.append("Hexadecimal byte groups")
    else:
        morse = _decode_morse(text)
        if morse is not None:
            decoded_text = morse
            decoded = morse.encode("utf-8")
            candidates.append(
                Identification("Morse code", "certain", "Valid Morse symbols and words")
            )
            layers.extend(("Morse code", "UTF-8 text"))
        elif structure is None:
            decoded, encoding = _decode_single_representation(text, candidates)
            if decoded is not None:
                layers.append(encoding)

    raw = decoded if decoded is not None else text.encode("utf-8")
    if decoded_text is None and decoded is not None:
        decoded_text = _printable_utf8(decoded)
        if decoded_text is not None:
            layers.append("UTF-8 text")
    if decoded_text is not None:
        raw, decoded_text = _recursive_decode(
            raw, decoded_text, candidates, layers
        )
    jwt = _identify_jwt(text, candidates)
    if jwt is not None:
        structure = jwt
    return _assess(
        raw,
        candidates,
        input_characters=len(text),
        decoded_bytes=len(raw) if decoded is not None else None,
        decoded_text=decoded_text,
        decode_layers=layers[:MAX_DECODE_DEPTH],
        structure=structure,
    )


def analyze_bytes(data: bytes) -> AnalysisResult:
    if not data:
        raise ValidationError("Analysis input cannot be empty.")
    if len(data) > MAX_ANALYSIS_BYTES:
        raise ValidationError(
            f"Analysis input exceeds the {MAX_ANALYSIS_BYTES}-byte safety limit."
        )
    return _assess(
        data,
        [],
        input_characters=0,
        decoded_bytes=len(data),
        decoded_text=_printable_utf8(data),
        decode_layers=[],
        structure=None,
    )


def _decode_single_representation(
    text: str, candidates: list[Identification]
) -> tuple[bytes | None, str]:
    if len(text) % 2 == 0 and _HEX.fullmatch(text):
        data = bytes.fromhex(text)
        candidates.append(
            Identification("hexadecimal encoding", "certain", "Valid hex alphabet")
        )
        _identify_hash_length(text, candidates)
        return data, "Hexadecimal"
    compact = "".join(text.split())
    if _strict_base64(compact):
        data = _decode_base64(compact)
        candidates.append(
            Identification(
                "Base64 encoding", "certain", "Canonical Base64 decodes successfully"
            )
        )
        return data, "Base64"
    if _strict_base64url(compact):
        data = _decode_base64(compact, urlsafe=True)
        candidates.append(
            Identification(
                "Base64URL encoding", "certain", "Canonical Base64URL decodes successfully"
            )
        )
        return data, "Base64URL"
    if len(compact) >= 8 and _BASE32.fullmatch(compact):
        try:
            data = base64.b32decode(
                compact.upper() + "=" * (-len(compact) % 8), casefold=True
            )
            candidates.append(
                Identification("Base32 encoding", "high", "Decodes successfully")
            )
            return data, "Base32"
        except binascii.Error:
            pass
    if re.search(r"%[0-9A-Fa-f]{2}", text):
        data = urllib.parse.unquote_to_bytes(text)
        candidates.append(
            Identification("URL percent encoding", "certain", "Valid %HH escapes")
        )
        return data, "URL percent encoding"
    return None, ""


def _recursive_decode(
    data: bytes,
    text: str,
    candidates: list[Identification],
    layers: list[str],
) -> tuple[bytes, str]:
    """Decode nested, unambiguous representations with a strict depth bound."""
    current_data = data
    current_text = text
    while len(layers) < MAX_DECODE_DEPTH:
        nested: bytes | None = None
        encoding = ""
        stripped = current_text.strip()
        if _BINARY_GROUPS.fullmatch(stripped):
            nested = bytes(int(group, 2) for group in stripped.split())
            encoding = "Binary byte groups"
        elif _HEX_GROUPS.fullmatch(stripped):
            nested = bytes.fromhex(stripped)
            encoding = "Hexadecimal byte groups"
        else:
            morse = _decode_morse(stripped)
            if morse is not None:
                nested = morse.encode("utf-8")
                encoding = "Morse code"
            elif _strict_base64(stripped):
                nested = _decode_base64(stripped)
                encoding = "Base64"
            elif _strict_base64url(stripped):
                nested = _decode_base64(stripped, urlsafe=True)
                encoding = "Base64URL"
            elif re.search(r"%[0-9A-Fa-f]{2}", stripped):
                nested = urllib.parse.unquote_to_bytes(stripped)
                encoding = "URL percent encoding"
        if nested is None or nested == current_data:
            break
        nested_text = _printable_utf8(nested)
        if nested_text is None:
            break
        candidates.append(
            Identification(
                f"nested {encoding} encoding",
                "high",
                f"Decoded at layer {len(layers) + 1}",
            )
        )
        layers.extend((encoding, "UTF-8 text"))
        current_data = nested
        current_text = nested_text
    return current_data, current_text


def _assess(
    data: bytes,
    candidates: list[Identification],
    *,
    input_characters: int,
    decoded_bytes: int | None,
    decoded_text: str | None,
    decode_layers: list[str],
    structure: StructureDetails | None,
) -> AnalysisResult:
    container = _identify_payload(data, candidates)
    crypto_container, metadata = _identify_cryptographic_format(
        data, candidates, container
    )
    if crypto_container is not None:
        container = crypto_container
    classification, suggestions = _text_characteristics(
        decoded_text if decoded_text is not None else _printable_utf8(data),
        candidates,
        suggest_classical=(
            decoded_bytes is None
            and not decode_layers
            and structure is None
            and container is None
        ),
    )
    observed_entropy = max(0.0, shannon_entropy(data))
    if len(data) < MIN_DISPLAYED_ENTROPY_SAMPLE:
        displayed_entropy = None
        sample_maximum = None
        statistical_note = (
            f"Not performed -- sample too small ({len(data)} "
            f"{'byte' if len(data) == 1 else 'bytes'})."
        )
    elif len(data) < MIN_STATISTICAL_SAMPLE:
        displayed_entropy = round(observed_entropy, 4)
        sample_maximum = round(log2(min(len(data), 256)), 4)
        statistical_note = (
            "Sample too small for meaningful randomness classification."
        )
    else:
        displayed_entropy = round(observed_entropy, 4)
        sample_maximum = 8.0
        statistical_note = (
            f"Entropy = {observed_entropy:.3f} bits/byte. Statistical characteristics "
            "alone do not identify encryption."
        )
        if observed_entropy >= 7.0:
            candidates.append(
                Identification(
                    "Binary/randomness characteristics",
                    "low",
                    f"Entropy = {observed_entropy:.3f} bits/byte; heuristic only",
                )
            )
    if not candidates:
        candidates.append(
            Identification(
                "unknown text or binary data",
                "unknown",
                "No recognized structural marker or strict encoding",
            )
        )
    return AnalysisResult(
        input_characters=input_characters,
        decoded_bytes=decoded_bytes,
        entropy_bits_per_byte=displayed_entropy,
        candidates=tuple(candidates),
        container=container,
        structure=structure,
        decoded_text=decoded_text,
        decode_layers=tuple(decode_layers),
        cipher="Unknown" if _is_crypto_container(container) else None,
        kdf="Unknown" if _is_crypto_container(container) else None,
        cryptographic_metadata=metadata,
        statistical_note=statistical_note,
        sample_limited_max_entropy=sample_maximum,
        classification=classification,
        suggestions=suggestions,
        warning=_CIPHER_WARNING,
    )


def _dot_structure(
    text: str, candidates: list[Identification]
) -> StructureDetails | None:
    parts = text.split(".")
    if len(parts) < 2 or any(not part for part in parts):
        return None
    formats = tuple(_segment_details(part) for part in parts)
    candidates.append(
        Identification(
            "dot-separated data",
            "high",
            f"{len(parts)} non-empty segments; no standard inferred from shape alone",
        )
    )
    return StructureDetails("Dot-separated data", formats, "None confirmed")


def _identify_jwt(
    text: str, candidates: list[Identification]
) -> StructureDetails | None:
    parts = text.split(".")
    if len(parts) not in {3, 5} or any(not part for part in parts):
        return None
    try:
        header = json.loads(_decode_base64(parts[0], urlsafe=True))
    except (UnicodeError, json.JSONDecodeError, binascii.Error):
        return None
    if not isinstance(header, dict) or not isinstance(header.get("alg"), str):
        return None
    segments = tuple(_segment_details(part) for part in parts)
    # After confirming a valid JSON header with "alg", allow segments that
    # match the Base64URL alphabet even when they are too short for the
    # strict round-trip check used by _segment_details.
    for index, seg in enumerate(segments):
        if seg.representation == "Unknown":
            if not _BASE64URL.fullmatch(parts[index]):
                return None
    if len(parts) == 5:
        if not isinstance(header.get("enc"), str):
            return None
        standard = "JWE compact serialization"
        kind = "JSON Web Encryption (JWE)"
        evidence = (
            f"Five encoded segments; header alg={header['alg']!s}, "
            f"enc={header['enc']!s}"
        )
    else:
        try:
            payload = json.loads(_decode_base64(parts[1], urlsafe=True))
        except (UnicodeError, json.JSONDecodeError, binascii.Error):
            payload = None
        if isinstance(payload, dict):
            standard = "JWT carried in JWS-compatible compact serialization"
            kind = "JSON Web Token (JWT)"
        else:
            standard = "JWS compact serialization"
            kind = "JSON Web Signature (JWS)"
        evidence = f"Three encoded segments; header alg={header['alg']!s}"
    candidates.append(
        Identification(
            kind,
            "high",
            evidence,
        )
    )
    return StructureDetails(
        "Dot-separated data",
        segments,
        standard,
    )


def _segment_details(value: str) -> SegmentDetails:
    data: bytes | None = None
    representation = "Unknown"
    confidence = "unknown"
    if len(value) % 2 == 0 and _HEX.fullmatch(value):
        data = bytes.fromhex(value)
        representation = "Hexadecimal"
        confidence = "certain"
    elif _strict_base64(value):
        data = _decode_base64(value)
        representation = "Base64"
        confidence = "certain"
    elif _strict_base64url(value):
        data = _decode_base64(value, urlsafe=True)
        representation = "Base64URL"
        confidence = "certain"
    if data is None:
        return SegmentDetails(representation, confidence)
    text = _printable_utf8(data)
    path = [representation]
    if text is not None:
        path.append("UTF-8 text")
        nested_data, nested_text = _recursive_segment_decode(data, text, path)
        data, text = nested_data, nested_text
    return SegmentDetails(
        representation,
        confidence,
        "printable UTF-8" if text is not None else "binary data",
        _bounded_text(text),
        tuple(path),
    )


def _recursive_segment_decode(
    data: bytes, text: str, path: list[str]
) -> tuple[bytes, str]:
    current_data, current_text = data, text
    while len(path) < MAX_DECODE_DEPTH:
        stripped = current_text.strip()
        if _strict_base64(stripped):
            nested = _decode_base64(stripped)
            encoding = "Base64"
        elif _strict_base64url(stripped):
            nested = _decode_base64(stripped, urlsafe=True)
            encoding = "Base64URL"
        else:
            break
        nested_text = _printable_utf8(nested)
        if nested_text is None or nested == current_data:
            break
        path.extend((encoding, "UTF-8 text"))
        current_data, current_text = nested, nested_text
    return current_data, current_text


def _bounded_text(value: str | None) -> str | None:
    if value is None:
        return None
    return value if len(value) <= 200 else value[:197] + "..."


def _strict_base64(value: str) -> bool:
    if len(value) < 8 or not _BASE64.fullmatch(value) or len(value) % 4 == 1:
        return False
    try:
        decoded = _decode_base64(value)
    except binascii.Error:
        return False
    return base64.b64encode(decoded).decode().rstrip("=") == value.rstrip("=")


def _strict_base64url(value: str) -> bool:
    if len(value) < 8 or not _BASE64URL.fullmatch(value) or len(value) % 4 == 1:
        return False
    try:
        decoded = _decode_base64(value, urlsafe=True)
    except binascii.Error:
        return False
    encoded = base64.urlsafe_b64encode(decoded).decode().rstrip("=")
    return encoded == value.rstrip("=")


def _decode_base64(value: str, *, urlsafe: bool = False) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.b64decode(
        padded, altchars=b"-_" if urlsafe else None, validate=True
    )


def _decode_morse(text: str) -> str | None:
    if not re.fullmatch(r"[.\-/ ]+", text) or not ({".", "-"} & set(text)):
        return None
    words: list[str] = []
    for word in re.split(r"\s*/\s*", text):
        symbols = word.split()
        if not symbols or any(symbol not in _MORSE for symbol in symbols):
            return None
        words.append("".join(_MORSE[symbol] for symbol in symbols))
    return " ".join(words)


def _printable_utf8(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text or any(not (char.isprintable() or char in "\r\n\t") for char in text):
        return None
    return text


def _text_characteristics(
    text: str | None,
    candidates: list[Identification],
    *,
    suggest_classical: bool,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if text is None:
        return (), ()
    traits = ["Printable UTF-8 text"]
    suggestions: tuple[str, ...] = ()
    letters = [char for char in text if char.isalpha()]
    if letters:
        traits.append("Alphabetic characters")
    if " " in text:
        traits.append("Preserved word boundaries")
    if suggest_classical and letters and len(letters) >= 6 and all(
        char.isalpha() or char.isspace() for char in text
    ):
        candidates.append(
            Identification(
                "possible classical-cipher text",
                "low",
                "Printable alphabetic text with insufficient evidence to identify a cipher",
            )
        )
        suggestions = (
            "Caesar/ROT shift analysis",
            "Substitution and frequency analysis",
            "Use the Crypto Lab for exploratory tests",
        )
    return tuple(traits), suggestions


def _identify_hash_length(text: str, candidates: list[Identification]) -> None:
    digest_names = {
        32: "MD5 or another 128-bit value",
        40: "SHA-1 or another 160-bit value",
        64: "SHA-256 or another 256-bit value",
        96: "SHA-384 or another 384-bit value",
        128: "SHA-512 or another 512-bit value",
    }
    if len(text) in digest_names:
        candidates.append(
            Identification(
                "hash/HMAC-sized value",
                "low",
                f"Length matches {digest_names[len(text)]}; length is not proof",
            )
        )


def _identify_payload(
    data: bytes, candidates: list[Identification]
) -> ContainerDetails | None:
    for magic, kind, format_name in _MAGIC:
        if data.startswith(magic):
            evidence = f'Magic header: "{magic.decode("ascii", errors="replace")}"'
            candidates.append(Identification(kind, "high", evidence))
            salt = None
            header = evidence.removeprefix("Magic ")
            if magic == b"Salted__":
                salt = "present (8 bytes)" if len(data) >= 16 else "truncated or absent"
                header = '8 bytes ("Salted__")'
            return ContainerDetails(format_name, header, salt)
    pem = _PEM_BEGIN.match(data)
    if pem:
        label = pem.group(1).decode("ascii")
        kind, format_name = _classify_pem_label(label)
        candidates.append(Identification(kind, "certain", f"BEGIN label: {label}"))
        return ContainerDetails(format_name, f'BEGIN label: "{label}"')
    for prefix, kind in _SSH_PREFIXES:
        if data.startswith(prefix):
            key_type = prefix.decode("ascii").strip()
            candidates.append(
                Identification(kind, "certain", f'Prefix: "{key_type}"')
            )
            return ContainerDetails("OpenSSH public-key record", f'Prefix: "{key_type}"')
    try:
        document = json.loads(data)
    except (UnicodeError, json.JSONDecodeError):
        return None
    if isinstance(document, dict):
        fields = set(document)
        if {"ciphertext", "nonce", "salt", "version"} <= fields:
            candidates.append(
                Identification(
                    "Cryptonik encrypted text token",
                    "certain",
                    "Contains versioned ciphertext, nonce, and salt fields",
                )
            )
            return ContainerDetails(
                "Cryptonik encrypted text token", "Versioned JSON envelope", "present"
            )
        candidates.append(Identification("JSON document", "certain", "Valid JSON object"))
        return ContainerDetails("JSON document", "JSON object")
    return None


def _classify_pem_label(label: str) -> tuple[str, str]:
    """Return (identification kind, container format) for a PEM BEGIN label."""
    _PEM_MAP: dict[str, tuple[str, str]] = {
        "CERTIFICATE": ("X.509 certificate (PEM)", "PEM-encoded certificate"),
        "TRUSTED CERTIFICATE": ("X.509 trusted certificate (PEM)", "PEM-encoded certificate"),
        "X509 CRL": ("X.509 CRL (PEM)", "PEM-encoded certificate"),
        "PUBLIC KEY": ("Public key (PEM)", "PEM-encoded public key"),
        "PRIVATE KEY": ("Private key PKCS#8 (PEM)", "PEM-encoded private key"),
        "ENCRYPTED PRIVATE KEY": (
            "Encrypted private key PKCS#8 (PEM)",
            "PEM-encoded encrypted private key",
        ),
        "RSA PRIVATE KEY": ("RSA private key PKCS#1 (PEM)", "PEM-encoded RSA private key"),
        "RSA PUBLIC KEY": ("RSA public key PKCS#1 (PEM)", "PEM-encoded public key"),
        "EC PRIVATE KEY": ("EC private key SEC1 (PEM)", "PEM-encoded EC private key"),
        "CERTIFICATE REQUEST": (
            "Certificate signing request (PEM)",
            "PEM-encoded certificate request",
        ),
        "NEW CERTIFICATE REQUEST": (
            "Certificate signing request (PEM)",
            "PEM-encoded certificate request",
        ),
        "PGP MESSAGE": ("OpenPGP encrypted message", "OpenPGP ASCII armor (message)"),
        "PGP PUBLIC KEY BLOCK": (
            "OpenPGP public key block",
            "OpenPGP ASCII armor (public key)",
        ),
        "PGP PRIVATE KEY BLOCK": (
            "OpenPGP private key block",
            "OpenPGP ASCII armor (private key)",
        ),
        "PGP SIGNATURE": ("OpenPGP signature", "OpenPGP ASCII armor (signature)"),
    }
    if label in _PEM_MAP:
        return _PEM_MAP[label]
    if label.startswith("PGP"):
        return (f"OpenPGP armor ({label})", "OpenPGP ASCII armor (message)")
    return ("PEM/PGP armor", "PEM/PGP textual container")


def _identify_cryptographic_format(
    data: bytes,
    candidates: list[Identification],
    container: ContainerDetails | None,
) -> tuple[ContainerDetails | None, tuple[str, ...]]:
    """Detect cryptographic structures in raw binary data.

    Returns a (container, metadata) pair.  When the data matches a known
    cryptographic container the returned *container* replaces or supplements
    the one found by ``_identify_payload``; *metadata* carries additional
    human-readable notes (key type, key size, algorithm, etc.).
    """
    metadata: list[str] = []

    # If _identify_payload already found a crypto container, enrich metadata.
    if container is not None and container.format in _CRYPTO_CONTAINER_FORMATS:
        if container.format == "OpenSSL enc-compatible salted container":
            ciphertext_len = max(0, len(data) - 16)  # 8 magic + 8 salt
            metadata.append(f"Ciphertext body: {ciphertext_len} bytes")
            metadata.append(
                'OpenSSL\'s "Salted__" header identifies the container '
                "format, not the encryption algorithm."
            )
        return None, tuple(metadata)

    # Skip if _identify_payload already matched a non-crypto container.
    if container is not None:
        return None, ()

    # Attempt DER / ASN.1 detection on raw binary.
    if len(data) >= 2 and data[0] == 0x30:
        der_container, der_meta = _try_der_parse(data, candidates)
        if der_container is not None:
            return der_container, tuple(der_meta)

    return None, ()


def _try_der_parse(
    data: bytes, candidates: list[Identification]
) -> tuple[ContainerDetails | None, list[str]]:
    """Attempt to parse binary data as DER-encoded cryptographic objects."""
    metadata: list[str] = []

    # Try X.509 certificate.
    try:
        cert = x509.load_der_x509_certificate(data)
        pub = cert.public_key()
        key_size = getattr(pub, "key_size", None)
        algo = type(pub).__name__.replace("_", " ")
        candidates.append(
            Identification(
                "X.509 certificate (DER)",
                "certain",
                f"Valid DER-encoded X.509 certificate; subject: "
                f"{cert.subject.rfc4514_string()}",
            )
        )
        metadata.append(f"Public key algorithm: {algo}")
        if key_size is not None:
            metadata.append(f"Key size: {key_size} bits")
        metadata.append(f"Subject: {cert.subject.rfc4514_string()}")
        metadata.append(f"Issuer: {cert.issuer.rfc4514_string()}")
        return (
            ContainerDetails("DER-encoded X.509 certificate", "ASN.1 SEQUENCE"),
            metadata,
        )
    except Exception:  # noqa: BLE001
        pass

    # Try PKCS#8 public key.
    try:
        pub = serialization.load_der_public_key(data)
        algo = type(pub).__name__.replace("_", " ")
        key_size = getattr(pub, "key_size", None)
        candidates.append(
            Identification(
                "PKCS#8 public key (DER)",
                "certain",
                f"Valid DER-encoded SubjectPublicKeyInfo; algorithm: {algo}",
            )
        )
        metadata.append(f"Key algorithm: {algo}")
        if key_size is not None:
            metadata.append(f"Key size: {key_size} bits")
        return (
            ContainerDetails("DER-encoded PKCS#8 public key", "ASN.1 SEQUENCE"),
            metadata,
        )
    except Exception:  # noqa: BLE001
        pass

    # Try PKCS#8 private key (unencrypted).
    try:
        priv = serialization.load_der_private_key(data, password=None)
        algo = type(priv).__name__.replace("_", " ")
        key_size = getattr(priv, "key_size", None)
        candidates.append(
            Identification(
                "PKCS#8 private key (DER)",
                "certain",
                f"Valid DER-encoded PKCS#8 PrivateKeyInfo; algorithm: {algo}",
            )
        )
        metadata.append(f"Key algorithm: {algo}")
        if key_size is not None:
            metadata.append(f"Key size: {key_size} bits")
        return (
            ContainerDetails("DER-encoded PKCS#8 private key", "ASN.1 SEQUENCE"),
            metadata,
        )
    except Exception:  # noqa: BLE001
        pass

    # Fallback: looks like ASN.1 but we can't parse specifics.
    if len(data) >= 4:
        candidates.append(
            Identification(
                "ASN.1 DER structure",
                "low",
                "Starts with 0x30 (SEQUENCE) but did not match known key/certificate formats",
            )
        )
        return (
            ContainerDetails("DER-encoded ASN.1 structure", "ASN.1 SEQUENCE"),
            metadata,
        )
    return None, metadata


def _is_crypto_container(container: ContainerDetails | None) -> bool:
    """Return True when the container is a recognized cryptographic format."""
    if container is None:
        return False
    return container.format in _CRYPTO_CONTAINER_FORMATS
