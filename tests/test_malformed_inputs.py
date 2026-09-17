"""Hostile-container tests for bounded, exact parsers."""

import io
import json
import struct

import pytest

from cryptosuite.files.file_format import MAGIC, PREFIX, VERSION, read_header
from cryptosuite.files.hybrid_file import MAGIC as HYBRID_MAGIC
from cryptosuite.files.hybrid_file import PREFIX as HYBRID_PREFIX
from cryptosuite.files.hybrid_file import VERSION as HYBRID_VERSION
from cryptosuite.files.hybrid_file import _read_header as read_hybrid_header
from cryptosuite.utils.exceptions import FileFormatError, ValidationError


def _container(prefix, magic, version, payload):
    encoded = json.dumps(payload, separators=(",", ":")).encode("ascii")
    return prefix.pack(magic, version, len(encoded)) + encoded


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"unexpected": True},
        {
            "algorithm": "aes-ecb",
            "chunk_size": 65536,
            "kdf": "argon2id",
            "kdf_parameters": {
                "time_cost": 1,
                "memory_cost_kib": 8192,
                "parallelism": 1,
                "key_length": 32,
            },
            "nonce_prefix": "AAAAAA==",
            "plaintext_size": 0,
            "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
        },
    ],
)
def test_cryptx_rejects_unknown_or_incomplete_headers(payload):
    with pytest.raises((FileFormatError, ValidationError)):
        read_header(io.BytesIO(_container(PREFIX, MAGIC, VERSION, payload)))


def test_cryptx_rejects_absurd_header_length_without_allocating():
    raw = struct.pack(">6sBI", MAGIC, VERSION, 0xFFFFFFFF)
    with pytest.raises(FileFormatError, match="length"):
        read_header(io.BytesIO(raw))


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {
            "algorithm": "xchacha20-poly1305",
            "chunk_size": True,
            "nonce_prefix": "AAAAAAAAAAAAAAAAAAAAAA==",
            "plaintext_size": 0,
            "recipients": [],
        },
        {
            "algorithm": "xchacha20-poly1305",
            "chunk_size": 65536,
            "nonce_prefix": "AAAAAAAAAAAAAAAAAAAAAA==",
            "plaintext_size": 0,
            "recipients": [
                {
                    "algorithm": "unknown",
                    "key_id": "AAAA-BBBB-CCCC",
                    "wrapped_key": "AA==",
                }
            ],
        },
    ],
)
def test_hybrid_parser_rejects_malformed_headers(payload):
    raw = _container(HYBRID_PREFIX, HYBRID_MAGIC, HYBRID_VERSION, payload)
    with pytest.raises(FileFormatError):
        read_hybrid_header(io.BytesIO(raw))
