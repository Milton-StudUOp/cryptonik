"""Tests for the public Cryptonik package alias."""

from cryptonik import __version__ as public_version
from cryptosuite import __version__ as implementation_version


def test_public_package_exposes_version():
    assert public_version == implementation_version
