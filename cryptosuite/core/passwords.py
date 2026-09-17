"""Cryptographically secure password generation and entropy estimates."""

from __future__ import annotations

import math
import secrets
import string

from cryptosuite.utils.exceptions import ValidationError


def generate_password(
    length: int = 32,
    *,
    uppercase: bool = True,
    lowercase: bool = True,
    numbers: bool = True,
    symbols: bool = True,
) -> str:
    """Generate a password containing at least one character from each selected set."""
    groups = []
    if uppercase:
        groups.append(string.ascii_uppercase)
    if lowercase:
        groups.append(string.ascii_lowercase)
    if numbers:
        groups.append(string.digits)
    if symbols:
        groups.append("!#$%&()*+,-./:;<=>?@[]^_{|}~")
    if not groups:
        raise ValidationError("At least one password character set must be selected.")
    if isinstance(length, bool) or not isinstance(length, int) or not len(groups) <= length <= 1024:
        raise ValidationError(
            "Password length must fit all selected sets and not exceed 1024."
        )
    characters = [secrets.choice(group) for group in groups]
    alphabet = "".join(groups)
    characters.extend(secrets.choice(alphabet) for _ in range(length - len(groups)))
    secrets.SystemRandom().shuffle(characters)
    return "".join(characters)


def estimated_entropy_bits(length: int, alphabet_size: int) -> float:
    """Return a theoretical uniform-choice estimate, not password strength proof."""
    if length < 0 or alphabet_size < 1:
        raise ValidationError("Length and alphabet size must be positive.")
    return length * math.log2(alphabet_size)
