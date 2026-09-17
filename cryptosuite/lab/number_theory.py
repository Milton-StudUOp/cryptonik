"""EDUCATIONAL NUMBER THEORY HELPERS — NOT CRYPTOGRAPHIC PRIMITIVES."""

from __future__ import annotations

import math

from cryptosuite.utils.exceptions import ValidationError


def gcd(first: int, second: int) -> int:
    return math.gcd(first, second)


def modular_inverse(value: int, modulus: int) -> int:
    if modulus <= 1 or math.gcd(value, modulus) != 1:
        raise ValidationError("A modular inverse does not exist.")
    return pow(value, -1, modulus)


def is_prime(value: int) -> bool:
    if value < 2:
        return False
    return all(value % divisor for divisor in range(2, math.isqrt(value) + 1))
