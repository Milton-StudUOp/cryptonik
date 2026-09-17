"""EDUCATIONAL RSA IMPLEMENTATION — NOT FOR PRODUCTION USE."""

from __future__ import annotations

import math
from dataclasses import dataclass

from cryptosuite.utils.exceptions import ValidationError


@dataclass(frozen=True, slots=True)
class RSADemo:
    p: int
    q: int
    n: int
    phi: int
    e: int
    d: int

    def encrypt(self, message: int) -> int:
        if not 0 <= message < self.n:
            raise ValidationError("RSA demo message must be between 0 and n-1.")
        return pow(message, self.e, self.n)

    def decrypt(self, ciphertext: int) -> int:
        return pow(ciphertext, self.d, self.n)


def create_rsa_demo(p: int, q: int, e: int = 65537) -> RSADemo:
    """Create tiny textbook RSA values for arithmetic demonstrations."""
    if not _is_prime(p) or not _is_prime(q) or p == q:
        raise ValidationError("p and q must be distinct primes.")
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        raise ValidationError("e must be coprime with phi(n).")
    return RSADemo(p, q, p * q, phi, e, pow(e, -1, phi))


def _is_prime(value: int) -> bool:
    if value < 2:
        return False
    return all(value % divisor for divisor in range(2, math.isqrt(value) + 1))

